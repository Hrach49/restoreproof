"""C5.1: the settings come from the environment; a fault names the variable, never a value."""

import pytest

from app.settings import (
    Settings,
    SettingsError,
    StorageSettings,
    database_url_from_environment,
    load_settings,
    log_level_from_environment,
    storage_settings_from_environment,
)

SENTINEL = "Sentinel-Settings-7c1e"

REQUIRED = (
    "DATABASE_URL",
    "S3_ENDPOINT",
    "S3_ACCESS_KEY",
    "S3_SECRET_KEY",
    "S3_BUCKET",
    "SECRET_KEY",
)


def environment(**changes: str | None) -> dict[str, str]:
    env = {
        "DATABASE_URL": f"postgresql+asyncpg://user:{SENTINEL}-db@db.test:5432/rp",
        "S3_ENDPOINT": "http://s3.test:9000",
        "S3_ACCESS_KEY": "access",
        "S3_SECRET_KEY": f"{SENTINEL}-s3",
        "S3_BUCKET": "bucket",
        "SECRET_KEY": f"{SENTINEL}-key-" + "k" * 32,
    }
    for name, value in changes.items():
        if value is None:
            env.pop(name, None)
        else:
            env[name] = value
    return env


def test_the_required_six_and_the_defaults():
    settings = load_settings(environment())

    assert settings.database_url.get_secret_value().startswith("postgresql+asyncpg://")
    assert settings.s3_endpoint == "http://s3.test:9000"
    assert settings.s3_access_key == "access"
    assert settings.s3_secret_key.get_secret_value() == f"{SENTINEL}-s3"
    assert settings.s3_bucket == "bucket"
    assert settings.s3_region == "us-east-1"
    assert settings.smtp_host is None
    assert settings.smtp_port == 587
    assert settings.smtp_username is None
    assert settings.smtp_password is None
    assert settings.smtp_from is None
    assert settings.log_level == "info"
    # C6.1, C6.2: the cookie is Secure and the links are signed for the data
    # endpoint unless a deployment says otherwise.
    assert settings.session_cookie_secure is True
    assert settings.s3_public_endpoint is None


def test_the_optional_ones_are_read_when_set():
    settings = load_settings(
        environment(
            S3_PUBLIC_ENDPOINT="http://127.0.0.1:9000",
            SESSION_COOKIE_SECURE="false",
            S3_REGION="eu-central-1",
            SMTP_HOST="smtp.test",
            SMTP_PORT="2525",
            SMTP_USERNAME="mailer",
            SMTP_PASSWORD=f"{SENTINEL}-smtp",
            SMTP_FROM="reports@example.test",
            LOG_LEVEL="debug",
        )
    )

    assert settings.s3_region == "eu-central-1"
    assert settings.smtp_host == "smtp.test"
    assert settings.smtp_port == 2525
    assert settings.smtp_username == "mailer"
    assert settings.smtp_password.get_secret_value() == f"{SENTINEL}-smtp"
    assert settings.smtp_from == "reports@example.test"
    assert settings.log_level == "debug"
    assert settings.s3_public_endpoint == "http://127.0.0.1:9000"
    assert settings.session_cookie_secure is False


@pytest.mark.parametrize("name", REQUIRED)
def test_a_required_variable_missing_names_it(name):
    with pytest.raises(SettingsError) as raised:
        load_settings(environment(**{name: None}))

    assert str(raised.value) == f"settings error: {name} is missing"


@pytest.mark.parametrize("name", REQUIRED)
def test_an_empty_required_variable_is_a_missing_one(name):
    with pytest.raises(SettingsError) as raised:
        load_settings(environment(**{name: ""}))

    assert str(raised.value) == f"settings error: {name} is missing"


def test_every_faulty_variable_is_named_at_once_in_the_settings_own_order():
    with pytest.raises(SettingsError) as raised:
        load_settings(environment(SECRET_KEY=None, DATABASE_URL=None, SMTP_PORT="smtp"))

    assert str(raised.value) == (
        "settings error: DATABASE_URL is missing; SECRET_KEY is missing; SMTP_PORT is not valid"
    )


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("DATABASE_URL", f"postgresql://user:{SENTINEL}@db.test/rp"),
        ("DATABASE_URL", f"sqlite+aiosqlite:///{SENTINEL}.db"),
        ("S3_ENDPOINT", f"s3.test:9000/{SENTINEL}"),
        ("S3_ENDPOINT", f"ftp://{SENTINEL}.test"),
        ("S3_PUBLIC_ENDPOINT", f"{SENTINEL}.test:9000"),
        ("SESSION_COOKIE_SECURE", f"{SENTINEL}"),
        ("SECRET_KEY", f"{SENTINEL}-short"),
        ("SMTP_PORT", f"{SENTINEL}"),
        ("SMTP_PORT", "0"),
        ("SMTP_PORT", "65536"),
        ("LOG_LEVEL", f"{SENTINEL}"),
    ],
)
def test_a_value_of_the_wrong_shape_names_its_variable(name, value):
    with pytest.raises(SettingsError) as raised:
        load_settings(environment(**{name: value}))

    assert str(raised.value) == f"settings error: {name} is not valid"


@pytest.mark.parametrize(
    "changes",
    [
        {"DATABASE_URL": None},
        {"SECRET_KEY": f"{SENTINEL}-short"},
        {"DATABASE_URL": f"postgresql://user:{SENTINEL}@db.test/rp"},
        {"S3_BUCKET": None, "SMTP_PASSWORD": f"{SENTINEL}-smtp", "SMTP_PORT": "x"},
    ],
)
def test_a_fault_never_holds_a_value(changes):
    """Not the faulty value, and not another variable's: pydantic's own text
    prints its input, which for a missing key is everything else."""
    with pytest.raises(SettingsError) as raised:
        load_settings(environment(**changes))

    error = raised.value
    shown = f"{error}{error!r}{error.args}{error.__cause__}{error.__context__}"
    assert SENTINEL not in shown
    assert error.__cause__ is None
    assert error.__suppress_context__ is True


def test_printing_the_settings_shows_no_secret():
    settings = load_settings(environment(SMTP_PASSWORD=f"{SENTINEL}-smtp"))

    assert SENTINEL not in f"{settings}{settings!r}{settings.model_dump()}"


def test_names_are_read_in_any_case_and_other_variables_are_ignored():
    env = {name.lower(): value for name, value in environment().items()}
    env["PATH"] = "/usr/bin"

    assert load_settings(env).s3_bucket == "bucket"


@pytest.mark.parametrize("given", ["INFO", "Info", "info"])
def test_log_level_is_read_in_any_case(given):
    assert load_settings(environment(LOG_LEVEL=given)).log_level == "info"


def test_a_log_level_that_is_no_level_names_its_variable():
    with pytest.raises(SettingsError) as raised:
        load_settings(environment(LOG_LEVEL="loud"))

    assert str(raised.value) == "settings error: LOG_LEVEL is not valid"


def test_the_process_environment_is_the_default_and_the_only_other_source(monkeypatch):
    for name, value in environment().items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("S3_BUCKET", "from-the-process")

    assert load_settings().s3_bucket == "from-the-process"
    # A mapping that is given is the whole environment: nothing leaks in.
    with pytest.raises(SettingsError, match="S3_BUCKET is missing"):
        load_settings(environment(S3_BUCKET=None))


def test_no_env_file_is_read(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("S3_BUCKET=from-a-file\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SettingsError, match="S3_BUCKET is missing"):
        load_settings(environment(S3_BUCKET=None))


def test_settings_cannot_be_built_around_load_settings_from_the_environment(monkeypatch):
    """`Settings(...)` takes what it is given and reads no environment itself."""
    for name, value in environment().items():
        monkeypatch.setenv(name, value)

    with pytest.raises(Exception) as raised:
        Settings()

    assert SENTINEL not in str(raised.value)


def test_a_migration_needs_database_url_and_nothing_else():
    url = "postgresql+asyncpg://user:pw@db.test:5432/rp"

    assert database_url_from_environment({"database_url": url}) == url


def test_the_process_environment_is_the_migration_s_default(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://user:pw@db.test:5432/from-process")

    assert database_url_from_environment().endswith("/from-process")


@pytest.mark.parametrize(
    "names",
    [("DATABASE_URL", "database_url"), ("database_url", "DATABASE_URL")],
)
def test_a_migration_and_the_app_read_the_same_database_from_one_environment(names):
    """A container's environment can hold the name in two cases."""
    first, second = (f"postgresql+asyncpg://user:pw@db.test:5432/{name}" for name in "ab")
    env = environment(DATABASE_URL=None) | {names[0]: first, names[1]: second}

    assert database_url_from_environment(env) == load_settings(env).database_url.get_secret_value()


def test_an_empty_database_url_beside_a_set_one_is_no_fault_for_a_migration():
    url = "postgresql+asyncpg://user:pw@db.test:5432/rp"
    env = environment(DATABASE_URL="") | {"database_url": url}

    assert load_settings(env).database_url.get_secret_value() == url
    assert database_url_from_environment(env) == url


@pytest.mark.parametrize(
    ("environ", "level"),
    [
        ({}, "info"),
        ({"LOG_LEVEL": ""}, "info"),
        ({"LOG_LEVEL": "ERROR"}, "error"),
        ({"log_level": "debug"}, "debug"),
    ],
)
def test_a_migration_s_log_level_is_the_app_s(environ, level):
    assert log_level_from_environment(environ) == level
    assert load_settings(environment(**environ)).log_level == level


def test_the_process_environment_is_the_default_for_a_migration_s_log_level(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "warning")

    assert log_level_from_environment() == "warning"


def test_a_migration_refuses_a_log_level_that_is_no_level():
    with pytest.raises(SettingsError) as raised:
        log_level_from_environment({"LOG_LEVEL": SENTINEL})

    assert str(raised.value) == "settings error: LOG_LEVEL is not valid"
    assert SENTINEL not in f"{raised.value!r}{raised.value.__cause__}{raised.value.__context__}"


@pytest.mark.parametrize("environ", [{}, {"DATABASE_URL": ""}, {"S3_BUCKET": "bucket"}])
def test_a_migration_without_database_url_names_it(environ):
    with pytest.raises(SettingsError) as raised:
        database_url_from_environment(environ)

    assert str(raised.value) == "settings error: DATABASE_URL is missing"


@pytest.mark.parametrize(
    "url", [f"postgresql://user:{SENTINEL}@db.test/rp", f"sqlite:///{SENTINEL}.db"]
)
def test_a_migration_refuses_another_driver_without_showing_the_url(url):
    with pytest.raises(SettingsError) as raised:
        database_url_from_environment({"DATABASE_URL": url})

    assert str(raised.value) == "settings error: DATABASE_URL is not valid"
    assert SENTINEL not in f"{raised.value!r}{raised.value.__cause__}{raised.value.__context__}"


# --- C6.4: the S3 settings alone, for `generate-report` -------------------------------------------

S3_NAMES = ("S3_ENDPOINT", "S3_ACCESS_KEY", "S3_SECRET_KEY", "S3_BUCKET")


def test_a_report_command_needs_the_five_s3_variables_and_nothing_else():
    env = {name: value for name, value in environment().items() if name.startswith("S3_")}

    settings = storage_settings_from_environment(env)

    assert (settings.s3_endpoint, settings.s3_access_key, settings.s3_bucket, settings.s3_region) == ("http://s3.test:9000", "access", "bucket", "us-east-1")
    assert settings.s3_secret_key.get_secret_value() == f"{SENTINEL}-s3"
    assert set(StorageSettings.model_fields) == {"s3_endpoint", "s3_access_key", "s3_secret_key", "s3_bucket", "s3_region"}
    assert set(StorageSettings.model_fields) <= set(Settings.model_fields)
    assert SENTINEL not in repr(settings) + str(settings)


def test_the_other_variables_are_ignored_and_the_names_read_in_any_case(monkeypatch):
    env = {"s3_endpoint": "https://s3.test", "S3_ACCESS_KEY": "a", "S3_SECRET_KEY": "s", "S3_Bucket": "b", "S3_REGION": "eu-west-1", "SECRET_KEY": "x" * 40, "DATABASE_URL": "not read", "NOT_A_SETTING": "ignored", "S3_PUBLIC_ENDPOINT": "http://public.test"}

    settings = storage_settings_from_environment(env)

    assert (settings.s3_endpoint, settings.s3_bucket, settings.s3_region) == ("https://s3.test", "b", "eu-west-1")
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    assert storage_settings_from_environment().s3_region == "eu-west-1"


@pytest.mark.parametrize("name", S3_NAMES)
def test_a_missing_s3_variable_is_named_and_an_empty_one_is_missing(name):
    env = {n: v for n, v in environment().items() if n.startswith("S3_")}
    for value in (None, ""):
        faulty = {n: v for n, v in env.items() if n != name} if value is None else {**env, name: value}

        with pytest.raises(SettingsError) as raised:
            storage_settings_from_environment(faulty)

        assert str(raised.value) == f"settings error: {name} is missing"


def test_every_faulty_s3_variable_is_named_at_once_without_a_value():
    with pytest.raises(SettingsError) as raised:
        storage_settings_from_environment({"S3_ENDPOINT": f"ftp://{SENTINEL}", "S3_BUCKET": "b"})

    assert str(raised.value) == "settings error: S3_ENDPOINT is not valid; S3_ACCESS_KEY is missing; S3_SECRET_KEY is missing"
    assert SENTINEL not in f"{raised.value!r}{raised.value.__cause__}{raised.value.__context__}"


def test_storage_settings_read_no_environment_of_their_own(monkeypatch):
    for name, value in environment().items():
        monkeypatch.setenv(name, value)

    with pytest.raises(Exception) as raised:
        StorageSettings()

    assert SENTINEL not in str(raised.value)

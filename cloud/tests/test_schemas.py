"""app/schemas.py: the Cloud reads shared/schemas/ by path, found by walking up
from app/ (the tree) or /srv/ (the image), never copied (docs/decisions.md
2026-10-10, "C5.3 and C5.4", point 7)."""

from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from app.schemas import load_schema, shared_schemas_dir
from tests.test_result_schema import shared_dir


def test_the_app_finds_the_repository_s_shared_schemas():
    assert shared_schemas_dir() == shared_dir() / "schemas"
    assert (shared_schemas_dir() / "client-profile.v1.json").is_file()


def test_the_folder_is_found_by_walking_up_from_the_given_file(tmp_path):
    (tmp_path / "shared" / "schemas").mkdir(parents=True)
    start = tmp_path / "srv" / "app" / "repo" / "connectors.py"
    start.parent.mkdir(parents=True)
    start.write_text("", encoding="utf-8")

    assert shared_schemas_dir(start) == tmp_path / "shared" / "schemas"


def test_a_missing_folder_is_an_error_naming_the_folder_and_no_path(tmp_path):
    start = tmp_path / "nowhere" / "app.py"
    start.parent.mkdir()
    start.write_text("", encoding="utf-8")

    with pytest.raises(FileNotFoundError) as raised:
        shared_schemas_dir(start)

    assert str(raised.value) == "no shared/schemas folder above the app"
    assert str(tmp_path) not in str(raised.value)


def test_load_schema_reads_the_one_copy_and_it_is_a_valid_schema():
    schema = load_schema("client-profile.v1.json")

    assert schema["$id"].endswith("/client-profile.v1.json")
    Draft202012Validator.check_schema(schema)
    assert schema == load_schema("client-profile.v1.json")


def test_a_schema_that_does_not_exist_is_an_error_naming_the_file(tmp_path):
    with pytest.raises(FileNotFoundError, match="^no such schema: nothing.v9.json$"):
        load_schema("nothing.v9.json")


IMAGE_PATHS = {
    "!cloud/pyproject.toml", "!cloud/uv.lock", "!cloud/alembic.ini", "!cloud/app",
    # C5.3: the schemas; C5.7: the verifier and the TSA root; C5.10: the CLI.
    "!shared/schemas", "!shared/tools", "!shared/tsa", "!cloud/manage.py",
}


def test_the_image_copies_the_schemas_the_verifier_and_the_tsa_root_beside_app_and_nothing_else():
    """The Dockerfile's build context is the repository: cloud/'s four paths,
    shared/schemas, shared/tools and shared/tsa go in, by a root .dockerignore
    that allows nothing else."""
    root = shared_dir().parent
    dockerfile = (root / "cloud" / "Dockerfile").read_text(encoding="utf-8")
    ignore = [
        line.strip()
        for line in (root / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    compose = (root / "cloud" / "docker-compose.yml").read_text(encoding="utf-8")

    assert "COPY shared/schemas ./shared/schemas" in dockerfile
    assert "COPY shared/tools ./shared/tools" in dockerfile
    assert "COPY shared/tsa ./shared/tsa" in dockerfile
    assert "COPY cloud/app ./app" in dockerfile
    assert "COPY cloud/manage.py ./" in dockerfile
    assert not (root / "cloud" / ".dockerignore").exists()
    assert ignore[0] == "*"
    assert IMAGE_PATHS <= set(ignore)
    assert not [line for line in ignore if line.startswith("!") and line not in IMAGE_PATHS]
    # No bytecode of the build machine under any of the seven (the last match
    # wins, so the line comes after them): the image runs the verifier's
    # source as committed, never a `verify_bundle.cpython-312.pyc` beside it.
    assert ignore[-1] == "**/__pycache__"
    # What the two folders hold is the one verifier and the one root, nothing else.
    assert sorted(p.name for p in (root / "shared" / "tools").iterdir() if p.name != "__pycache__") == ["verify_bundle.py"]
    assert sorted(p.name for p in (root / "shared" / "tsa").iterdir()) == ["tsa-ca.pem"]
    assert compose.count("context: ..") == 2
    assert compose.count("dockerfile: cloud/Dockerfile") == 2
    assert "build: ." not in compose
    # C5.9: the scheduler service runs the dispatcher and never migrates.
    assert 'command: ["python", "-m", "app.scheduler"]' in compose
    assert "sleep infinity" not in compose
    assert compose.count("alembic upgrade head") == 1


@pytest.mark.parametrize("package", ["jsonschema", "cryptography", "asn1crypto", "python-multipart", "typer", "apscheduler", "croniter", "argon2-cffi", "itsdangerous", "jinja2"])
def test_the_verifier_s_libraries_and_the_form_parser_are_runtime_dependencies(package):
    """jsonschema since C5.3; the verifier's two and starlette's form parser
    since C5.7 (docs/decisions.md 2026-10-10, C5.7, point 1); the CLI's and
    the scheduler's three since C5.10 and C5.9; the login's three since C6.1
    (slowapi is not among them, point 7)."""
    import tomllib

    pyproject = tomllib.loads((Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8"))

    assert any(dep.startswith(package) for dep in pyproject["project"]["dependencies"])
    assert not any(dep.startswith(package) for dep in pyproject["dependency-groups"]["dev"])
    assert not any(dep.startswith("slowapi") for dep in pyproject["project"]["dependencies"])

"""The Cloud's settings, read from the process environment (C5.1).

Nothing that is a secret, and nothing that says where data goes, has a default
here: a deployment that forgets one stops at startup instead of running against
a made-up value. The local stack's values are in docker-compose.yml.

A fault names the variable and never a value: `SettingsError` is built from the
names alone, since pydantic's own message prints its input.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any, Literal, get_args

from pydantic import Field, SecretStr, ValidationError, field_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

DATABASE_URL_SCHEME = "postgresql+asyncpg://"
MIN_SECRET_KEY_LENGTH = 32

LogLevel = Literal["debug", "info", "warning", "error"]
DEFAULT_LOG_LEVEL: LogLevel = "info"


class SettingsError(Exception):
    """The environment doesn't make a `Settings`; the text holds names only."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(hide_input_in_errors=True, extra="forbid", frozen=True)

    database_url: SecretStr
    s3_endpoint: str
    s3_access_key: str
    s3_secret_key: SecretStr
    s3_bucket: str
    s3_region: str = "us-east-1"
    secret_key: SecretStr
    smtp_host: str | None = None
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str | None = None
    log_level: LogLevel = DEFAULT_LOG_LEVEL

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # `load_settings` hands over the environment it was given, and that is
        # the only source: no .env file, no second look at os.environ.
        return (init_settings,)

    @field_validator("database_url")
    @classmethod
    def _asyncpg_url(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().startswith(DATABASE_URL_SCHEME):
            raise ValueError("not a postgresql+asyncpg URL")
        return value

    @field_validator("s3_endpoint")
    @classmethod
    def _http_endpoint(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("not an http or https URL")
        return value

    @field_validator("log_level", mode="before")
    @classmethod
    def _any_case(cls, value: Any) -> Any:
        # LOG_LEVEL=INFO is how most deployments write it.
        return value.lower() if isinstance(value, str) else value

    @field_validator("secret_key")
    @classmethod
    def _long_enough(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < MIN_SECRET_KEY_LENGTH:
            raise ValueError("too short")
        return value


def _settings_in(environ: Mapping[str, str] | None) -> dict[str, str]:
    """The settings' variables in `environ` (default: the process environment).

    Names are read in any case, an empty value is a missing one, and a variable
    that isn't a setting is ignored. The app and a migration both read through
    here, so one environment never gives them two answers.
    """
    source = os.environ if environ is None else environ
    return {
        name.lower(): value
        for name, value in source.items()
        if name.lower() in Settings.model_fields and value != ""
    }


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    """Make the settings from `environ` (default: the process environment).

    Raises `SettingsError` naming every faulty variable, in the settings' own
    order.
    """
    values = _settings_in(environ)
    try:
        return Settings(**values)
    except ValidationError as error:
        words = {
            str(fault["loc"][0]): "is missing" if fault["type"] == "missing" else "is not valid"
            for fault in error.errors(include_input=False, include_context=False)
        }
    faults = [f"{name.upper()} {words[name]}" for name in Settings.model_fields if name in words]
    raise SettingsError("settings error: " + "; ".join(faults)) from None


def database_url_from_environment(environ: Mapping[str, str] | None = None) -> str:
    """DATABASE_URL alone, for a migration: it needs no other setting.

    Held to the same shape as the app's, and a fault names the variable only.
    """
    url = _settings_in(environ).get("database_url", "")
    if not url:
        raise SettingsError("settings error: DATABASE_URL is missing")
    if not url.startswith(DATABASE_URL_SCHEME):
        raise SettingsError("settings error: DATABASE_URL is not valid")
    return url


def log_level_from_environment(environ: Mapping[str, str] | None = None) -> LogLevel:
    """LOG_LEVEL alone, for a migration's own log lines; the app's default when unset."""
    level = _settings_in(environ).get("log_level", DEFAULT_LOG_LEVEL).lower()
    if level not in get_args(LogLevel):
        raise SettingsError("settings error: LOG_LEVEL is not valid")
    return level

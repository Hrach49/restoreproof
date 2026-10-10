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


def test_the_image_copies_the_schemas_beside_app_and_nothing_else():
    """The Dockerfile's build context is the repository: cloud/'s four paths and
    shared/schemas go in, by a root .dockerignore that allows nothing else."""
    root = shared_dir().parent
    dockerfile = (root / "cloud" / "Dockerfile").read_text(encoding="utf-8")
    ignore = [
        line.strip()
        for line in (root / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    compose = (root / "cloud" / "docker-compose.yml").read_text(encoding="utf-8")

    assert "COPY shared/schemas ./shared/schemas" in dockerfile
    assert "COPY cloud/app ./app" in dockerfile
    assert not (root / "cloud" / ".dockerignore").exists()
    assert ignore[0] == "*"
    assert {"!cloud/pyproject.toml", "!cloud/uv.lock", "!cloud/alembic.ini", "!cloud/app", "!shared/schemas"} <= set(ignore)
    assert not [line for line in ignore if line.startswith("!") and line not in {
        "!cloud/pyproject.toml", "!cloud/uv.lock", "!cloud/alembic.ini", "!cloud/app", "!shared/schemas"
    }]
    assert compose.count("context: ..") == 2
    assert compose.count("dockerfile: cloud/Dockerfile") == 2
    assert "build: ." not in compose


def test_jsonschema_is_a_runtime_dependency():
    import tomllib

    pyproject = tomllib.loads((Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8"))

    assert any(dep.startswith("jsonschema") for dep in pyproject["project"]["dependencies"])
    assert not any(dep.startswith("jsonschema") for dep in pyproject["dependency-groups"]["dev"])

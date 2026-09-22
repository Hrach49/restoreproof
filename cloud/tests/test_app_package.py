import re

import app


def test_app_package_exposes_a_semver_version():
    assert re.fullmatch(r"\d+\.\d+\.\d+", app.__version__)

import sys


def test_runs_on_python_312_or_newer():
    assert sys.version_info >= (3, 12)

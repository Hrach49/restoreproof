# Convenience targets for the cloud backend. CI does not use this file.
#
# make is not installed on the Windows dev laptop, and mutmut needs fork(),
# so run these from WSL or Linux: cd /mnt/c/restoreproof/cloud && make mutate
# See docs/testing.md.

.PHONY: test cov mutate

# Same as the CI test step.
test:
	uv run --locked pytest

# Same as the CI coverage steps (.github/workflows/cloud.yml): 80% of combined
# line + branch on app/, then 100% line + branch on the guarded paths.
cov:
	uv run --locked pytest --cov=app --cov-branch --cov-report=term-missing --cov-report=json:coverage.json --cov-fail-under=80
	uv run --locked python tools/check_coverage.py coverage.json

# Once-per-sprint mutation run. Manual only; never run in CI.
# Settings live in [tool.mutmut] in pyproject.toml; output goes to mutants/.
# Exits 1 ("could not find any test case for any mutant") until app/ has real
# functions to mutate.
mutate:
	uv run mutmut run
	uv run mutmut results

# Convenience targets for the cloud backend. CI does not use this file.
#
# make is not installed on the Windows dev laptop, and mutmut needs fork(),
# so run these from WSL or Linux: cd /mnt/c/restoreproof/cloud && make mutate
# See docs/testing.md.

.PHONY: db up down test cov mutate

# The tests' database: PostgreSQL 16 on 127.0.0.1:55432 (docker-compose.yml).
# The database tests never skip; without it they fail. See docs/testing.md, "Cloud".
db:
	docker compose up -d --wait postgres

# The whole local stack; then GET http://127.0.0.1:8000/healthz.
up:
	docker compose up -d --wait --build

# Stop the stack. The volumes stay; `docker compose down -v` drops them.
down:
	docker compose down

# Same as the CI test step. Needs `make db` (or TEST_DATABASE_URL).
test:
	uv run --locked pytest

# Same as the CI coverage steps (.github/workflows/cloud.yml): 80% of combined
# line + branch on app/, then 100% line + branch on the guarded paths.
cov:
	uv run --locked pytest --cov=app --cov-branch --cov-report=term-missing --cov-report=json:coverage.json --cov-fail-under=80
	uv run --locked python tools/check_coverage.py coverage.json

# Once-per-sprint mutation run. Manual only; never run in CI.
# Settings live in [tool.mutmut] in pyproject.toml; output goes to mutants/.
# Needs `make db`: the tests it runs include the database ones.
mutate:
	uv run mutmut run
	uv run mutmut results

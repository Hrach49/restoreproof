# The Cloud's image (C5.1): the api, and the scheduler with another command.
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.12.17 /uv /usr/local/bin/uv

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /srv

# C6.4: what WeasyPrint renders the PDF report with (docs/decisions.md
# 2026-10-12, "C6.4", point 2): Pango, HarfBuzz's subsetter and one font,
# before the dependencies so a code change installs none of it again. The
# font cache is built here, system-wide, and XDG_CACHE_HOME (below, after
# uv's layer so uv's cache is not written there as root) gives fontconfig a
# writable place for its own: the service user has no home, and fontconfig
# printed "No writable cache directories" per font otherwise.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-dejavu-core fontconfig \
    && fc-cache -fs \
    && rm -rf /var/lib/apt/lists/*

# Built with the repository as context (cloud/docker-compose.yml, .dockerignore
# at the root): the app reads shared/schemas/ by path, so the schemas go in
# beside app/, where app/schemas.py finds them by walking up; C5.7 reads the
# verifier (shared/tools/verify_bundle.py) and the TSA root (shared/tsa) the
# same way.
# The dependencies first, so a change to the code doesn't install them again.
COPY cloud/pyproject.toml cloud/uv.lock ./
RUN uv sync --locked --no-dev

COPY cloud/alembic.ini ./
COPY shared/schemas ./shared/schemas
COPY shared/tools ./shared/tools
COPY shared/tsa ./shared/tsa
COPY cloud/app ./app
# C5.10: the onboarding CLI, run as `docker compose exec api python manage.py ...`;
# the scheduler service (C5.9) runs `python -m app.scheduler` from this image.
COPY cloud/manage.py ./

RUN useradd --system --no-create-home --uid 10001 restoreproof
# C6.4: fontconfig's cache for the service user, which has no home (above).
ENV XDG_CACHE_HOME=/tmp/cache
USER restoreproof

EXPOSE 8000

# The api migrates before it listens; a migration that fails stops the
# container. Written here and not in a script: a .sh checked out with CRLF on
# Windows doesn't run in this image.
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000 --no-access-log"]

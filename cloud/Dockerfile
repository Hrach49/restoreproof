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

# The dependencies first, so a change to the code doesn't install them again.
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev

COPY alembic.ini ./
COPY app ./app

RUN useradd --system --no-create-home --uid 10001 restoreproof
USER restoreproof

EXPOSE 8000

# The api migrates before it listens; a migration that fails stops the
# container. Written here and not in a script: a .sh checked out with CRLF on
# Windows doesn't run in this image.
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000 --no-access-log"]

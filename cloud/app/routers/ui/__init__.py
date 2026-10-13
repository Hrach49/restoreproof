"""The pages, served at the root and never in the OpenAPI document (C6.1 to
C6.3; docs/decisions.md 2026-10-12, "C6.1, C6.2 and C6.3", point 1): the
login (`login.py`), the clients and their runs (`clients.py`), a run and its
files (`runs.py`), the Workers (`workers.py`), the audit page (`audit.py`),
the reports and their downloads (`reports.py`, C6.6).
`app/main.py` includes this one router at the root with
`include_in_schema=False`; a page is added to its module and no wiring."""

from __future__ import annotations

from fastapi import APIRouter

from app.routers.ui import audit, clients, login, reports, runs, workers

router = APIRouter()
for module in (login, clients, runs, workers, audit, reports):
    router.include_router(module.router)

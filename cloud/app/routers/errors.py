"""The body of every refusal a route answers, for the OpenAPI document (the
C5.5/C5.6 review's finding 3): FastAPI's `HTTPException` answers
`{"detail": "<fixed words>"}`, and the committed contract names each status a
route can answer with."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class ErrorBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detail: str


def refusal(description: str, *, header: str | None = None) -> dict[str, Any]:
    """One entry of a route's `responses`."""
    entry: dict[str, Any] = {"model": ErrorBody, "description": description}
    if header is not None:
        entry["headers"] = {header: {"schema": {"type": "string"}, "description": "`Bearer`"}}
    return entry


NOT_AUTHENTICATED = refusal(
    "Not authenticated: no valid token, whatever the reason.", header="WWW-Authenticate"
)

# C5.11: every request body but the upload's is held to app/contract.py's cap.
BODY_OVER_THE_CAP = refusal("The body is over the 64 KiB cap every request but the upload has (`body: too large`).")

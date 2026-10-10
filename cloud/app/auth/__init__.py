"""Authentication (C5.4; docs/decisions.md 2026-10-10, "C5.3 and C5.4", point 5).

`tokens`: a token is 32 random bytes in base64url; the database holds its
SHA-256 alone; an install token lasts seven days and is used once.
`dependency`: `current_worker`, the Worker behind `Authorization: Bearer`,
one 401 for every failure. `current_user` (sessions, C6.1) is not here.
"""

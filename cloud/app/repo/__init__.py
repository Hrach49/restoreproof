"""The repository layer (C5.3; docs/decisions.md 2026-10-10, "C5.3 and C5.4",
point 2): the only place a database statement is built or run.

One module per aggregate, each a class over an `AsyncSession`. Every public
method takes `msp_id: UUID` first and every statement has
`.where(Model.msp_id == msp_id)`: a `get` that finds nothing answers `None`,
and another MSP's row is "nothing"; an `update` or `delete` answers the number
of rows it touched, `0` for another MSP's row. The repos flush and never
commit: the transaction is the caller's.

The exceptions, by name: `lookup.Lookup`'s two reads by a token's hash, which
happen before any MSP is known, and `msps.MspRepo.create`, which makes the
MSP. tests/test_tenant_scope.py holds the rule on the AST;
tests/test_repo_isolation.py holds it on two MSPs.
"""

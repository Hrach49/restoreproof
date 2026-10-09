-- Runs once, when the postgres container first makes its data directory.
-- The tests' own database (docs/testing.md, "Cloud"): they empty it, so it is
-- never the api's.
CREATE DATABASE restoreproof_test;

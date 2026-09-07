# Legacy adapter verification

2026-09-07; three coherent test groups in `tests/test_legacy.py` were added.

- Initial `.venv/bin/python -m pytest tests/test_legacy.py -q`: exit 1,
  `3 failed in 0.08s`: compatibility module absent and entrypoint help still
  described the historical implementation.
- Implemented translation, envelope/atomic JSON and four main wrappers: same
  command exit 0, `3 passed in 0.31s`.
- Scope change requested duration-preserving lab observation. Updated existing
  request mapping test first; targeted command exited 1 (`LEGACY_LONG_PROFILE_REQUIRES_MIGRATION`).
  Added legacy 300/1800-second profile mapping and bounded modern `run_series`
  dispatch. Same suite exited 0, `3 passed in 0.33s`.
- Expanded existing entrypoint test to run read-only system discovery with an
  exact `--json` file, and a one-second native `localhost` observation with
  brief envelope. No public resolver queried by these integration cases.
  Suite exited 0, `3 passed in 1.54s`.
- Final `.venv/bin/python -m pytest tests/test_legacy.py tests/test_transport.py -q`
  (loopback socket permission): exit 0, **`8 passed in 2.27s`**.

Tests also cover unsupported exact-round/per-query timeout/reliability options,
unknown flags, server-file IPv4/IPv6 normalization, record-only `--no-v6`, HK
workload/quick selection, retained partial state in brief envelopes and absence
of historical-score fallback recommendations. No tests removed or weakened.
See `LEGACY_MIGRATION.md` for explicit schema and semantic changes.

# Presentation and publication evidence

2026-09-07. Tests authored independently from presentation implementation.

- Collector baseline: 130 cases, no direct render_text coverage. Added one parameterized presentation contract with seven scenarios; initial RED: 5 failed / 2 passed. It checks bounded width/rows, missing values, all-probe versus repeat statistics, incomplete reasons, next-action previews, no mutation, and lossless JSON.
- Implementation GREEN: 7 passed. The same hostile-input row was extended with C1, bidi and Unicode line separators. Actual RED: 1 failed / 6 passed; one encoded report split into 22 lines. Encoding escapes preserve decoded data. GREEN: 7 passed.
- Reverted only escape_json_controls to return raw text: 1 failed / 6 passed, pytest exit1; restored in finally. This proves the regression test catches the framing defect.
- Added one publication group with clean/symlink-file/symlink-directory cases. Initial RED: 3 failed because export implementation was absent. GREEN: 3 passed. It checks exact publication scope, SHA-256 manifest, deterministic archive bytes, source tree unchanged and symlink rejection.
- Independent CLI/presentation stale scan found no contradictory pre-change text-default assertions or redundant presentation groups. No existing assertion was weakened or deleted.

Full suite after integration:

- Python 3.14.6: `.venv/bin/python -m pytest -q --tb=short` → 156 passed in 7.23s, exit0.
- Python 3.11.15: isolated interpreter `python -m pytest -q --tb=short` → 156 passed in 7.40s, exit0.

The CI matrix is configured; these are local macOS results, not Linux/Windows results. Docker daemon was unavailable, so container build is not claimed as verified.

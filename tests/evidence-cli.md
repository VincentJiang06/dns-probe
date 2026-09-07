# CLI/config/report implementation evidence — 2026-09-07

Scope: `src/dnsprobe/{config,report,cli,__main__}.py`, packaged request/report/event schemas, `tests/test_cli.py`. Test-first groups added; no legacy tests removed. Tests use local files and a localhost UDP resolver; no public DNS load tests. Python 3.14.6 on the development Mac, project's `.venv`.

## Initial contract cycle

- RED command: `.venv/bin/python -m pytest tests/test_cli.py -q`
- Exit 1; **29 failed in 0.10 s**. Failures explicitly asserted `Missing implementation: dnsprobe.config`, `dnsprobe.report`, or `dnsprobe.cli` before modules existed, rather than failing collection with import errors.
- Implemented strict request normalization, output/report/artifact functions, CLI commands and packaged schemas.
- Intermediate GREEN: `.venv/bin/python -m pytest tests/test_cli.py -k 'request or report_summary' -q`; exit 0, **22 passed, 7 deselected in 0.03 s**.
- GREEN: `.venv/bin/python -m pytest tests/test_cli.py -q`; exit 0, **29 passed in 0.62 s**.

## Bug regressions and additional behavior

- Empty DNS labels / explicit port zero: `-k 'live_cli or empty_labels'` initially produced three `DID NOT RAISE ValueError` failures for `..`, `example.com..`, and `udp://127.0.0.1:0`. Normalization fixed. Reverted only both normalization fixes in a try/finally script, ran `-k empty_labels`: **3 failed, 30 deselected in 0.02 s**, exit 1; restored fixes. Afterwards offline suite **32 passed**.
- `--format=json`, `--format=ndjson` parameter errors and terminal event identity: `-k 'equals_format or final_identity'` returned **3 failed** (human text where JSON required; mismatched report/envelope run IDs), exit 1. Fixed early format recognition and terminal identity; **35 offline passed**.
- JSON session options: `-k json_can_express` returned **1 failed**, `Unknown request field(s): session`. Added strictly validated `session.duration_ms/interval_ms/max_runs`, CLI-over-JSON precedence, and explicit rate support from JSON. **36 offline passed**.
- Fatal series execution: `-k preserves_fatal` returned **1 failed, 1 passed**, because fatal exit 4 had become partial. Fixed priority `130 > 4 > 3 > 1/0`; rerun passed.
- Full output cap: `-k full_output_limit` returned **1 failed**, because oversized JSON was written. Added 64 MiB full output/artifact guards before any stdout write; request input remains 1 MiB, summary remains 8192 bytes.
- Offline malformed report: `-k offline_report_schema` returned **2 failed**, exit 4 instead of input error 2. Added packaged-schema validation for explain/compare input; both passed.
- Independent reviewer authored source fingerprint/policy/schedule regressions in `test_engine_review.py`. Reviewed RED evidence from that agent; fixed comparison to require implementation fingerprints, compare all non-output effective configuration, and compare observation schedule. Fixed series stop-reason conditional precedence. Targeted comparison suite passed.
- Series configuration hash: real subprocess observation test failed because aggregate `effective_config` carried the requested configuration while `config_hash` came from the reduced-budget final sample. Recomputed aggregate hash; recomputed aggregate repeat statistics and omitted the stale last-sample plan.

## Real process and protocol integration

Initial localhost run needed sandbox escalation because binding loopback UDP is restricted by the environment. Approved test execution stays on localhost.

`test_live_cli_json_ndjson_artifacts_and_series` runs actual `python -m dnsprobe` child processes against a local UDP fixture and validates:

- compact agent JSON and saved full report both pass packaged report schema;
- NDJSON sequences start at 1, have stable run ID, exactly one terminal event, and every event validates;
- three observation sample runs retain three independently identifiable observations and absolute UTC timestamps;
- shared global max_attempts=2 sends at most two real packets, cumulative cost is at most 2, and exits partial (3);
- real SIGINT after plan emission returns 130 and exactly one complete cancelled terminal event;
- aggregate configuration hash matches the effective configuration.

One test assertion was corrected to measure actual wire queries and `cost.dns_attempts`, rather than `len(observations)`: the contract deliberately retains cancelled observations without sending a packet. This was a test-spec correction, not an implementation relaxation.

## Final result

Command: `.venv/bin/python -m pytest tests/test_cli.py tests/test_engine_review.py -q`

Result: **68 passed in 2.69 s**, exit **0**. This includes 42 CLI contract cases and 26 independently authored engine-review cases. CLI-owned tests added; existing group tests expanded for process integration and corrected for cancellation accounting; none deleted.

Implementation notes:

- `--agent` supplies JSON/summary defaults; explicit `--format ndjson` or `--detail full` is honored.
- `observe` and `bench` require explicit targets, resolvers, duration, and interval/rate respectively; they share one scheduler and keep `capacity_test=false`. Bench is a bounded diagnostic workload, not a claim of resolver capacity measurement.
- `compare` refuses simple performance-regression verdicts without paired statistical evidence; condition and finding differences remain available.
- Artifact report SHA256 is returned to the caller, rather than embedded in the bytes it hashes. Evidence hash and both file paths are embedded in the saved report.
- Windows remains experimental; no Windows real-process validation was performed here.

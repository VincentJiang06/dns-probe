# Engine TDD and independent verification

2026-09-07, macOS, Python 3.14.6.

1. Initial bounded-run contracts: 9 tests failed against NotImplementedError stub; implemented engine, 9 passed.
2. Added expectation max_answers/AD, explicit encrypted transport execution, cancelled advanced coverage, and event reference contracts: 6 failed / 10 passed; implementation fixed them, 16 passed.
3. Replaced engine temporarily with saved pre-fix file and ran the same tests: 6 failed / 10 passed, `REVERT_PROOF_EXIT=1`; restored in finally, then 16 passed. Backup `/tmp/dnsprobe-engine-before-contract-fixes.py` was local verification scratch, not package input.
4. Fresh independent verifier authored `test_engine_review.py` without production edits. Initial batches: 12 failed, then controlled negatives/owner tests 3 failed + 1 control passed, then all/deep selection 2 failed. All initial 18 regressions passed after fixes.
5. Second independent review: 6 engine regressions failed (internal error, cancelled CNAME references, system DNS64 control, SERVFAIL PERF/CACHE, per-target ranking); 2 series regressions failed (comparison schedule, attempt-stop reason). Engine/CLI fixes passed all 26 cases.
6. Added default-authority privacy regression for `private` and private-name public scope: 2 failed before fix. Central target privacy marker and delegation policy stop both. Evidence-budget regression confirms no new query after 16 MiB evidence cap.
7. Combined first integration run: 106 passed / 2 failed. One error-priority issue fixed in CLI. The other assertion required skipped on a real 100 ms UDP cancellation; native transport could legitimately finish its rounded 99 ms timeout first, yielding inconclusive. Assertion now accepts either incomplete state while retaining mandatory exit3 and target-level coverage.

Commands: `.venv/bin/python -m pytest tests/test_engine.py -q`, `.venv/bin/python -m pytest tests/test_engine_review.py -q`, and full `.venv/bin/python -m pytest -q`. Real loopback tests run with sandbox permission; no public network is used by this suite. This document records actual red/green steps, not a claim of cross-platform execution.

8. Default `--connect` originally selected APP.CONNECT but omitted its default app endpoint: 1 red, fixed to TLS/443 for selected targets. Explicit connect warning assessment and silently unmatched expectation tests: 4 red, fixed required scope plus input target/type/resolver matching.

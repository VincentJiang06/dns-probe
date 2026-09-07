# Independent acceptance evidence

Date: 2026-09-07. Repository: `repository root`.

## Final command and result

```text
.venv/bin/python -m pytest tests/test_engine_review.py -q
..................................                                       [100%]
34 passed in 0.44s
Process exit code: 0
```

The final run used the current delivered source. The review tests use an offline,
recording transport and discovery fixture; no personal data, external resolvers,
or production network endpoints were accessed. This acceptance pass changed only
this evidence document; it did not modify production code.

## Focused source confirmation

Inspected only the six engine regression fixes from the preceding review:

1. An unexpected transport implementation exception is copied into report errors
   and produces execution error / exit 4, rather than a completed network failure.
2. Advanced queries receive their owning check ID before the query starts. Final
   evidence reconciliation retains both completed and cancelled alias observations.
3. DNS64 skips its generated `ipv4only.arpa` control under system/private scope.
4. PERF samples use response semantics; all-SERVFAIL responses no longer pass.
5. CACHE checks require semantically successful observations; all-SERVFAIL
   responses no longer pass.
6. Resolver eligibility requires adequate comparable samples for each target and
   record-type group. A successful pooled rate cannot hide a target whose repeated
   queries all time out.

The final 34-case run also retained the earlier privacy, explicit selection,
controlled-negative, owner-reachability, synthetic-answer, implementation
fingerprint, observation schedule, and shared series attempt-limit regressions.

## Verification boundary

No unresolved failure remains in this bounded regression set. These results verify
deterministic engine/report integration, not current public DNS behavior, native
OS routing, cryptographic transport interoperability, or release-package startup.
Those require the separate transport/platform and packaging acceptance evidence.
This pass did not reopen a broad review or claim exhaustive defect absence.

## Follow-up: native resolver record-type applicability

The native `getaddrinfo` path supports A and AAAA, not arbitrary DNS record types.
An explicit TXT/MX request previously became `SYSTEM_HELPER_ERROR`, retried, and
produced a DNS path failure. Explicit `DNS.BASIC` on a native-only path also left
an unresolved alias check even when A/AAAA succeeded.

Added one parameterized applicability group in `test_engine_review.py`, covering
A/AAAA/MX/TXT on native-only and native-plus-wire paths, plus MX/TXT with automatic
discovery of an applicable wire resolver. The test uses an offline recording
transport for routing decisions and calls the real native adapter only for its
unsupported-type guard; no public target resolution is required.

Actual targeted RED before production edits:

```text
.venv/bin/python -m pytest tests/test_engine_review.py -q -k native_record_type --tb=short
6 failed, 2 passed, 34 deselected in 0.19s
exit 1
```

Failures were four unsupported native checks still planned as pending, and two
supported native-only controls assessed unknown due to the `DNS.BASIC` alias.
After the requested auto-discovery usability refinement, its two added cases
also failed on unknown versus pass before that production change.

The delivered policy is:

- Unsupported native types are skipped with `SYSTEM_RRTYPE_UNSUPPORTED`, without
  starting a helper, consuming an attempt, retrying, or substituting A/AAAA.
- Native PERF/CACHE repeats for an unsupported requested type are also skipped.
- Explicit native requests remain required and unresolved (unknown / exit 3).
- In auto mode with an applicable discovered wire resolver, non-address record
  queries use required wire checks; the unsupported native check is optional.
- Explicit wire MX/TXT queries and native A/AAAA remain supported.

Actual final validation:

```text
.venv/bin/python -m pytest tests/test_engine.py tests/test_engine_review.py -q
60 passed in 0.78s
exit 0
```

Reverting only `engine.py` and `discovery.py` to their pre-fix contents, retaining
all ten applicability cases, then restoring both files in `finally`:

```text
.venv/bin/python -m pytest tests/test_engine_review.py -q -k native_record_type --tb=no
8 failed, 2 passed, 34 deselected in 0.11s
exit 1

.venv/bin/python -m pytest tests/test_engine_review.py -q
44 passed in 0.46s
exit 0
```

The real CLI repro was rerun after the fix:

```text
.venv/bin/python -m dnsprobe example.test TXT @system --tests DNS.BASIC --network-scope system --budget 1s --detail full
assessment: unknown
execution: completed; exit 3
check: skipped; SYSTEM_RRTYPE_UNSUPPORTED; required true
cost: dns_attempts 0; auxiliary_calls 0
observations: []; findings: []; errors: []
```

Independent final acceptance collected 10 applicability cases out of 44 review
cases and ran them: `10 passed, 34 deselected in 0.10s`, exit 0. The reviewer also
reran the original CLI repro with the same corrected result and found no stale
or duplicate test: engine applicability/assessment/cost coverage is distinct from
the existing native-transport field/deadline checks, which remain unchanged.

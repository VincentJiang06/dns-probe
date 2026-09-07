# Advanced diagnostics test evidence

Tests were written before `src/dnsprobe/advanced.py` existed.

- Red: `.venv/bin/python -m pytest -q tests/test_advanced.py` exited 2, `ModuleNotFoundError: No module named 'dnsprobe.advanced'` (11 tests).
- Initial implementation: 10 passed; the localhost TCP test was blocked by sandbox socket binding (`PermissionError`), not by a code assertion. Approved local-only rerun exited 0, 11 passed.
- Added behavioral regression tests before fixes: all-test APP precondition coverage and unproven CNAME terminal returned 2 assertion failures (exit 1). Fixed explicit skip and inconclusive semantics; rerun passed.
- Added native-system APP regression before fix: system path incorrectly skipped APP (exit 1). Fixed to resolve through the native probe before connecting to numeric addresses.
- Added denial proof regressions before fix: parent delegation NSEC/NSEC3 incorrectly proved child A NODATA (2 failures, exit 1). Fixed delegation boundary handling.
- Final: `.venv/bin/python -m pytest -q tests/test_advanced.py` exited 0: **24 passed in 0.06s** on macOS, Python 3.14.6 (2026-09-07). Local TCP/TLS tests ran with sandbox escalation; no public network tests or stress tests were used.

Coverage includes CNAME loops inside one response, depth bound and timeout ambiguity, optional RR absence, unavailable/expired DNSSEC fixtures, DNS64 /96 synthesis, missing NSID, absent trust anchors, actual ECDSA signature acceptance and tampered response rejection, authenticated DS/DNSKEY chain from a DS trust anchor, signed NSEC and NSEC3 NXDOMAIN proofs, invalid denial signatures, parent/child zone boundary handling, delegation privacy and unrelated glue rejection, local TCP connections, certificate trust and strict TLS hostname verification.

All DNS operations, including key and DS lookup, use the injected probe. Application connections use the injected network slot and numeric addresses (no implicit resolver calls). Tests generate their own signing keys/certificates and do not need installed trust anchors or internet access.

References consulted for implementation:
- https://dnspython.readthedocs.io/en/latest/dnssec.html (DNSSEC local signing, validation, DS and NSEC3 helpers)
- https://www.rfc-editor.org/rfc/rfc7050.html (DNS64 discovery controls and prefix formats)

Deliberate limits are surfaced in check reason codes: missing trust anchor, unsupported/denied algorithm, NSEC3 opt-out, high-iteration NSEC3, incomplete denial or delegation chain, positive wildcard requiring proof, unavailable DNS wire data. These conditions are never reported as successful local validation. No trust-anchor auto-update or claim of universal validator completeness is made.

## Independent integration review corrections

Six new failing regression tests were added before corrections. The first focused run failed five assertions (exact plan selection, all-tests required status, application answer ownership, DNS64 answer ownership, reachable alias helper). A subsequent signed-fixture control regression failed separately because unrelated normal-mode answers were accepted.

Corrections: the engine's internal `_selected_tests` is honored exactly without mutating the original `tests` request; `all` and explicit lists retain required semantics; optional `_required_tests` allows engine policy ownership. Application connections, DNS64, record reports, and DNSSEC fixture checks only consume terminal records reachable from the queried owner through an unambiguous bounded CNAME chain. Both normal and CD fixture responses must satisfy configured answer expectations.

Final local-fixture command: `.venv/bin/python -m pytest -q tests/test_advanced.py` exited 0, **30 passed**. Review integration subset initially showed private-fixture routing and all-tests failure aggregation passing; deep-auto selection required the root engine to pass its agreed `_selected_tests` marker.

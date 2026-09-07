# Human DNS answer view evidence

Date: 2026-09-07. Scope: `src/dnsprobe/report.py` and the existing parameterized
presentation feature group in `tests/test_presentation.py`.

## Inventory and test changes

The independent inventory agent ran the native presentation collector:
`.venv/bin/python -m pytest tests/test_presentation.py --collect-only -q`.
It found seven cases in one existing feature group, with no answer-record display
assertions. Modify mode extended that group to ten cases: normal/deduplicated
answers, negative/nullable answers, and long/bounded answers. The existing hostile
input case now also exercises answer owners and TXT values. No new test function,
duplicate suite, production-network fixture, or JSON contract was added.

## Actual RED, GREEN and revert proof

The initial delegated targeted run caught a bracket typo in the new fixture at
collection time (exit 2). That was corrected before production edits and is not
counted as behavior RED evidence.

Delegated command after that correction:

```text
.venv/bin/python -m pytest tests/test_presentation.py -q
10 failed in 0.08s
exit 1
```

The three new cases failed on absent answer rows: zero rows instead of seven,
missing NXDOMAIN/target text, and missing TXT/RRSIG values. Existing cases failed
the updated human product label (`DNSProbe` versus `DNS Probe`).

After implementing the renderer, without weakening or changing the test:

```text
.venv/bin/python -m pytest tests/test_presentation.py -q
10 passed in 0.04s
exit 0
```

Reverted only `report.py` to its pre-change contents, kept tests, ran the new
answer cases, and restored the fixed file in a `finally` block:

```text
.venv/bin/python -m pytest tests/test_presentation.py -q -k answers
3 failed, 7 deselected in 0.03s
exit 1

.venv/bin/python -m pytest tests/test_presentation.py -q
10 passed in 0.03s
exit 0
```

Independent final verification reran the complete presentation file:
`10 passed in 0.04s`, exit 0. Its stale/duplicate scan found no obsolete assertion
or duplicate feature group; the original null, terminal-control, width, omission,
and nonmutation checks remain in place. No tests were weakened or deleted.

## Delivered behavior

Human output shows up to 12 distinct answer rows, including path/protocol, owner,
record type, TTL in seconds, and value. Repeat observations collapse only when
their recorded path, protocol, family, owner, type, TTL, and value agree. Distinct
paths, values and TTLs remain represented. Missing TTLs/values stay `-`; an actual
TTL of zero remains zero. Negative responses retain their recorded response code
without inventing answers. Long TXT/DNSSEC fields are clipped visibly; omitted row
counts and the full JSON location are stated. Existing terminal-control escaping,
100-column/100-line bounds, report immutability, and lossless JSON checks pass.

Actual output from the repository's `examples/report.json`:

```text
DNS Probe 1.1.0
Observed answer records (repeat rows collapsed)
Path/protocol   Owner                     Type      TTL (s)   Value / response
--------------  ------------------------  --------  --------  --------------------------------
fixture/udp     example.test.             A         60        192.0.2.10
Full values and every attempt: --detail full --json (observations[].answers).
```

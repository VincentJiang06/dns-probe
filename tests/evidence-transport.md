# Transport and discovery verification

2026-09-07, macOS, project `.venv/bin/python` (Python 3.14), dnspython 2.8.0.
Tests use local loopback UDP/TCP/TLS/HTTP/QUIC fixtures, a generated temporary CA,
and native localhost lookup. No public DNS stress tests were performed.

## Actual red / green evidence

- Initial `.venv/bin/python -m pytest tests/test_transport.py -q`: exit 1,
  `3 failed in 0.03s`, missing `dnsprobe.transport` / `dnsprobe.discovery` modules.
  After implementation: exit 0, `3 passed in 0.22s`.
- Encrypted fixture group: exit 1, `1 failed, 3 passed in 0.37s`;
  post-handshake DNS timeout incorrectly said `stage=tls`.
  Fix: exit 0, `4 passed in 0.51s`. Reverting only DNS phase marker reproduced
  `assert 'tls' == 'dns'` (exit 1); restored suite passed (exit 0).
- QUIC handshake blackhole at 40 ms: exit 1, `1 failed in 0.80s`;
  default dnspython QUIC close consumed about 643 ms, exceeding the 250 ms bound.
  A pinned-version bounded shutdown adapter cancels/joins socket tasks and enables
  connection reuse. Updated suite: exit 0, `5 passed in 0.56s`.
- Strict question matching: `.venv/bin/python -m pytest tests/test_transport.py::test_dns_wire_contract -q`
  exited 1, `assert 'SERVFAIL' == 'NOERROR'`; dnspython accepts error responses
  without the query question. Explicit equality fixes this; suite exit 0.
- HTTP reuse reporting: encrypted group exited 1 (`assert 'reused' == 'new'`)
  after server `Connection: close`; httpcore connection trace now records actual
  new connections, instead of treating a reused client as a reused connection.
  Encrypted group then exited 0 (`1 passed in 0.50s`).
- Interface binding: wire group exited 1 (`outcome=error`, expected response);
  implemented psutil interface address selection and socket source binding.
  All groups then exited 0 (`5 passed in 0.82s`).
- System family: native group exited 1 (`assert 'ipv4' is None`); changed
  unobservable DNS transport family to null, and separately report
  `answer_address_family`. Suite exited 0 (`5 passed in 0.59s`).
- Combined revert-to-red for strict question equality, bounded QUIC shutdown,
  and system family: command selecting wire/native/cancel groups exited 1,
  `3 failed in 0.83s`, each matching its original failure (QUIC 643 ms).
  Restored fixes: `.venv/bin/python -m pytest tests/test_transport.py -q`,
  exit 0, **`5 passed in 0.57s`**.

Added five coherent feature-group tests; expanded existing groups for edge cases.
No tests removed or weakened. A first QUIC blackhole fixture accidentally closed
its stream upon request EOF; corrected the fixture to hold its response open.
That fixture mistake is not counted as feature red evidence.

## What is covered

- Real UDP AAAA, authority SOA, EDNS EDE, semantic NXDOMAIN;
  wrong ID, malformed data and error reply missing question ignored until a
  matching reply. No automatic TCP fallback in transport.
- Real TCP persistent connection and truncated flag preservation;
  deadline blackhole cancellation.
- Real DoT/DoH/DoQ with local CA and hostname validation; DoT/DoH wrong trust
  and wrong hostname errors; HTTP 503 and wrong media type; HTTP keepalive
  closure and reopened connection; encrypted response timeout attribution.
- Native resolver returns unobservable fields as null; helper interruption
  kills the actual PID (OS `kill(pid, 0)` confirms process absent).
- Source binding to real loopback interface; mismatched address family error;
  native explicit interface rejected without launching resolver helper.
- macOS scoped/supplemental DNS, resolv.conf search domains, Windows NRPT
  parser fixtures. Live macOS discovery outside sandbox returned three resolver
  records from `scutil --dns`, 29 interfaces, no warnings. Sandbox-only discovery
  correctly returned the `resolv.conf` fallback with scope-incomplete warnings.

## Explicit limits

- Source address binding records `route_selection=kernel_selected`; it does
  not assert a particular physical egress interface or route.
- Linux discovery uses `resolvectl status` with explicit D-Bus-not-queried
  fallback metadata; Windows/Linux parser support is not a claim of live OS
  certification. This run only verified real macOS discovery.
- Native lookup internal wire attempts/upstream IP/RCODE/AD/TTL are unobservable.
  Hostname bootstrap is one bounded native call reported separately.
- DoQ shutdown extends dnspython internals; dependency is pinned to 2.8.0 and
  upgrade requires rerunning these local handshake/cancellation fixtures.

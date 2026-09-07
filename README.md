# DNS Probe

**Find out what your DNS is doing—with one command.**

[中文](README.zh-CN.md) · [CLI guide](docs/CLI.md) · [JSON integration](docs/AGENT_INTEGRATION.md) · [Design decisions](docs/COMPARISON.md) · [MIT license](LICENSE)

DNS Probe is a DNS diagnostic CLI. Give it a domain and optionally a resolver: it checks resolution, relevant protocol behavior and repeated responses within a fixed budget, then explains what passed, what failed and what remains unverified. View answers and timings in your terminal, or consume a versioned JSON report in scripts, CI and agents.

```sh
dnsprobe example.com --human
dnsprobe example.com A AAAA @1.1.1.1 --human
dnsprobe example.com @https://dns.google/dns-query --pretty
```

The command is **`dnsprobe`**; the Python package is **`dns-probe`**. This is an independent project, unrelated to the archived [ProjectDiscovery dnsprobe](https://github.com/projectdiscovery/dnsprobe).

## Install

Python **3.11+** is required. Install directly from GitHub with [uv](https://docs.astral.sh/uv/):

```sh
uv tool install git+https://github.com/VincentJiang06/dns-probe.git@v1.2.1
```

Or clone and install the source:

```sh
git clone https://github.com/VincentJiang06/dns-probe.git
cd dns-probe
```

From the checkout:

```sh
uv tool install .
dnsprobe --version
dnsprobe example.com --human
```

With pip, run `python -m pip install .` inside a virtual environment. For development, use `uv sync --locked` and `uv run --no-sync dnsprobe example.com --human`. Installation uses [uv](https://docs.astral.sh/uv/) or pip; subsequent calls run `dnsprobe` directly.

PyPI, Homebrew and prebuilt native binaries are not published yet. Install from GitHub or a verified wheel from [Releases](https://github.com/VincentJiang06/dns-probe/releases). If upgrading from the earlier local `dnsprobe-agent` package, see [migration](LEGACY_MIGRATION.md).

## Everyday commands

```sh
# Diagnose with the system's applicable resolver paths
dnsprobe example.com --human

# Select records and a resolver; quoted URLs also work
dnsprobe example.com MX @1.1.1.1 --human
dnsprobe example.com @tls://one.one.one.one:853 --human
dnsprobe example.com @https://dns.google/dns-query --human

# Faster bounded diagnosis, or only the basic DNS check
dnsprobe example.com --profile quick --budget 2s --human
dnsprobe example.com A @1.1.1.1 --tests DNS.BASIC --human

# Multiple domains or resolvers
dnsprobe example.com example.org @1.1.1.1 @8.8.8.8 --human

# Keep an internal name on a specified internal resolver
dnsprobe service.corp @10.0.0.53 --network-scope system --human

# Inspect a plan without sending DNS traffic
dnsprobe plan example.com @1.1.1.1 --pretty
```

`--human` is short for `--format text`. It shows answers with owner, record type, TTL and resolver path, followed by execution status, findings, coverage and timings. Long answers and large reports are abbreviated in this view; the complete evidence is available as JSON. See the [terminal example](examples/terminal.txt), generated from a local synthetic DNS fixture.

Use uppercase record types **after a name**: `example.com A AAAA`. For unambiguous input, use `-d/--domain`, `-t/--type` and `-r/--resolver`. Lowercase single labels are names; a name matching a subcommand needs `dnsprobe run NAME`. [CLI guide](docs/CLI.md) covers precedence and edge cases.

## JSON when you need it

**JSON is the default**, including in a terminal. There are no prompts or progress animations in stdout.

```sh
dnsprobe example.com                           # Compact JSON summary
dnsprobe example.com --pretty                  # Indented JSON
dnsprobe example.com --jsonl                   # Events, then one terminal report
dnsprobe example.com --detail full             # Every check and observation
dnsprobe example.com --artifact-dir .artifacts # Save full report + evidence
dnsprobe --request-json - < examples/request.json
dnsprobe schema --kind report
```

`--json` explicitly selects JSON; `--jsonl` selects NDJSON. `--pretty` only applies to JSON. Defaults are identical in terminals, pipes and CI. `--agent` remains a compatibility alias; it is not required.

A consumer first reads `execution.exit_code`, `assessment.status` and `coverage.sufficient_for_assessment`, then `findings`. Execution finishing does not mean DNS is healthy. Summaries are capped at 8 KiB before optional indentation; full output at 64 MiB. Full reports and saved artifacts contain the records and evidence omitted from summaries.

| Exit code | Meaning |
|---|---|
| 0 | Required evidence is sufficient; no failure policy triggered |
| 1 | Required checks or failure policy failed |
| 2 | Invalid input |
| 3 | Incomplete evidence, deadline or resource limit |
| 4 | Tool or artifact-writing error |
| 130 | Interrupted; collected evidence retained where possible |

Examples: [request](examples/request.json), [full report](examples/report.json), [summary](examples/summary.json). Integration details, safe argument arrays and schema handling: [JSON integration](docs/AGENT_INTEGRATION.md).

## What it checks

- Native OS address lookup; UDP, TCP, authenticated DoT, DoH and DoQ.
- RCODE/address/AD expectations, negative responses, EDNS/EDE and TCP fallback after truncation.
- CNAME chains, record inspection, bounded delegation trace, DNS64, NSID and explicit ECS.
- DNSSEC resolver behavior with expiring fixtures; local signature/DS-chain and supported denial-proof validation with supplied trust anchors.
- Optional TCP/TLS application connectivity with `--connect`.
- Repeated response behavior and bounded observation sessions, sharing deadline, attempt, rate and concurrency limits.

| Profile | Default deadline | DNS attempt cap |
|---|---:|---:|
| quick | 5 s | 80 |
| standard | 15 s | 240 |
| deep | 60 s | 900 |

Budgets are upper bounds. Healthy runs may finish earlier. `--tests all` enumerates checks and reports missing prerequisites; it cannot make externally controlled fixtures or trust anchors appear. `IDENTITY.OBSERVE` is unavailable without external infrastructure. DNSSEC limitations and Windows experimental support are documented in [implementation status](docs/STATUS.md).

Without targets, the default diagnostic can use built-in public control domains. With your own names, automatic public comparison requires `--public-comparison`; explicit resolvers select the endpoints to contact. Discovered private suffixes need per-target permission for automatic public paths. `system`/`private` scope disables automatic public candidates and public controls. See [query scope](docs/CLI.md#query-scope) before testing internal names.

DNS Probe does not change system DNS settings or flush caches. Encrypted transports verify certificates and hostnames; there is no insecure automatic fallback. Environment HTTP proxies are not used. `--connect` makes TCP/TLS connections and does not send an HTTP request.

## Observe and compare

```sh
dnsprobe observe example.com @1.1.1.1 --duration 1m --interval 5s --human
dnsprobe bench example.com @1.1.1.1 @8.8.8.8 --duration 15s --rate 20 --human
dnsprobe explain --report report.json --finding f-001
dnsprobe compare before.json after.json
dnsprobe capabilities --pretty
```

Observe and bench require targets, resolvers and duration; observe also needs an interval, bench a rate. All samples share a resource budget. Bench measures diagnostic samples, not server capacity. p95/p99 require at least 20/100 successful samples; a recommendation may be absent when per-target evidence is insufficient. Changed networks, configuration or implementation prevent direct regression conclusions.

## Built on proven libraries

[dnspython](https://www.dnspython.org/) supplies DNS messages, records, asynchronous transports and DNSSEC primitives; HTTPX, aioquic and cryptography support encrypted transports and signatures. DNS Probe adds bounded scheduling, system-path discovery, evidence evaluation and a consistent CLI/report contract. It does not require an installed `dig` or parse another CLI's terminal output.

The command syntax draws on [doggo](https://github.com/mr-karan/doggo) and [q](https://github.com/natesales/q); JSONL and explicit measurement limits draw on dnsx and iperf3. See [research and reuse decisions](docs/COMPARISON.md). Their implementation code has not been copied into this project.

## Development

```sh
uv sync --locked
uv run --no-sync pytest -q
uv run --no-sync python -m build --no-isolation
uv run --no-sync python scripts/check_distribution.py
uv run --no-sync python scripts/prepare_release.py --require-license --output release
```

Tests use offline DNS messages and loopback UDP/TCP/TLS/HTTPS/QUIC servers. GitHub CI passed all 187 tests, package builds and wheel smoke checks on macOS and Linux with Python 3.11/3.14. Windows remains experimental: its initial CI run has 9 failures in discovery/deadline and platform-dependent test cases. See [validation](docs/VALIDATION-1.2.1.md) for actual results and limits.

The source exporter produces an allowlisted ZIP with SHA-256 hashes. Local network reports and unrelated workspace files are excluded. See [releasing](docs/RELEASING.md), [contributing](CONTRIBUTING.md), [security](SECURITY.md) and [changelog](CHANGELOG.md).

Licensed under [MIT](LICENSE).

# DNS Probe CLI guide

## Names, types and resolvers

```sh
dnsprobe example.com
dnsprobe example.com A AAAA @1.1.1.1 --human
dnsprobe example.com --human @1.1.1.1 A
dnsprobe -d example.com -t MX -r 1.1.1.1 --human
```

Omitting a command means `run`. A name can also be an HTTP(S) URL; only its hostname is used, and no page is fetched. The shorthand works on `run`, `plan`, `observe` and `bench`.

- Bare names are targets. Uppercase known DNS type tokens after a target, such as `A`, `AAAA` or `MX`, select types for all CLI targets. Without explicit types, targets default to A and AAAA.
- A leading `@` selects a resolver and must have a nonempty endpoint after it. It can appear before or after names. Repeat it for multiple resolvers.
- `-d/--domain`, `-t/--type` and `-r/--resolver` are explicit, repeatable equivalents. A target given with `-d` also enables bare uppercase type tokens. Named lists precede shorthand lists when both are used; validation rejects conflicting resolver definitions.
- Lowercase `a` or `mx` is a hostname, not a type. Use `-t mx` to request MX explicitly. A literal uppercase single-label hostname matching a type can be supplied with `-d A`.
- Root command words are reserved: use `dnsprobe run plan` for a hostname named `plan`. Use `--domain` when a name would otherwise be ambiguous. Arguments after `--` are positional; it does not disable the shorthand interpretation.
- Flags and positionals may be interleaved. Invalid options stay errors and produce structured JSON by default.

Configuration is merged in this order: explicit `--config`, then `--request-file` or `--request-json`, then CLI options. No config file or environment variable is discovered implicitly. CLI targets replace configured targets; CLI resolvers replace configured resolvers. Output flags override configured output. Prefer a JSON request for per-target types, application expectations, bootstrap addresses or private CA paths.

## Select output

| Option | Result |
|---|---|
| default / `--json` | Compact JSON; diagnostic runs default to summary |
| `--pretty` | Indented JSON |
| `--human` / `--format text` | Bounded human-readable answer and diagnostic tables |
| `--jsonl` / `--format ndjson` | One JSON event per line, including a terminal report |
| `--detail full` | All available checks, observations and evidence in JSON |
| `--artifact-dir PATH` | Full report and evidence in a new run directory, with returned paths and hashes |

Formats are mutually exclusive. `--pretty` cannot be combined with human or JSONL output. Explicit `--detail summary` can omit answer observations even in the human view. Text output never invents omitted information: use full JSON to inspect long record data, individual repeated responses or authority/additional sections.

Returned DNS text is untrusted. Human output escapes controls and clips long rows; JSON escaping preserves the original decoded value. No ANSI colors or full-screen terminal are required.

## Query scope

```sh
dnsprobe service.corp @10.0.0.53 --network-scope system --human
dnsprobe example.com --public-comparison --human
dnsprobe example.com @tcp://1.1.1.1:53 --human
dnsprobe example.com @tls://one.one.one.one:853 --human
dnsprobe example.com @https://dns.google/dns-query --human
dnsprobe example.com @quic://dns.adguard-dns.com:853 --human
```

No explicit resolver: discover the native system path and applicable configured DNS servers. User names are not automatically sent to built-in public comparison candidates unless `--public-comparison` is enabled. Without targets, a diagnostic can use built-in public control domains and candidates.

Explicit resolvers replace automatic candidates and select those endpoints. A literal IP defaults to UDP port 53; native OS resolution is selected by `@system`. UDP/TCP endpoints take numeric addresses; encrypted hostnames may need bootstrap resolution unless `bootstrap_ips` is supplied in JSON. IPv6 endpoints with a port use brackets, for example `'@udp://[2606:4700:4700::1111]:53'`.

`--network-scope system` and `private` currently share a conservative policy: explicit targets are required; automatic public candidates, public controls and default root tracing are disabled. Neither scope overrides a resolver you explicitly selected. Discovered private suffixes, `.local` and single-label names need per-target `allow_public: true` for automatic public comparison. Unrecognized private domains cannot be classified perfectly; select your internal resolver explicitly.

The OS native path provides address lookup, not raw DNS TTL, RCODE, AD or arbitrary record types. Unknown fields remain unknown. Use a wire resolver for MX/TXT/SOA or DNS protocol evidence. Unsupported native types are reported as `SYSTEM_RRTYPE_UNSUPPORTED` without a helper call or retry. With automatic selection and an applicable discovered wire resolver, non-address record checks require that wire path and treat the unsupported native path as optional. Explicit `@system` for an unsupported type remains incomplete (exit 3), never a DNS failure. Container runs observe the container network namespace; they do not automatically reproduce host DNS.

## Control time and work

```sh
dnsprobe example.com --profile quick --budget 2s --human
dnsprobe example.com A @1.1.1.1 --tests DNS.BASIC --human
dnsprobe example.com --profile deep --tests all --detail full
dnsprobe example.com --max-attempts 80 --concurrency 8 --rate 20 --human
```

Durations accept `ms`, `s`, `m`, `h`; an unqualified number means seconds. The maximum budget is one hour. Work shares global limits, including retries, TCP fallback and advanced queries; native API wire packet counts are unavailable and auxiliary calls are reported separately. `--tests DNS.BASIC` restricts checks to basic resolution; `all` requests the full catalog with explicit unmet-prerequisite outcomes.

For response validation or DNSSEC, prepare a request using `dnsprobe schema --kind request` and [controlled fixtures](../examples/controlled-fixtures.json). Example `.invalid` zones and documentation addresses must be replaced by services you control. Local DNSSEC validation requires explicit trusted DS/DNSKEY material. A resolver's AD bit alone is not local signature verification.

`--connect` opts into TCP/TLS application checks. It never fetches a supplied URL. `--ecs` explicitly adds the chosen client subnet; it is never inferred. Source-interface binding selects a local source address; the kernel still selects the actual route.

## Observe and inspect

```sh
dnsprobe observe example.com @1.1.1.1 --duration 1m --interval 5s --max-runs 12 --human
dnsprobe bench example.com @1.1.1.1 @8.8.8.8 --duration 15s --rate 20 --human
dnsprobe capabilities --pretty
dnsprobe plan example.com @1.1.1.1 --pretty
dnsprobe explain --report report.json --finding f-001
dnsprobe compare before.json after.json
```

Plan and inspection commands are offline. A plan does not perform system discovery; runtime discovery refines it. Observation and benchmark sessions require explicit targets, resolvers and duration. They share one budget across samples and may stop early. Short sample sizes do not support tail percentiles or resolver recommendations. See [implementation limits](STATUS.md).

## Help and compatibility

```sh
dnsprobe --help
dnsprobe run --help
dnsprobe observe --help
dnsprobe --version
python -m dnsprobe example.com --human
```

`dnstk` and the original root Python entrypoints remain compatibility routes to the same engine. See [legacy migration](../LEGACY_MIGRATION.md). They are not the recommended starting point for new usage.

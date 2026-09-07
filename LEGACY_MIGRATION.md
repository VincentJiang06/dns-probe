# Legacy script migration

`dnstk.py`, `dns_bench.py`, `dns_bench_hk.py`, and `dns_lab.py` now delegate their
`main()` entrypoints to the modern bounded engine. The original functions remain
available as historical source/reference; the normal CLI no longer executes the
old query, ranking, burst, or output-capture implementation.

Use the installed environment (for example `.venv/bin/python dnstk.py ...`).
The preferred supported interface is `dnsprobe example.com --human`, or
`dnsprobe example.com` for JSON.

## Preserved paths

```sh
python dnstk.py agent bench -s 127.0.0.1 -d example.com --no-ping
python dns_bench.py -s 127.0.0.1 --no-v6 --json result.json
python dns_bench_hk.py -s 127.0.0.1 --quick
python dnstk.py agent sys --brief
python dns_lab.py --profile quick -s 127.0.0.1
python dns_lab.py --duration 300 --interval 15 -s 127.0.0.1 -d example.com
```

Addresses above are examples, not an assertion of a running local DNS service.

- `-s/--server`, `-d/--domain`, `--servers-file`, `--no-v6`, and
  `-c/--concurrency` map to modern requests. A server file accepts one
  `IP [name] [group]` per line; labels are not fabricated into modern rankings.
- `--json PATH` writes the **modern full report** atomically to the exact path.
  `dnstk agent ... --json PATH` can both write that report and print its envelope.
- `--brief` retains execution, assessment and coverage in the envelope, while
  omitting `data`. `--quiet`, `--no-ping`, and `--color never` remain usable;
  modern diagnostics do not have a progress dashboard or implicit ICMP probes.
- HK mode selects the `hong-kong` workload; HK `--quick` selects the modern
  five-second quick profile. Legacy bench uses quick by default.
- Legacy lab `quick` has no observation window and maps to a bounded 60-second
  deep run. Legacy lab `standard` (including no profile) retains its configured
  300-second observation window and 15-second interval; `marathon` retains
  1800 seconds and 15 seconds. `--duration/--interval` override these in seconds.
  These sessions use the modern shared query/concurrency/rate caps, can end with
  partial coverage on exhaustion, and **do not run the former burst test**.
  With no explicit servers, legacy observation uses the native system path;
  with no target, it uses the public control name `example.com`.
- `--no-hijack` omits `DNS.NEGATIVE`; `--no-audit` additionally omits DNSSEC
  behavior tests. These flags do not restore the old unreliable hijack claims.
- `--no-local` requires explicit resolver input. `--budget` is a new convenience
  for an explicit modern per-run wall-clock budget; an observation session also
  retains its independent total duration and shared resource cap.

## Envelope and explicit breaking changes

The machine envelope retains `ok`, `mode`, `elapsed_s`, `warnings`, `recommend`,
and (unless brief) `data`. It adds `returncode`, `execution`, `assessment`,
`coverage`, and `compatibility`. `data` is a versioned DNS Probe report; it is not
an unversioned legacy payload. `recommend.primary/backup` remain null: historical
scores/rankings are not reconstructed. `ok` is true only for exit code 0, and
partial/insufficient reports retain modern exit code 3. Never infer network
health solely from the existence of an output file.

Deprecation messages go to stderr; successful machine stdout is one JSON object.
Input failures return a structured error with an actionable modern argv and
exit code 2. Forced ANSI output and the historical exact-round count,
per-query timeout, reliability threshold, ranking top-N, preset and regional
candidate-list flags are rejected, rather than silently changed. Use explicit
modern `--resolver`, `--workload`, `--budget`, `--tests`, or `bench --duration
--rate` as appropriate. Default candidate selection uses modern discovery and
privacy rules, not the historic exhaustive public-server list; the envelope
warns about that difference. For exact data-schema consumers, migrate to the
new command before upgrading.

## 1.2 package and command naming

The product is **DNS Probe**. The Python distribution was renamed from
`dnsprobe-agent` to `dns-probe`; `dnsprobe` and `dnstk` command names are unchanged.
The JSON schema major version remains 1. New shorthand arguments and `--human`
are additive; `--agent` and named long options remain supported.

For an earlier uv tool installation, run from the new source checkout:

```sh
uv tool uninstall dnsprobe-agent
uv tool install .
dnsprobe --version
```

For a pip virtual environment, remove the old distribution before installing
the new one: `python -m pip uninstall dnsprobe-agent`, then
`python -m pip install .`. They expose the same console scripts and should not
be installed side by side. `uv sync --locked` handles the rename in the project
virtual environment automatically.

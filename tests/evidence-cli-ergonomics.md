# DNS Probe CLI shorthand: observed test evidence

Date: 2026-09-07. Scope: `src/dnsprobe/cli.py` and `tests/test_cli.py`.
This feature follows the approved DNS Probe naming and familiar DNS command
syntax. It does not change transport/query behavior or default JSON output.

## Syntax contract

```console
dnsprobe example.com A AAAA @1.1.1.1 --human
dnsprobe plan example.com --pretty
dnsprobe plan @1.1.1.1 example.com --profile quick A other.test @8.8.8.8
dnsprobe -d example.com -t A -r 1.1.1.1
dnsprobe observe example.com A @1.1.1.1 --duration 5s --interval 1s
dnsprobe bench example.com A @1.1.1.1 --duration 5s --rate 10
```

- Positional shorthand is available on implicit/explicit `run`, `plan`, `observe`
  and `bench`. Existing duration, traffic and input bounds remain in force.
- A positional token is a target name unless it starts with `@`, or is a known
  supported uppercase RR type after a target has been supplied. Lowercase `a`
  and `aaaa` remain literal names. An initial `A` with no named target is a name.
- Named `-d/--domain` entries are combined before positional names, named
  `-t/--type` entries before shorthand types, and named `-r/--resolver` entries
  before shorthand resolvers. This order is deterministic regardless of option
  placement. Normalization continues to validate values and enforce caps.
- A named target counts as a supplied name, so `-d example.com A` selects A.
  `-d A` explicitly selects a literal host named A. Unknown uppercase tokens are
  names; use `-t` when an unknown type should cause type validation to fail.
- Selected types apply to all CLI targets. Any CLI target list replaces config
  targets exactly as the existing `--domain` option did.
- `@resolver` works anywhere among the arguments. An empty `@` returns an input
  error. Endpoint normalization and supported transport syntax are unchanged.
- `--human` aliases `--format text` in the mutually exclusive output group.
  JSON remains the default. A name matching a command can use explicit `run`,
  for example `dnsprobe run plan`.
- Request child parsers use the public `parse_intermixed_args` API so options
  between positional tokens do not trigger argparse's usual `nargs='*'` trap.

## Inventory and test changes

The independent native collector found 58 existing CLI cases. Existing output,
error and live subprocess tests were modified. One new parameterized shorthand
feature group adds 11 semantic cases. Three new error rows and one human-alias
row extend existing groups. Final inventory is 73 cases. No test functions or
assertions were deleted to obtain green.

The live integration test now executes an implicit shorthand run against a
localhost UDP server and an observe command with intermixed positional/options;
it retains its JSON summary, artifacts, NDJSON, series and SIGINT assertions.

## Red, green and independent review

Delegated command, before implementation:

```text
.venv/bin/python -m pytest tests/test_cli.py -q --tb=short -k 'request_shorthand or explicit_text_errors or machine_errors'
12 failed, 14 passed, 47 deselected in 1.38s; exit 1
```

Eleven shorthand cases failed because positionals/short aliases were rejected.
The human alias case returned JSON instead of the requested text output.
After implementation the same command returned 26 passed, 47 deselected in
1.75s, exit 0. An independent rerun returned 26 passed, 47 deselected in 1.92s,
exit 0. Its stale/duplicate scan found no conflicting former text defaults,
duplicate new feature group, or input precedence regression.

Full local CLI suite:

```text
.venv/bin/python -m pytest tests/test_cli.py -q --tb=short
73 passed in 6.04s; exit 0
```

The integration listener was loopback-only on a random port. No public DNS
server was contacted by this validation.

## Revert proof

Only `cli.py` was temporarily replaced by its pre-feature baseline; new tests
were retained. The source was restored in a `finally` block.

```text
.venv/bin/python -m pytest tests/test_cli.py -q --tb=no -k 'request_shorthand or explicit_text_errors or machine_errors'
12 failed, 14 passed, 47 deselected in 1.22s
SHORTHAND_REVERT_PROOF_EXIT 1
```

After restoration, the targeted suite again returned 26 passed, 47 deselected
in 1.77s, exit 0. The DNS Probe help output was inspected and contains the new
examples, RR type ambiguity rules and explicit-command escape.

## Follow-up: lowercase explicit CLI types

A documentation audit found that the documented `-t mx` example still failed.
Only values supplied through `--type`/`-t` are now uppercased in CLI request
preparation. JSON request/config values remain strict, and lowercase bare
positional names are still names. This also supports `--type aaaa` when targets
come from JSON.

Two rows were added to the existing shorthand group and one lowercase-JSON row
to the existing invalid-request group. No new test function was introduced.
Independent RED before the fix:

```text
.venv/bin/python -m pytest tests/test_cli.py -q --tb=short -k request_shorthand
2 failed, 11 passed, 62 deselected in 0.66s; exit 1
```

The failures were the expected strict enum rejection of CLI `mx` and `aaaa`.
After the one-line CLI-only normalization:

```text
.venv/bin/python -m pytest tests/test_cli.py -q --tb=short -k 'request_shorthand or request_rejects'
34 passed, 42 deselected in 0.72s; exit 0
```

Reverting only `cli.py` to the pre-fix version, keeping all tests, reproduced
2 failed, 11 passed, 63 deselected in 0.57s (`LOWERCASE_TYPE_REVERT_PROOF_EXIT 1`).
After restoration, the shorthand and strict-input groups passed again:
34 passed, 42 deselected in 0.77s, exit 0. The final CLI inventory is 76 cases;
the parent task is responsible for the combined release-suite rerun.

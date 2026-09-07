# CLI JSON and input-boundary validation (2026-09-07)

Scope: `cli.py`, `config.py`, request schema and existing CLI contract suite.
The user requested an improved CLI UI, JSON output and additional testing.
The existing report serializer/human renderer was developed separately and is
called through its public interface.

## Changes and test inventory

The delegated native collector initially found 42 cases in `tests/test_cli.py`.
This change edits existing normalization, machine-error, offline-command and
live CLI test groups. It adds two feature groups: explicit text versus escaped
JSON diagnostics, and held-open stdin deadline handling. Parameterized cases
cover native pipes, the Windows branch using real OS reads, and an explicit
base-config budget. No existing tests or assertions were removed to make the
implementation green. The existing SIGINT portion is skipped after cleanup on
Windows because it requires a console process group; the preceding live JSON,
NDJSON, artifact and shared-budget checks still execute there.

Final inventory: 58 CLI cases, up from 42. This is two added test functions and
expanded parameter rows; no test functions were deleted or renamed.

Implemented contracts:

- New CLI defaults to compact JSON; run/observe/bench default to bounded summary.
  Plan/capabilities/schema/explain/compare retain full structured objects.
- `--json` and `--jsonl` are mutually exclusive aliases for `--format`.
- `--pretty` indents JSON by two spaces and works in JSON request output settings.
  Text and NDJSON combinations are rejected. Pretty printing can exceed the
  compact summary's 8192-byte size, with the existing 64-MiB output ceiling.
- `--format text` explicitly selects the human view, with full detail by default.
  `--agent` remains accepted. TTY state does not change output format.
- Compact and pretty JSON escape control/format characters, Unicode line
  separators and lone surrogates while preserving values after `json.loads`.
- A producer that keeps stdin open cannot bypass the deadline, including on
  Windows. Low-level reads run in a daemon thread, avoiding buffered stdin locks
  at interpreter shutdown. A valid loaded config budget also governs stdin.
- Help groups input/output/diagnostics and supplies examples and exit codes.
  Capabilities advertises the output contract. `--help`/`--version` retain normal
  human-readable CLI conventions.

## Observed red and green results

Formatting group, before production changes:

```text
.venv/bin/python -m pytest tests/test_cli.py -q --tb=short -k 'not live_cli and not series_preserves'
10 failed, 42 passed, 3 deselected in 1.32s; exit 1
```

The parent independently ran the same command: 10 failed, 42 passed,
3 deselected in 1.30s, exit 1. Failures were missing `output.pretty`, default
text error output, absent aliases and the schema command's old formatting.
After implementation the same group passed: 52 passed, 3 deselected in 2.37s,
exit 0.

Held-open stdin Windows regression:

```text
.venv/bin/python -m pytest tests/test_cli.py -q --tb=short -k stdin_deadline
1 failed, 1 passed, 55 deselected in 2.27s; exit 1
```

The actual Windows branch blocked beyond 2 seconds despite a 100-ms deadline.
Only OS selection was substituted; the subprocess pipe and `os.read` were real.
After the universal reader, the full CLI suite passed: 57 passed in 4.00s,
exit 0, including the localhost DNS process tests.

Pretty JSON hostile Unicode regression:

```text
.venv/bin/python -m pytest tests/test_cli.py -q --tb=short -k explicit_text_errors
2 failed, 55 deselected in 0.36s; exit 1
```

Pretty output raised `UnicodeEncodeError` and exited 1 for a lone surrogate.
After using the shared escaping helper: 2 passed, 55 deselected in 0.33s, exit 0.

Loaded config budget regression:

```text
.venv/bin/python -m pytest tests/test_cli.py -q --tb=short -k stdin_deadline
1 failed, 2 passed, 55 deselected in 2.44s; exit 1
```

A 100-ms config budget was ignored while stdin remained open. After correcting
budget precedence: 3 passed, 55 deselected in 0.57s, exit 0.

## Revert proofs

Only production changes were reverted temporarily; tests were preserved and
sources restored in `finally` blocks.

1. Restoring the CLI/config/schema baseline yielded 11 failed, 43 passed,
   3 deselected in 3.47s (`REVERT_PROOF_EXIT 1`), including the formatting and
   Windows deadline regressions. Restored sources: 56 offline passed in 2.81s.
2. Removing only the pretty escaping wrapper yielded 2 failed, 55 deselected
   in 0.34s (`PRETTY_REVERT_PROOF_EXIT 1`). Restored suite: 57 passed in 4.15s.
3. Removing only loaded-config budget precedence yielded 1 failed, 2 passed,
   55 deselected in 2.40s (`CONFIG_STDIN_REVERT_PROOF_EXIT 1`).

Final command after all restorations:

```text
.venv/bin/python -m pytest tests/test_cli.py -q --tb=short
58 passed in 4.46s; exit 0
```

Live tests used loopback listeners on random ports. No public DNS/network service
was required. These results were observed on macOS/Python 3.14; the Windows
branch test does not constitute a full native Windows platform certification.

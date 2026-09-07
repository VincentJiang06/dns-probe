# Source publication privacy: observed regression evidence

Date: 2026-09-08. Scope: `scripts/prepare_release.py` and its existing release
contract group. No files were staged, committed, published or sent to a server.
All Git operations in the tests were local, temporary fixture repositories.

## Contract

When the requested source root contains a `.git` directory or gitdir file, the
exporter obtains NUL-delimited tracked paths using explicit root-specific
`--git-dir` and `--work-tree` arguments. It clears inherited `GIT_*` routing/index
settings and bounds Git execution to ten seconds. Git failure refuses the export;
it never silently falls back to scanning all allowed extensions.

The tracked path set is intersected with the existing root-file, directory,
extension and hidden-path rules. Existing symlink rejection remains in force.
A tracked private key or unrelated root file is still excluded. Untracked JSON
under `docs/` or `examples/` is excluded. The exporter never copies `.git`.
Extracted source snapshots without `.git` retain the existing allowlist behavior.
File ordering, ZIP metadata, hashes and manifests remain deterministic.

`--require-license` checks the actual selected export contents before creating
any output directory or archive. A local but untracked LICENSE is insufficient.
A selected LICENSE remains in the archive and manifest.

Tracked source files can still contain sensitive text. This filename-level rule
complements the parent's content scan and archive validation; it does not replace
them or assert that any tracked content is automatically safe to publish.

## Inventory and changes

Native collector:

```text
.venv/bin/python -m pytest tests/test_release.py --collect-only -q
3 tests collected in 0.01s; exit 0
```

The existing parameterized group was extended with five cases: normal Git,
gitdir-file checkout, corrupt Git metadata, hostile inherited Git routing/index
environment and an untracked license. Existing clean snapshot and file/directory
symlink cases remain. No new test functions, deleted assertions or weakened
original exclusions. The Git cases deliberately track excluded junk as well as
public source to verify the intersection, not merely the tracked-file filter.

## Tracked-file regression

Before implementation:

```text
.venv/bin/python -m pytest tests/test_release.py -q --tb=short
3 failed, 3 passed in 0.13s; exit 1
```

The two valid checkout variants leaked `docs/network-report.json` and
`examples/credentials.json`; corrupt Git metadata silently exported instead of
raising an error. After the fix: 6 passed in 0.16s, exit 0. With the inherited
Git-environment regression added: 7 passed in 0.18s, exit 0.

Only the exporter was then temporarily reverted to its original version; the
tests were preserved and the fixed source restored in a `finally` block:

```text
.venv/bin/python -m pytest tests/test_release.py -q --tb=no
4 failed, 3 passed in 0.15s
TRACKED_EXPORT_REVERT_PROOF_EXIT 1
```

After restoration: 7 passed in 0.18s, exit 0.

## License regression

The tracked-file filter exposed an adjacent false assurance: `--require-license`
checked the local path, allowing an untracked license to pass even though it was
absent from the export. The existing contract group gained one row:

```text
.venv/bin/python -m pytest tests/test_release.py -q --tb=short -k untracked_license
1 failed, 7 deselected in 0.09s; exit 1
```

The observed failure was exit 0 plus an archive without LICENSE. After checking
selected contents before writes: 8 passed in 0.25s, exit 0. Reverting only this
fix reproduced 1 failed, 7 deselected in 0.05s
(`LICENSE_EXPORT_REVERT_PROOF_EXIT 1`). Restoring the fix yielded 8 passed in
0.21s, exit 0. Ordinary snapshot/Git fixtures also include a selected license and
verify its exact archive bytes and manifest hash.

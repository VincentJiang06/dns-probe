# Publication privacy audit

Date: 2026-09-08 (Asia/Shanghai). Scope: the public DNS Probe Git history, tracked source, source export, Python wheel and sdist. Local diagnostic folders are outside the publication scope.

## Independent checks

1. Inspect the tracked file list, sensitive filename patterns, private-key markers, credential-like strings, personal home paths, and public report examples. The examples use loopback peers and documentation addresses; discovery lists are empty and artifact paths are null.
2. Run Gitleaks 8.30.1 on complete reachable Git history with default rules, added personal-path rules, and redacted logs. The scanner binary is downloaded from its official release and checked against a pinned SHA-256 before execution.
3. Download the actual GitHub draft assets, verify wheel/sdist checksums and every source-manifest entry, then unpack and scan their contents. Check archive member paths and file types separately from text scanning.
4. Repeat the history and artifact scans after the publication guard changes. The release workflow runs both the history/source gate and the unpacked-asset gate before creating a draft.

The initial published source history and downloaded 1.2.0 draft assets had no detected credentials or personal home paths. This is a scan result, not proof that every possible sensitive value can be recognized.

## Scanner controls

A temporary, generated fake GitHub token was detected with exit code 1; removing it produced exit code 0. Separate temporary Unix and Windows home-path fixtures were also detected. These fixtures never entered Git.

A critical negative control showed that this scanner did **not** inspect a `.whl` file merely by enabling archive depth. The workflow therefore explicitly unpacks wheel, sdist and source ZIP before scanning. A clean result on unopened archives is not accepted as evidence.

## Changes made in 1.2.1

- Source export from a Git checkout intersects the publication allowlist with tracked paths. Untracked JSON/TXT files in `docs/`, `examples/` and other public directories cannot silently enter the release.
- Git errors stop the export. A source snapshot without Git metadata still uses the documented allowlist; it must be scanned before publication.
- The license check applies to the actual bytes selected for export, not merely a file on disk.
- Wheel and sdist members are validated independently. Private filename classes, local diagnostic paths, traversal/absolute paths, archive links and ambiguous duplicate names are rejected.
- Docker build context exclusions cover environment files, key/certificate bundles and local metadata directories.
- GitHub release jobs depend on the reusable privacy workflow and scan unpacked assets. No blanket credential ignore list is added.

Regression evidence is recorded in `tests/evidence-publication-privacy.md` and `tests/evidence-distribution-privacy.md`.

## Commit metadata

Credential scanning does not classify Git author email addresses as secrets. Author and committer metadata must be inspected separately. New maintainer commits use the account's GitHub noreply address; changing existing public commit IDs is a separate history operation. A later rewrite cannot promise deletion of copies, cached objects or forks that already exist.

## Reproduce locally

From a Git checkout, after reviewing and tracking the intended publication files:

```sh
gitleaks git . --log-opts='--all' --config .github/gitleaks.toml --ignore-gitleaks-allow --redact
uv run --no-sync python -m build --no-isolation
uv run --no-sync python scripts/check_distribution.py
uv run --no-sync python scripts/prepare_release.py --require-license --output release
```

Extract the current wheel, sdist and source ZIP into a fresh temporary directory, then run `gitleaks dir` against that directory with the same configuration. Never upload an unredacted scanner report or raw local network artifacts in a public issue.

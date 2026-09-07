# Contributing

Use Python 3.11 or newer. From a clone:

```sh
uv sync --locked
uv run --no-sync pytest -q
uv run --no-sync python -m build --no-isolation
```

Tests run offline or against loopback DNS/TLS/HTTPS/QUIC servers. Do not add tests that depend on public DNS answers, global packet loss, or a particular VPN. Platform-specific behavior needs platform fixtures and a clearly scoped test.

For behavior changes, update the relevant existing test first, reproduce the failure, implement the change, and run the affected tests. Run the complete suite before a pull request. Keep stdout a valid JSON value or an explicitly selected stream; log messages belong on stderr. Preserve exit codes, required coverage, deadlines, name-routing policy and evidence references.

Use semantic versioning. Changes to default output or exit semantics must be described in CHANGELOG.md. Additive report fields keep schema major version 1; incompatible field meanings need a new major contract. Regenerate examples after output changes.

Pull requests should explain the user-visible problem, resulting behavior, test command/results, and material limits. Do not upload local DNS reports, interface names, private names, resolver credentials, proxy configuration, or actual network logs as fixtures. Use `.example`, `.test`, `.invalid` and documentation IP ranges in synthetic fixtures.

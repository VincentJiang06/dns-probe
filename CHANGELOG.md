# Changelog

## 1.2.1 — 2026-09-08

- Restrict source exports from Git checkouts to tracked files and require the exported license to be tracked. Preserve clean source-snapshot exports.
- Validate wheel and sdist paths independently, including private file types, local reports, unsafe members and archive links.
- Gate publication on pinned, checksum-verified Gitleaks scans of reachable history, exported source and unpacked wheel/sdist assets. Extend Docker exclusions for local secrets.
- Record the repeated publication privacy audit and regression evidence.


## 1.2.0 — 2026-09-08

- Publish the MIT project on GitHub; macOS/Linux CI passes all 187 tests on Python 3.11/3.14. Windows remains experimental with 9 known CI failures.
- Name the product DNS Probe and Python distribution `dns-probe`; keep `dnsprobe` and `dnstk` commands. Adopt MIT licensing.
- Accept positional domains, uppercase record types after a name and `@resolver` shortcuts; add `-d/-t/-r` and `--human`. Preserve default JSON and named options.
- Show deduplicated DNS answers with owner, type, TTL and resolver path in bounded human output; retain full records in JSON.
- Accept lowercase explicit record flags without relaxing JSON schema validation. Report unsupported native record types as unverified with no retries; use applicable discovered wire paths for automatic MX/TXT checks.
- Rewrite English/Chinese README around everyday use, document the CLI grammar and mature-library reuse decisions, and update GitHub release materials.


## 1.1.0 — 2026-09-07

### Changed

- Modern CLI now defaults to compact JSON, including errors. Use `--format text` for human-readable output. Existing `--agent` integrations remain compatible.
- Human output shows bounded path and repeat-sample tables, stop reasons, incomplete checks and command previews.
- Terminal and JSON encoding escape control characters and Unicode line separators without discarding decoded evidence.

### Added

- `--json`, `--jsonl`, and JSON-only `--pretty`; grouped help and copyable usage examples.
- Held-open stdin deadline regression tests, including configuration-derived budgets and Windows behavior.
- Publication source allowlist, deterministic archive and manifest, clean-wheel smoke checks, contribution/security docs and GitHub templates.
- Official-source comparison with doggo, q, dnsx, iperf3, Trippy and netshoot.

## 1.0.0 — 2026-09-07

- Initial bounded diagnostic engine, six transport paths, JSON/NDJSON report contracts, advanced checks, shared observation sessions, artifacts and legacy adapters.
- Local macOS protocol and CLI verification; other platforms explicitly scoped in status documentation.

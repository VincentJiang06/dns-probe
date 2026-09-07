# Release DNS Probe

Product: **DNS Probe**. Repository slug: **dns-probe**. Python distribution: **dns-probe**. Console command: **dnsprobe**. License: **MIT**; the full text is in [LICENSE](../LICENSE) and is included in distribution metadata.

## Verify and export

```sh
uv sync --locked
uv run --no-sync pytest -q
uv run --no-sync python -m build --no-isolation
uv run --no-sync python scripts/check_distribution.py
uv run --no-sync python scripts/prepare_release.py --require-license --output release
```

`release/dns-probe-source.zip` contains publication source files. `release/source-manifest.json` lists each member's SHA-256 and the archive hash. Ordering and ZIP timestamps are deterministic. Symlinks are rejected. Local diagnostics, unrelated workspace material and private network reports are excluded.

The export command never stages, commits or uploads files. For a new public repository, use the reviewed export or the exact allowlisted files in its manifest. Do not add all files from a mixed diagnostics workspace. The wheel and sdist in `dist/` have a separate `SHA256SUMS`.

## GitHub project setup

The public repository is [VincentJiang06/dns-probe](https://github.com/VincentJiang06/dns-probe). The initial repository creation below is only needed for a new fork or a different destination.

Create the repository under the intended owner, select its visibility and push the reviewed `main` branch. Configure the GitHub description as:

> One-command DNS diagnostics with readable answers, bounded tests, and JSON evidence.

Suggested topics: `dns`, `dns-cli`, `network-diagnostics`, `dnssec`, `doh`, `dot`, `doq`, `python`, `cli`, `json`.

The source tree includes:

- English and Chinese README, CLI guide and synthetic examples.
- MIT license, contributing and security policies, changelog and migration guide.
- Bug/feature issue forms and a pull request template.
- Python 3.11/3.14 test matrix for macOS/Linux, with experimental Windows jobs.
- Dependency update configuration and a draft release workflow.

After the remote exists, add its real URL to project metadata, enable private vulnerability reporting, and inspect the actual CI results. Choose branch protection checks after the workflow has run; experimental Windows jobs do not certify Windows support. Do not add passing badges before their backing jobs exist.

For maintainers using GitHub CLI, from the reviewed Git repository, replace `OWNER` with the intended account or organization:

```sh
gh repo create OWNER/dns-probe --source . --remote origin --public --push \
  --description 'One-command DNS diagnostics with readable answers, bounded tests, and JSON evidence.'
```

That command creates a **public** repository and uploads committed source. Use `--private` instead when preparing privately. Repository creation is separate from preparing the local source archive.

## Draft release automation

Push a `v<package-version>` tag after reviewing platform results. `.github/workflows/release.yml` waits for the test workflow, checks the tag/package match, builds wheel/sdist, validates schemas and archive contents, writes checksums and requires LICENSE. It creates a **draft** GitHub Release with these artifacts, the source ZIP, manifest and changelog. Review the draft before publishing it.

No PyPI, Homebrew or container registry upload is configured. Those channels require control of the corresponding names and a separate publishing setup. A locally chosen Python package name is not a reservation on PyPI.

## Container use

```sh
docker build -t dns-probe:local .
docker run --rm dns-probe:local example.com --human
```

The image installs the same wheel and runs as a non-root user. Container diagnostics describe the container's network namespace. Docker Desktop does not automatically reproduce the host resolver path. See [validation](VALIDATION-1.2.md) for which builds and platforms were actually run.

## Compatibility

1.1 changed default output from text to JSON. 1.2 renames the distribution and adds shorthand syntax and `--human`; existing named flags and `--agent` remain available. The versioned JSON contract is still schema major 1. See [migration](../LEGACY_MIGRATION.md) for removing the earlier `dnsprobe-agent` installation before installing `dns-probe`.

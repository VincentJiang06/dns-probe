# 1.2.1 validation

Date: 2026-09-08 (Asia/Shanghai). This patch adds publication privacy gates; DNS protocol behavior is unchanged. See [the previous release validation](VALIDATION-1.2.md) for baseline protocol and platform evidence.

## Publication checks

The exporter regression group uses real temporary Git indexes, tracked and untracked JSON files, a Git-directory indirection file, a damaged Git directory, Git environment overrides, symlinks and license selection. The distribution group constructs real wheel ZIPs and source tarballs to exercise both archives independently.

The scanner was checked using temporary positive and clean controls. Fake credentials and personal home paths were detected. A direct compressed-wheel scan failed its positive control; this patch explicitly unpacks wheel/sdist/ZIP assets before scanning their contents.

Existing committed source, complete Git history and downloaded 1.2.0 draft artifacts had no detected credentials or personal home paths. The repeated scan procedure, scope, commit-metadata caveat and limitations are recorded in [the publication audit](PUBLICATION_AUDIT.md).

## Local results

- Python 3.14.6: **225 passed in 8.76s**.
- Python 3.11.15: **225 passed in 7.14s**.
- Independent exporter/distribution verification: **41 passed**; all newly exposed faults demonstrated RED, GREEN and revert-to-RED evidence.
- Gitleaks full-history, staged-change and unpacked-asset scans: no detected credentials or personal home paths. Scan reports are redacted and retained locally.
- Wheel/sdist builds and archive/schema validation passed. Source manifest entries are checked against the selected tracked files.

## Platform scope

macOS and Linux are the verified release platforms. Windows remains experimental: baseline 1.2.0 CI had nine failures in short-budget discovery and platform-specific checks. Docker runtime has not been validated in this session. These limitations are not hidden by the publication privacy checks.

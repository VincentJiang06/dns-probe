# Distribution publication guard evidence

Date: 2026-09-08. Scope: local archive-member validation; no network or publication.

- Native inventory initially found the three source-export tests and no wheel/sdist member-validation group.
- Added one parameterized group in `test_distribution.py`: 32 crafted ZIP/tar cases, including valid controls, case-insensitive private filenames, local diagnostic results, unsafe paths, symlinks/hardlinks, duplicate names, required license/script files and invalid schemas. Fixture file contents may legitimately discuss `.env` and certificate filenames.
- Independent RED, run by the parent: `.venv/bin/python -m pytest tests/test_distribution.py -q --tb=short` returned **26 failed, 6 passed**, exit 1. The existing checker accepted prohibited members, particularly in wheels.
- Initial GREEN after implementation: the same command returned **32 passed in 0.12s**, exit 0.
- Read-only `validate_archives` against the existing 1.2.0 wheel and sdist passed with all three schemas.
- Revert proof restored only the original `scripts/check_distribution.py`, kept tests, and ran `.venv/bin/python -m pytest tests/test_distribution.py -q --tb=no`: **26 failed, 6 passed in 0.11s**, exit 1. A `finally` block restored the fixed source.
- Restored GREEN: **32 passed in 0.08s**, exit 0.

The validator inspects both archives independently and does not extract members. Checksums are emitted only after both archives pass. This is a filename, archive-type and packaging-contract gate; it does not replace content scanning, Git-history scanning or review of the selected release assets. Existing source-export tests remain separate and unchanged.

Independent review found that an sdist without LICENSE still passed. Added one `sdist-missing_license` row to the same group. Independent RED returned **1 failed, 32 deselected in 0.07s**, exit 1. The two-line requirement produced **33 passed in 0.11s**. Reverting only this requirement made the new row fail again (**1 failed, 32 deselected**, exit 1); restoring it returned **33 passed**, exit 0. Both archive formats now require their packaged LICENSE file.

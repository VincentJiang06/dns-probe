"""Public source export is explicit, reproducible, and never follows symlinks."""
from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path
import zipfile

import pytest


@pytest.mark.parametrize("case", ["clean", "symlink_file", "symlink_directory"])
def test_source_release_contract(tmp_path, case):
    root = tmp_path / "checkout"
    root.mkdir()
    public = {
        "README.md": b"# DNS Probe\n",
        "pyproject.toml": b"[project]\nname = 'dns-probe'\nversion = '1.0.0'\n",
        "src/dnsprobe/__init__.py": b"__version__ = '1.0.0'\n",
        "src/dnsprobe/schemas/report.schema.json": b'{"type":"object"}\n',
        "tests/test_example.py": b"def test_example(): assert True\n",
        "docs/USAGE.md": b"Public usage notes\n",
        "examples/request.json": b'{"profile":"quick"}\n',
        ".github/workflows/tests.yml": b"name: tests\n",
    }
    private = {
        "dns_result.json": b'{"resolver":"private-network"}',
        "surge-tuning-20260907/original-active.conf": b"private network configuration",
        "unrelated-secret.txt": b"not part of the project",
        ".env": b"API_TOKEN=fixture-only",
        "src/dnsprobe/.DS_Store": b"local filesystem metadata",
        "src/dnsprobe/server.key": b"private test key",
        "src/dnsprobe/certificate.pem": b"local certificate",
        "tests/__pycache__/test_example.pyc": b"local bytecode",
        "docs/.artifacts/run.json": b"local diagnostics",
    }
    for name, content in {**public, **private}.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    if case != "clean":
        external = tmp_path / ("external.py" if case == "symlink_file" else "external_dir")
        if case == "symlink_file":
            external.write_text("external private content", encoding="utf-8")
        else:
            external.mkdir()
            (external / "private.py").write_text("external private content", encoding="utf-8")
        link = root / "src/dnsprobe" / ("linked.py" if case == "symlink_file" else "linked")
        try:
            link.symlink_to(external, target_is_directory=case == "symlink_directory")
        except OSError:
            pytest.skip("This platform does not permit creation of test symlinks")

    export_source = importlib.import_module("scripts.prepare_release").export_source
    if case != "clean":
        with pytest.raises(ValueError, match="(?i)symlink"):
            export_source(root, tmp_path / "export")
        return

    snapshot = {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}
    result = export_source(root, tmp_path / "one")
    repeated = export_source(root, tmp_path / "two")
    assert result["files"] == sorted(public)
    archive = Path(result["archive"])
    manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
    assert archive.read_bytes() == Path(repeated["archive"]).read_bytes(), "Export bytes must be reproducible"
    assert manifest["archive_sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert manifest["files"] == {name: hashlib.sha256(content).hexdigest() for name, content in public.items()}
    with zipfile.ZipFile(archive) as zipped:
        assert sorted(zipped.namelist()) == sorted(public)
        assert {name: zipped.read(name) for name in zipped.namelist()} == public
    assert snapshot == {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}

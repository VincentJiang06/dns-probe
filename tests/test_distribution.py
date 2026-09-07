"""Both public archive formats reject private and unsafe member paths."""
import hashlib
import io
import json
import stat
import tarfile
import zipfile

import jsonschema
import pytest

from scripts import check_distribution


@pytest.mark.parametrize("kind,case", [
    (kind, case) for kind in ("wheel", "sdist") for case in (
        "valid", "env", "git", "key", "p12", "pfx", "pem", "diagnostics",
        "result", "parent", "absolute", "backslash", "symlink", "duplicate", "missing_required",
    )
] + [("sdist", "hardlink"), ("sdist", "missing_license"), ("wheel", "invalid_schema")])
def test_distribution_publication_contract(tmp_path, monkeypatch, capsys, kind, case):
    (tmp_path / "dist").mkdir()
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "1.2.0"\n')
    monkeypatch.setattr(check_distribution, "__file__", str(tmp_path / "scripts/check_distribution.py"))
    wheel = tmp_path / "dist/dns_probe-1.2.0-py3-none-any.whl"
    source = tmp_path / "dist/dns_probe-1.2.0.tar.gz"
    # Source code may discuss secret filenames without itself containing secrets.
    content = b'example = ".env certificate.pem"\n'
    schemas = {f"dnsprobe/schemas/{name}.schema.json": b'{"type":"object"}'
               for name in ("event", "request", "report")}
    wheel_files = {"dnsprobe/__init__.py": content, **schemas,
                   "dns_probe-1.2.0.dist-info/licenses/LICENSE": b"MIT license fixture"}
    source_files = {"dns_probe-1.2.0/scripts/prepare_release.py": content,
                    "dns_probe-1.2.0/LICENSE": b"MIT license fixture"}
    prefix = "dnsprobe" if kind == "wheel" else "dns_probe-1.2.0/docs"
    paths = {"env": f"{prefix}/.EnV.production", "git": f"{prefix}/.GiT/config",
             "key": f"{prefix}/secret.KEY", "p12": f"{prefix}/secret.P12", "pfx": f"{prefix}/secret.pfx",
             "pem": f"{prefix}/secret.PEM", "diagnostics": f"{prefix}/Surge-Tuning-local/routes.json",
             "result": f"{prefix}/DNS_RESULT_HK.JSON", "parent": f"{prefix}/../private.txt",
             "absolute": f"/{prefix}/private.txt", "backslash": f"{prefix}\\private.txt",
             "symlink": f"{prefix}/linked.py", "hardlink": f"{prefix}/linked.py"}
    target = wheel_files if kind == "wheel" else source_files
    if case == "missing_required":
        del target["dns_probe-1.2.0.dist-info/licenses/LICENSE" if kind == "wheel"
                   else "dns_probe-1.2.0/scripts/prepare_release.py"]
    elif case == "missing_license":
        del source_files["dns_probe-1.2.0/LICENSE"]
    elif case == "invalid_schema":
        wheel_files["dnsprobe/schemas/report.schema.json"] = b'{"type":"invalid-schema-type"}'
    elif case in paths:
        target[paths[case]] = content
    if case == "duplicate":
        target[f"{prefix}/SAME.py"] = content
        target[f"{prefix}/same.py"] = content

    with zipfile.ZipFile(wheel, "w") as archive:
        for name, data in wheel_files.items():
            member = zipfile.ZipInfo(name)
            member.create_system = 3
            member.external_attr = ((stat.S_IFLNK if kind == "wheel" and case == "symlink"
                                      and name == paths[case] else stat.S_IFREG) | 0o644) << 16
            archive.writestr(member, data)
    with tarfile.open(source, "w:gz") as archive:
        for name, data in source_files.items():
            member = tarfile.TarInfo(name)
            if kind == "sdist" and case in ("symlink", "hardlink") and name == paths[case]:
                member.type = tarfile.SYMTYPE if case == "symlink" else tarfile.LNKTYPE
                member.linkname = "../../private.txt"
                archive.addfile(member)
            else:
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))

    if case != "valid":
        with pytest.raises((ValueError, AssertionError, jsonschema.exceptions.SchemaError)):
            check_distribution.main()
        assert not (tmp_path / "dist/SHA256SUMS").exists(), "No success checksums after rejected validation"
    else:
        check_distribution.main()
        result = json.loads(capsys.readouterr().out)
        assert result["status"] == "passed" and result["schemas"] == 3
        assert result["artifacts"] == {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (wheel, source)}

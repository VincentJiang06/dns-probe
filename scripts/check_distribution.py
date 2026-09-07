"""Verify release metadata, archive scope, checksums and JSON schemas offline."""
from pathlib import Path
import hashlib
import json
import sys
import tarfile
import tomllib
import zipfile


def main():
    root=Path(__file__).resolve().parents[1]
    version=tomllib.loads((root/'pyproject.toml').read_text())['project']['version']
    wheel=root/'dist'/f'dns_probe-{version}-py3-none-any.whl'
    source=root/'dist'/f'dns_probe-{version}.tar.gz'
    with zipfile.ZipFile(wheel) as archive:
        names=archive.namelist()
        assert len([p for p in names if p.endswith('.schema.json')])==3
        assert all(p.startswith('dnsprobe/') or '.dist-info/' in p for p in names)
        for path in names:
            if path.endswith('.schema.json'):
                import jsonschema
                jsonschema.Draft202012Validator.check_schema(json.loads(archive.read(path)))
    with tarfile.open(source) as archive:
        names=archive.getnames()
        assert any(p.endswith('/scripts/prepare_release.py') for p in names)
    forbidden=('surge-tuning-', 'diagnostics-', '.artifacts/', '.venv/', 'dns_result.json', 'dns_lab_result.json')
    assert not any(value in name for name in names for value in forbidden)
    values={path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in (wheel,source)}
    (root/'dist'/'SHA256SUMS').write_text(''.join(f'{digest}  {name}\n' for name,digest in values.items()))
    print(json.dumps({'version':version,'artifacts':values,'schemas':3,'status':'passed'},separators=(',',':')))


if __name__=='__main__':
    main()

"""Verify release metadata, archive scope, checksums and JSON schemas offline."""
from pathlib import Path
import hashlib
import json
import re
import stat
import tarfile
import tomllib
import zipfile


def _public_parts(name):
    """Reject ambiguous paths before inspecting members; never extract an archive."""
    if not name or name.startswith(('/', '\\')) or '\\' in name or re.match(r'^[A-Za-z]:', name):
        raise ValueError(f'Unsafe archive member: {name!r}')
    parts = name.removesuffix('/').split('/')
    if any(part in ('', '.', '..') or ':' in part or any(ord(c) < 32 or ord(c) == 127 for c in part)
           for part in parts):
        raise ValueError(f'Unsafe archive member: {name!r}')
    hidden = {'.git', '.artifacts', '.venv', '.uv-cache', '.pytest_cache', '__pycache__', '.ds_store'}
    private_extensions = ('.pem', '.key', '.p12', '.pfx', '.p8')
    private_names = {'id_rsa', 'id_ed25519', 'id_dsa', 'id_ecdsa'}
    for part in parts:
        lower = part.casefold()
        if (lower in hidden or lower == '.env' or lower.startswith('.env.')
                or lower in private_names or lower.endswith(private_extensions)
                or lower.startswith(('surge-tuning-', 'diagnostics-'))
                or (lower.startswith(('dns_result', 'hk_real_')) and lower.endswith('.json'))
                or lower == 'dns_lab_result.json'):
            raise ValueError(f'Private or local archive member: {name!r}')
    return parts


def validate_archives(wheel, source, version):
    """Validate each archive independently, including type, scope and required files."""
    schemas = {f'dnsprobe/schemas/{kind}.schema.json' for kind in ('event', 'request', 'report')}
    metadata = f'dns_probe-{version}.dist-info'
    with zipfile.ZipFile(wheel) as archive:
        seen, files = set(), set()
        for member in archive.infolist():
            parts = _public_parts(member.filename)
            canonical = '/'.join(parts).casefold()
            if canonical in seen:
                raise ValueError(f'Duplicate archive member: {member.filename!r}')
            seen.add(canonical)
            mode = stat.S_IFMT(member.external_attr >> 16)
            if mode not in (0, stat.S_IFREG, stat.S_IFDIR) or (mode == stat.S_IFDIR and not member.is_dir()):
                raise ValueError(f'Unsupported archive member type: {member.filename!r}')
            if parts[0] not in ('dnsprobe', metadata) or (len(parts) == 1 and not member.is_dir()):
                raise ValueError(f'Unexpected wheel member: {member.filename!r}')
            if not member.is_dir():
                files.add(member.filename)
        if {name for name in files if name.endswith('.schema.json')} != schemas:
            raise ValueError('Wheel must contain the three public JSON schemas')
        if not files.intersection({f'{metadata}/licenses/LICENSE', f'{metadata}/LICENSE'}):
            raise ValueError('Wheel is missing LICENSE')
        import jsonschema
        for name in sorted(schemas):
            jsonschema.Draft202012Validator.check_schema(json.loads(archive.read(name)))
    with tarfile.open(source) as archive:
        seen, files = set(), set()
        for member in archive.getmembers():
            parts = _public_parts(member.name)
            canonical = '/'.join(parts).casefold()
            if canonical in seen:
                raise ValueError(f'Duplicate archive member: {member.name!r}')
            seen.add(canonical)
            if not (member.isfile() or member.isdir()):
                raise ValueError(f'Unsupported archive member type: {member.name!r}')
            if parts[0] != f'dns_probe-{version}':
                raise ValueError(f'Unexpected source archive member: {member.name!r}')
            if member.isfile():
                files.add(member.name)
        if f'dns_probe-{version}/scripts/prepare_release.py' not in files:
            raise ValueError('Source archive is missing scripts/prepare_release.py')
        if f'dns_probe-{version}/LICENSE' not in files:
            raise ValueError('Source archive is missing LICENSE')
    return {'schemas': len(schemas)}


def main():
    root=Path(__file__).resolve().parents[1]
    version=tomllib.loads((root/'pyproject.toml').read_text())['project']['version']
    wheel=root/'dist'/f'dns_probe-{version}-py3-none-any.whl'
    source=root/'dist'/f'dns_probe-{version}.tar.gz'
    validation=validate_archives(wheel,source,version)
    values={path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in (wheel,source)}
    (root/'dist'/'SHA256SUMS').write_text(''.join(f'{digest}  {name}\n' for name,digest in values.items()))
    print(json.dumps({'version':version,'artifacts':values,**validation,'status':'passed'},separators=(',',':')))


if __name__=='__main__':
    main()

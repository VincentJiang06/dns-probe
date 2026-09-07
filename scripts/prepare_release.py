"""Export a reviewable source snapshot without local network evidence.

This module never publishes, stages files, or contacts a server.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import zipfile

ROOT_FILES = frozenset('README.md README.zh-CN.md LICENSE NOTICE CHANGELOG.md CONTRIBUTING.md SECURITY.md LEGACY_MIGRATION.md pyproject.toml uv.lock .gitignore .gitattributes .dockerignore Dockerfile dnstk.py dns_core.py dns_bench.py dns_bench_hk.py dns_lab.py'.split())
DIRECTORIES = ('src', 'tests', 'docs', 'examples', 'scripts', '.github')
SUFFIXES = frozenset(('.py', '.json', '.md', '.yml', '.yaml', '.toml', '.svg', '.txt'))


def _source_files(root):
    files = []
    for name in sorted(ROOT_FILES):
        path = root / name
        if path.is_symlink():
            raise ValueError(f'Symlinks cannot be published: {name}')
        if path.is_file(): files.append(path)
    for name in DIRECTORIES:
        directory = root / name
        if directory.is_symlink(): raise ValueError(f'Symlinks cannot be published: {name}')
        if not directory.is_dir(): continue
        for path in directory.rglob('*'):
            relative = path.relative_to(root)
            if path.is_symlink(): raise ValueError(f'Symlinks cannot be published: {relative}')
            if any(part.startswith('.') or part == '__pycache__' for part in relative.parts[1:]): continue
            if path.is_file() and path.suffix in SUFFIXES:
                files.append(path)
    return sorted(files, key=lambda p:p.relative_to(root).as_posix())


def export_source(root: Path, output: Path) -> dict:
    root, output = Path(root).resolve(), Path(output).resolve()
    if not root.is_dir(): raise ValueError('Source directory does not exist')
    if output == root or any(output == root / directory or (root / directory) in output.parents for directory in DIRECTORIES):
        raise ValueError('Output cannot be the source root or a published source directory')
    files = _source_files(root)
    if not files: raise ValueError('No publishable source files found')
    # Collect and hash the exact bytes before any writes; symlink rejection is atomic.
    contents = {p.relative_to(root).as_posix():p.read_bytes() for p in files}
    output.mkdir(parents=True,exist_ok=True)
    archive = output / 'dns-probe-source.zip'
    temporary = output / '.source.zip.tmp'
    try:
        with zipfile.ZipFile(temporary,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as bundle:
            for name,data in contents.items():
                entry=zipfile.ZipInfo(name,date_time=(2026,1,1,0,0,0))
                entry.create_system=3
                entry.external_attr=0o100644<<16
                entry.compress_type=zipfile.ZIP_DEFLATED
                bundle.writestr(entry,data)
        temporary.replace(archive)
    finally:
        temporary.unlink(missing_ok=True)
    manifest = output / 'source-manifest.json'
    values={'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),
            'files':{name:hashlib.sha256(data).hexdigest() for name,data in contents.items()}}
    manifest.write_text(json.dumps(values,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    return {'archive':str(archive),'manifest':str(manifest),'files':list(contents)}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output',type=Path,default=Path('release'))
    parser.add_argument('--require-license',action='store_true',help='Refuse a public release before a license is selected')
    args=parser.parse_args(argv)
    try:
        if args.require_license and not (args.root/'LICENSE').is_file():
            raise ValueError('Select a license and add LICENSE before public release')
        print(json.dumps(export_source(args.root,args.output),separators=(',',':')))
        return 0
    except (OSError,ValueError) as exc:
        print(json.dumps({'error':str(exc)}),file=sys.stderr)
        return 2


if __name__=='__main__':
    raise SystemExit(main())

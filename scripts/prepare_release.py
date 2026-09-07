"""Export a reviewable source snapshot without local network evidence.

Git checkouts export only tracked files that also match the source allowlist.
Extracted snapshots without Git metadata use the same allowlist on their own.
This module never publishes, stages files, or contacts a server.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT_FILES = frozenset('README.md README.zh-CN.md LICENSE NOTICE CHANGELOG.md CONTRIBUTING.md SECURITY.md LEGACY_MIGRATION.md pyproject.toml uv.lock .gitignore .gitattributes .dockerignore Dockerfile dnstk.py dns_core.py dns_bench.py dns_bench_hk.py dns_lab.py'.split())
DIRECTORIES = ('src', 'tests', 'docs', 'examples', 'scripts', '.github')
SUFFIXES = frozenset(('.py', '.json', '.md', '.yml', '.yaml', '.toml', '.svg', '.txt'))


def _tracked_files(root):
    metadata = root / '.git'
    if not metadata.exists() and not metadata.is_symlink():
        return None  # Extracted source distributions retain the source allowlist.
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    try:
        result = subprocess.run(
            ['git', f'--git-dir={metadata}', f'--work-tree={root}', 'ls-files', '-z'],
            cwd=root, env=environment, check=True, capture_output=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError('Git tracked-file discovery failed; refusing source export') from exc
    return {os.fsdecode(name) for name in result.stdout.split(b'\0') if name}


def _source_files(root):
    tracked = _tracked_files(root)
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
    if tracked is not None:
        files = [path for path in files if path.relative_to(root).as_posix() in tracked]
    return sorted(files, key=lambda p:p.relative_to(root).as_posix())


def export_source(root: Path, output: Path, *, require_license=False) -> dict:
    root, output = Path(root).resolve(), Path(output).resolve()
    if not root.is_dir(): raise ValueError('Source directory does not exist')
    if output == root or any(output == root / directory or (root / directory) in output.parents for directory in DIRECTORIES):
        raise ValueError('Output cannot be the source root or a published source directory')
    files = _source_files(root)
    if not files: raise ValueError('No publishable source files found')
    # Collect and hash the exact bytes before any writes; symlink rejection is atomic.
    contents = {p.relative_to(root).as_posix():p.read_bytes() for p in files}
    if require_license and 'LICENSE' not in contents:
        raise ValueError('Select a license and include LICENSE in the publishable source files before public release')
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
        print(json.dumps(export_source(args.root,args.output,require_license=args.require_license),separators=(',',':')))
        return 0
    except (OSError,ValueError) as exc:
        print(json.dumps({'error':str(exc)}),file=sys.stderr)
        return 2


if __name__=='__main__':
    raise SystemExit(main())

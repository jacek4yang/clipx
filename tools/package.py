"""CI-only packaging helper; the shipped executable has no Python dependency."""
import hashlib
import pathlib
import sys
import tarfile
import zipfile

target = sys.argv[1]
windows = 'windows' in target
binary = 'clipx.exe' if windows else 'clipx'
files = [(pathlib.Path('target/release') / binary, binary)]
files += [(pathlib.Path(p), p) for p in ['README.md', 'README.zh-CN.md', 'SECURITY.md', 'LICENSE', 'docs/PROTOCOL.md']]
out = pathlib.Path('dist')
out.mkdir(exist_ok=True)
archive = out / ('clipx-' + target + ('.zip' if windows else '.tar.gz'))
if windows:
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
        for path, name in files:
            z.write(path, name)
else:
    with tarfile.open(archive, 'w:gz') as z:
        for path, name in files:
            z.add(path, arcname=name)
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
archive.with_suffix(archive.suffix + '.sha256').write_text(f'{digest}  {archive.name}\n', encoding='utf-8')

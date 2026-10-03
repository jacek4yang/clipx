#!/usr/bin/env python3
"""Collect the exact locked dependency copyright/license notices for binary distribution."""
import json
import hashlib
import pathlib
import subprocess

root = pathlib.Path(__file__).resolve().parents[1]
packages = {}
for target in ['x86_64-unknown-linux-gnu','x86_64-unknown-linux-musl','x86_64-pc-windows-msvc']:
    meta = json.loads(subprocess.check_output(['cargo', 'metadata', '--locked', '--all-features', '--format-version', '1', '--filter-platform',target], cwd=root))
    nodes = {n['id']: n for n in meta['resolve']['nodes']}
    pending = [meta['resolve']['root']]
    seen = set()
    while pending:
        node = pending.pop()
        if node in seen:
            continue
        seen.add(node)
        for dependency in nodes[node]['deps']:
            if any(k['kind'] != 'dev' for k in dependency['dep_kinds']):
                pending.append(dependency['pkg'])
    packages.update({p['id']:p for p in meta['packages'] if p['id'] in seen})
out = ['# Third-party dependency notices\n\nGenerated from Cargo.lock for shipped Linux/Windows targets, including build dependencies.\nOriginal copyright and license texts follow; this does not relicense dependencies.\n']
missing = []
texts = {}
for package in sorted(packages.values(), key=lambda p: (p['name'], p['version'])):
    if package['name'] == 'clipx':
        continue
    directory = pathlib.Path(package['manifest_path']).parent
    candidates = [p for p in directory.iterdir() if p.is_file() and p.name.lower().startswith(('license', 'copying', 'notice', 'unlicense'))]
    if package.get('license_file'):
        candidates.append(directory / package['license_file'])
    fallback = root / 'docs' / 'licenses' / (package['name'] + '.txt')
    if not candidates and fallback.exists():
        candidates.append(fallback)
    candidates = sorted(set(candidates))
    out.append(f"\n## {package['name']} {package['version']}\n\nLicense: {package.get('license') or 'see supplied license'}\nRepository: {package.get('repository') or 'see crates.io metadata'}\n")
    if not candidates:
        missing.append(package['name'])
    for path in candidates:
        text = path.read_text(encoding='utf-8', errors='replace').strip()
        digest = hashlib.sha256(text.encode()).hexdigest()
        if digest not in texts:
            texts[digest] = (len(texts) + 1, text)
        number = texts[digest][0]
        out.append(f'License file {path.name}: text L{number} below.\n')
out.append('\n# Full license texts (identical texts shared by multiple crates are printed once)\n')
for number, text in texts.values():
    out.append(f'\n## L{number}\n\n{text}\n')
(root / 'THIRD_PARTY_NOTICES.md').write_text('\n'.join(out), encoding='utf-8')
print('Packages:', len(packages) - 1, 'Missing top-level license files:', missing)
if missing:
    raise SystemExit(1)

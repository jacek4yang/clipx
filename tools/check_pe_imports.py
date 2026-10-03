"""Fail packaging if a Windows executable needs a redistributable/non-system DLL."""
import pathlib
import struct
import sys

b = pathlib.Path(sys.argv[1]).read_bytes()
def u16(p): return struct.unpack_from('<H', b, p)[0]
def u32(p): return struct.unpack_from('<I', b, p)[0]
assert b[:2] == b'MZ'
pe = u32(0x3c)
assert b[pe:pe + 4] == b'PE\0\0'
coff = pe + 4
optional = coff + 20
magic = u16(optional)
assert magic in (0x10b, 0x20b)
directories = optional + (112 if magic == 0x20b else 96)
image_base = struct.unpack_from('<Q' if magic == 0x20b else '<I', b, optional + (24 if magic == 0x20b else 28))[0]
sections = coff + 20 + u16(coff + 16)
regions = []
for i in range(u16(coff + 2)):
    off = sections + i * 40
    regions.append((u32(off + 12), max(u32(off + 8), u32(off + 16)), u32(off + 20)))
def position(rva):
    for base, size, raw in regions:
        if base <= rva < base + size:
            return raw + rva - base
    if rva < u32(optional + 60):
        return rva
    raise ValueError(f'Unmapped PE RVA: {rva:x}')
def string(rva):
    off = position(rva)
    end = b.index(b'\0', off, off + 256)
    return b[off:end].decode('ascii').lower()
imports = set()
rva = u32(directories + 8)
if rva:
    off = position(rva)
    while any(b[off:off + 20]):
        imports.add(string(u32(off + 12)))
        off += 20
rva = u32(directories + 13 * 8)
if rva:
    off = position(rva)
    while any(b[off:off + 32]):
        name = u32(off + 4)
        if not u32(off) & 1:
            name -= image_base
        imports.add(string(name))
        off += 32
system = {
    'kernel32.dll', 'kernelbase.dll', 'ntdll.dll', 'user32.dll', 'gdi32.dll',
    'advapi32.dll', 'shell32.dll', 'ole32.dll', 'oleaut32.dll', 'ws2_32.dll',
    'bcrypt.dll', 'bcryptprimitives.dll', 'crypt32.dll', 'secur32.dll',
    'normaliz.dll', 'iphlpapi.dll', 'shlwapi.dll', 'dbghelp.dll', 'ucrtbase.dll',
    'runtimeobject.dll', 'propsys.dll', 'imm32.dll', 'version.dll', 'winmm.dll',
    'mswsock.dll', 'dnsapi.dll', 'psapi.dll', 'userenv.dll', 'cfgmgr32.dll',
    'combase.dll', 'comdlg32.dll', 'comctl32.dll', 'wintrust.dll',
}
bad = sorted(n for n in imports if n not in system and not n.startswith(('api-ms-win-', 'ext-ms-win-')))
print('PE imports:', ', '.join(sorted(imports)))
if bad:
    raise SystemExit('Unexpected runtime DLL dependencies: ' + ', '.join(bad))
print('PASS: only Windows system DLL imports; no separate VC runtime or application DLL required')

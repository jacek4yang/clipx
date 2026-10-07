"""CI-only audit: Intel Mach-O, bounded deployment target, system dylibs only."""
import pathlib
import struct
import sys

DYLIB_COMMANDS = {0xC, 0x80000018, 0x8000001F, 0x20, 0x80000023}
SYSTEM_PREFIXES = ("/usr/lib/", "/System/Library/")


def packed_version(text):
    fields = [int(part) for part in text.split(".")]
    if not 1 <= len(fields) <= 3:
        raise ValueError("invalid macOS version")
    fields += [0] * (3 - len(fields))
    if not (0 <= fields[0] <= 65535 and all(0 <= p <= 255 for p in fields[1:])):
        raise ValueError("invalid macOS version")
    return (fields[0] << 16) | (fields[1] << 8) | fields[2]


def audit(data, maximum):
    if len(data) < 32:
        raise ValueError("truncated Mach-O header")
    magic, cpu, _, kind, count, size, _, _ = struct.unpack_from("<8I", data)
    if magic != 0xFEEDFACF or cpu != 0x01000007 or kind != 2:
        raise ValueError("expected a thin x86_64 Mach-O executable")
    end = 32 + size
    if end > len(data) or count > size // 8:
        raise ValueError("invalid load-command bounds")
    pos = 32
    versions = []
    libraries = []
    for _ in range(count):
        if pos + 8 > end:
            raise ValueError("truncated load command")
        command, length = struct.unpack_from("<2I", data, pos)
        if length < 8 or length % 8 or pos + length > end:
            raise ValueError("invalid load-command length")
        if command == 0x24:  # LC_VERSION_MIN_MACOSX
            if length < 16:
                raise ValueError("truncated deployment command")
            versions.append(struct.unpack_from("<I", data, pos + 8)[0])
        elif command == 0x32:  # LC_BUILD_VERSION
            if length < 24:
                raise ValueError("truncated build-version command")
            platform, version = struct.unpack_from("<2I", data, pos + 8)
            if platform != 1:
                raise ValueError("not a macOS deployment target")
            versions.append(version)
        elif command in DYLIB_COMMANDS:
            if length < 24:
                raise ValueError("truncated dylib command")
            offset = struct.unpack_from("<I", data, pos + 8)[0]
            if not 24 <= offset < length:
                raise ValueError("invalid dylib name offset")
            name = data[pos + offset:pos + length].split(b"\0", 1)
            if len(name) != 2:
                raise ValueError("unterminated dylib name")
            name = name[0].decode("utf-8")
            if not name.startswith(SYSTEM_PREFIXES) or ".." in name.split("/"):
                raise ValueError(f"non-system runtime dependency: {name}")
            libraries.append(name)
        elif command == 0x8000001C:  # LC_RPATH
            raise ValueError("unexpected runtime search path")
        pos += length
    if pos != end or not versions or not libraries:
        raise ValueError("missing or inconsistent Mach-O metadata")
    if any(version > packed_version(maximum) for version in versions):
        raise ValueError(f"binary requires macOS newer than {maximum}")
    return libraries


if __name__ == "__main__":
    libraries = audit(pathlib.Path(sys.argv[1]).read_bytes(), sys.argv[2])
    print("Intel macOS executable verified; system libraries only:")
    print("\n".join(libraries))

import struct
import unittest
from check_macho import audit, packed_version


def binary(name="/usr/lib/libSystem.B.dylib", version="10.13", cpu=0x01000007):
    raw = name.encode() + b"\0"
    length = (24 + len(raw) + 7) & ~7
    dylib = struct.pack("<6I", 0xC, length, 24, 0, 0, 0) + raw
    dylib += bytes(length - len(dylib))
    commands = struct.pack("<6I", 0x32, 24, 1, packed_version(version), 0, 0) + dylib
    return struct.pack("<8I", 0xFEEDFACF, cpu, 3, 2, 2, len(commands), 0, 0) + commands


class MachOAudit(unittest.TestCase):
    def test_system_only_intel_passes(self):
        self.assertEqual(audit(binary(), "10.13"), ["/usr/lib/libSystem.B.dylib"])

    def test_homebrew_and_rpath_dependencies_fail(self):
        for name in ("/opt/homebrew/lib/a.dylib", "/usr/local/lib/a.dylib", "@rpath/a.dylib", "/usr/lib/../../tmp/a.dylib"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                audit(binary(name=name), "10.13")

    def test_wrong_architecture_and_newer_os_fail(self):
        for data in (binary(cpu=0x0100000C), binary(version="11.0")):
            with self.assertRaises(ValueError):
                audit(data, "10.13")

    def test_all_truncated_inputs_fail(self):
        data = binary()
        for n in range(len(data)):
            with self.subTest(n=n), self.assertRaises(ValueError):
                audit(data[:n], "10.13")

    def test_zero_command_length_fails(self):
        data = bytearray(binary())
        struct.pack_into("<I", data, 36, 0)
        with self.assertRaises(ValueError):
            audit(data, "10.13")


if __name__ == "__main__":
    unittest.main()

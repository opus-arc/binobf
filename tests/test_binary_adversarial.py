"""Independent malformed-container and preservation tests.

The fixtures are deliberately tiny, self-contained object containers.  These
tests exercise file-format boundaries rather than mirroring parser internals.
"""
import struct
import unittest

from binobf.binary import BinaryError, parse


CODE = struct.pack("<II", 0x0B010000, 0xD65F03C0)  # add w0,w0,w1; ret


def align8(value):
    return (value + 7) & ~7


def elf_object(extra_symbols=()):
    names = b"\0.text\0.symtab\0.strtab\0.shstrtab\0"
    strings = bytearray(b"\0demo\0")
    symbols = [bytes(24), struct.pack("<IBBHQQ", 1, 0x12, 0, 1, 0, len(CODE))]
    for name, info, section, value, size in extra_symbols:
        name_offset = len(strings)
        strings.extend(name.encode("ascii") + b"\0")
        symbols.append(struct.pack("<IBBHQQ", name_offset, info, 0, section, value, size))
    textoff = 64
    symoff = align8(textoff + len(CODE))
    symbytes = b"".join(symbols)
    stroff = symoff + len(symbytes)
    nameoff = stroff + len(strings)
    shoff = align8(nameoff + len(names))
    data = bytearray(shoff + 5 * 64)
    data[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", data, 16,
                     1, 183, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 5, 4)
    data[textoff:textoff + len(CODE)] = CODE
    data[symoff:symoff + len(symbytes)] = symbytes
    data[stroff:stroff + len(strings)] = strings
    data[nameoff:nameoff + len(names)] = names
    sections = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (1, 1, 6, 0, textoff, len(CODE), 0, 0, 4, 0),
        (7, 2, 0, 0, symoff, len(symbytes), 3, 1, 8, 24),
        (15, 3, 0, 0, stroff, len(strings), 0, 0, 1, 0),
        (23, 3, 0, 0, nameoff, len(names), 0, 0, 1, 0),
    ]
    for index, section in enumerate(sections):
        struct.pack_into("<IIQQQQIIQQ", data, shoff + index * 64, *section)
    return data, dict(shoff=shoff, symoff=symoff, stroff=stroff,
                      nameoff=nameoff, textoff=textoff)


def macho_object(*, data_in_code=False, relocation=False):
    command_size = 152 + 24 + (16 if data_in_code else 0)
    textoff = 32 + command_size
    symoff = align8(textoff + len(CODE))
    stroff = symoff + 16
    strings = b"\0_demo\0"
    extraoff = align8(stroff + len(strings))
    extrasize = 8 if (data_in_code or relocation) else 0
    data = bytearray(extraoff + extrasize)
    struct.pack_into("<8I", data, 0, 0xFEEDFACF, 0x0100000C, 0,
                     1, 3 if data_in_code else 2, command_size, 0x2000, 0)
    struct.pack_into("<II16sQQQQiiII", data, 32, 0x19, 152,
                     b"__TEXT", 0, len(CODE), textoff, len(CODE), 7, 5, 1, 0)
    section = 104
    struct.pack_into("<16s16sQQIIIIIIII", data, section,
                     b"__text", b"__TEXT", 0, len(CODE), textoff, 2,
                     extraoff if relocation else 0, 1 if relocation else 0,
                     0x80000400, 0, 0, 0)
    symcommand = 184
    struct.pack_into("<6I", data, symcommand, 2, 24, symoff, 1, stroff, len(strings))
    if data_in_code:
        struct.pack_into("<4I", data, 208, 0x29, 16, extraoff, 8)
        struct.pack_into("<IHH", data, extraoff, textoff, 4, 1)
    data[textoff:textoff + len(CODE)] = CODE
    struct.pack_into("<IBBHQ", data, symoff, 1, 0x0F, 1, 0, 0)
    data[stroff:stroff + len(strings)] = strings
    return data, dict(section=section, symcommand=symcommand,
                      textoff=textoff, symoff=symoff, stroff=stroff)


class BinaryAdversarialTests(unittest.TestCase):
    def assert_not_selectable(self, data):
        with self.assertRaises(BinaryError):
            parse(data).select(["demo"])

    def test_minimal_objects_have_exact_code_and_export(self):
        for builder, expected_name in ((elf_object, "demo"), (macho_object, "_demo")):
            with self.subTest(format=expected_name):
                data, _ = builder()
                image = parse(data)
                functions = image.virtualizable()
                self.assertEqual(len(functions), 1)
                self.assertEqual(functions[0].name, expected_name)
                self.assertEqual(functions[0].code, CODE)
                self.assertEqual(image.select(["demo"]), functions)

    def test_truncated_inputs_raise_domain_error(self):
        for builder in (elf_object, macho_object):
            data, _ = builder()
            for size in range(len(data)):
                # Trailing alignment zeros are not required by either format.
                if not any(data[size:]):
                    continue
                with self.subTest(format=builder.__name__, size=size):
                    with self.assertRaises(BinaryError):
                        parse(data[:size])

    def test_unknown_fat_and_big_endian_formats_are_rejected(self):
        for magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                      b"\xfe\xed\xfa\xcf", b"MZ\0\0", b"\x7f???"):
            with self.subTest(magic=magic):
                with self.assertRaises(BinaryError):
                    parse(magic + bytes(128))

    def test_elf_invalid_header_fields(self):
        fields = [(4, "B", 1), (5, "B", 2), (18, "H", 62),
                  (40, "Q", (1 << 64) - 1), (52, "H", 0),
                  (58, "H", 63), (60, "H", 0), (62, "H", 5)]
        for offset, fmt, value in fields:
            data, _ = elf_object()
            struct.pack_into("<" + fmt, data, offset, value)
            with self.subTest(offset=offset):
                with self.assertRaises(BinaryError):
                    parse(data)

    def test_elf_symbol_table_requires_valid_link_and_entry_size(self):
        for relative, fmt, value in ((40, "I", 99), (40, "I", 1), (56, "Q", 23)):
            data, m = elf_object()
            struct.pack_into("<" + fmt, data, m["shoff"] + 2 * 64 + relative, value)
            with self.subTest(relative=relative, value=value):
                with self.assertRaises(BinaryError):
                    parse(data)

    def test_elf_invalid_function_extents(self):
        for relative, fmt, value in ((6, "H", 8), (8, "Q", 9), (16, "Q", 9)):
            data, m = elf_object()
            struct.pack_into("<" + fmt, data, m["symoff"] + 24 + relative, value)
            with self.subTest(relative=relative):
                with self.assertRaises(BinaryError):
                    parse(data)

    def test_elf_unterminated_and_invalid_symbol_names(self):
        data, m = elf_object()
        struct.pack_into("<I", data, m["symoff"] + 24, 9999)
        with self.assertRaises(BinaryError):
            parse(data)
        data, m = elf_object()
        data[m["stroff"] + 5] = ord("x")
        with self.assertRaises(BinaryError):
            parse(data)

    def test_elf_exec_nobits_is_not_code(self):
        data, m = elf_object()
        struct.pack_into("<I", data, m["shoff"] + 64 + 4, 8)
        self.assert_not_selectable(data)

    def test_elf_section_name_table_must_be_string_table(self):
        data, m = elf_object()
        struct.pack_into("<I", data, m["shoff"] + 4 * 64 + 4, 1)
        with self.assertRaises(BinaryError):
            parse(data)

    def test_elf_header_overlap_is_not_mutable_code(self):
        data, m = elf_object()
        struct.pack_into("<Q", data, m["shoff"] + 64 + 24, 0)
        self.assert_not_selectable(data)

    def test_virtualize_cannot_drop_other_exported_definitions(self):
        additions = [
            ("common_data", 0x11, 0xFFF2, 4, 4),
            ("absolute_value", 0x10, 0xFFF1, 7, 0),
            ("function_alias", 0x10, 1, 0, 0),
        ]
        for symbol in additions:
            data, _ = elf_object([symbol])
            with self.subTest(symbol=symbol[0]):
                with self.assertRaises(BinaryError):
                    parse(data).virtualizable()

    def test_macho_invalid_header_and_load_commands(self):
        fields = [(4, 0x01000007), (8, 2), (16, 999), (20, 0xFFFFFFFF),
                  (36, 7), (36, 160), (32 + 64, 2)]
        for offset, value in fields:
            data, _ = macho_object()
            struct.pack_into("<I", data, offset, value)
            with self.subTest(offset=offset, value=value):
                with self.assertRaises(BinaryError):
                    parse(data)

    def test_macho_symbol_and_strings_are_bounds_checked(self):
        for field in (8, 12, 16, 20):
            data, m = macho_object()
            struct.pack_into("<I", data, m["symcommand"] + field, 0xFFFFFFFF)
            with self.subTest(field=field):
                with self.assertRaises(BinaryError):
                    parse(data)
        data, m = macho_object()
        struct.pack_into("<I", data, m["symoff"], 0xFFFFFFFF)
        with self.assertRaises(BinaryError):
            parse(data)

    def test_macho_data_in_code_is_not_selectable(self):
        data, _ = macho_object(data_in_code=True)
        self.assert_not_selectable(data)

    def test_macho_relocated_text_is_not_selectable(self):
        data, _ = macho_object(relocation=True)
        self.assert_not_selectable(data)

    def test_macho_zerofill_executable_section_is_not_code(self):
        data, m = macho_object()
        struct.pack_into("<I", data, m["section"] + 64, 0x80000401)
        self.assert_not_selectable(data)

    def test_macho_header_overlap_is_not_mutable_code(self):
        data, m = macho_object()
        struct.pack_into("<Q", data, 32 + 40, 0)
        struct.pack_into("<I", data, m["section"] + 48, 0)
        self.assert_not_selectable(data)

    def test_macho_symbol_table_overlap_is_not_mutable_code(self):
        data, m = macho_object()
        struct.pack_into("<Q", data, 32 + 40, m["symoff"])
        struct.pack_into("<I", data, m["section"] + 48, m["symoff"])
        self.assert_not_selectable(data)


if __name__ == "__main__":
    unittest.main()

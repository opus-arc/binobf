"""Original synthetic AArch64 fixtures; no proprietary code or data."""
from __future__ import annotations

import struct


MIX_WORDS = (0x0B010008, 0x4A010109, 0x531B692A, 0x0B090140, 0xD65F03C0)
SELECT_WORDS = (0x6B01001F, 0x1A818008, 0x4A010100, 0xD65F03C0)


def words(*values: int) -> bytes:
    return struct.pack('<' + 'I' * len(values), *values)


def mix_reference(x: int, y: int) -> int:
    z = ((x + y) & 0xFFFFFFFF) ^ y
    return ((z << 5) + z) & 0xFFFFFFFF


def select_reference(x: int, y: int) -> int:
    return (x if x > y else y) ^ y


def elf_object(functions=None) -> bytes:
    """Construct a strict, reloc-free ELF64 little-endian AArch64 ET_REL file."""
    if functions is None:
        functions = [('mix32', words(*MIX_WORDS)), ('select32', words(*SELECT_WORDS))]
    code = bytearray()
    strings = bytearray(b'\0')
    symbols = bytearray(24)  # ELF symbol zero
    symbols += struct.pack('<IBBHQQ', 0, 3, 0, 1, 0, 0)  # local section
    for name, body in functions:
        if not body or len(body) % 4:
            raise ValueError('instruction-aligned nonempty fixture required')
        name_offset = len(strings)
        strings += name.encode('ascii') + b'\0'
        symbols += struct.pack('<IBBHQQ', name_offset, 0x12, 0, 1, len(code), len(body))
        code += body
    section_names = b'\0.text\0.symtab\0.strtab\0.shstrtab\0'
    payloads = [bytes(code), bytes(symbols), bytes(strings), section_names]
    image = bytearray(64)
    offsets = []
    for payload, alignment in zip(payloads, [4, 8, 1, 1]):
        image += b'\0' * (-len(image) % alignment)
        offsets.append(len(image))
        image += payload
    image += b'\0' * (-len(image) % 8)
    section_offset = len(image)
    sections = [bytes(64)]
    # name, type, flags, addr, offset, size, link, info, alignment, entry-size
    sections.append(struct.pack('<IIQQQQIIQQ', 1, 1, 6, 0, offsets[0], len(code), 0, 0, 4, 0))
    sections.append(struct.pack('<IIQQQQIIQQ', 7, 2, 0, 0, offsets[1], len(symbols), 3, 2, 8, 24))
    sections.append(struct.pack('<IIQQQQIIQQ', 15, 3, 0, 0, offsets[2], len(strings), 0, 0, 1, 0))
    sections.append(struct.pack('<IIQQQQIIQQ', 23, 3, 0, 0, offsets[3], len(section_names), 0, 0, 1, 0))
    image += b''.join(sections)
    ident = b'\x7fELF\x02\x01\x01' + bytes(9)
    image[:64] = struct.pack('<16sHHIQQQIHHHHHH', ident, 1, 183, 1, 0, 0,
                            section_offset, 0, 64, 0, 0, 64, 5, 4)
    return bytes(image)

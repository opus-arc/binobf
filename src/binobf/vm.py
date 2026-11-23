"""Strict AArch64 u32 leaf decoding and native C99 virtualization.

The decoder consumes instruction words, not LLVM IR or disassembler text.
The supported ABI is uint32_t(uint32_t, uint32_t). This module intentionally
does not claim arbitrary executable rewriting or cryptographic protection.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import random
import re
import struct
from typing import Mapping, Sequence

U32 = 0xFFFFFFFF
MAX_INSTRUCTIONS = 4096


class UnsupportedInstruction(ValueError):
    """The entire function must be left untouched when decoding fails."""


@dataclass(frozen=True)
class FunctionSpec:
    name: str
    code: bytes
    address: int = 0


@dataclass(frozen=True)
class RegisterField:
    name: str
    shift: int
    reg: int
    role: str


@dataclass(frozen=True)
class Instruction:
    offset: int
    word: int
    op: str
    args: tuple[int, ...]
    reads: frozenset[int]
    writes: frozenset[int]
    register_fields: tuple[RegisterField, ...]
    reads_flags: bool = False
    writes_flags: bool = False


@dataclass(frozen=True)
class GeneratedSource:
    source: str
    manifest: dict


def _rng(seed: int, spec: FunctionSpec, purpose: str) -> random.Random:
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise TypeError("seed must be an integer")
    digest = hashlib.sha256(
        str(seed).encode("ascii") + b"\0" + purpose.encode("ascii") + b"\0"
        + spec.name.encode("utf-8") + b"\0" + spec.code
    ).digest()
    return random.Random(int.from_bytes(digest, "big"))


def _rotate(value: int, amount: int, width: int = 32) -> int:
    amount %= width
    mask = (1 << width) - 1
    return ((value >> amount) | (value << ((width - amount) % width))) & mask


def _logical_immediate(word: int) -> int:
    n, immr, imms = (word >> 22) & 1, (word >> 16) & 63, (word >> 10) & 63
    if n:
        raise ValueError("N=1 is not a 32-bit logical immediate")
    length = ((~imms) & 63).bit_length() - 1
    if length < 1:
        raise ValueError("reserved logical immediate")
    size = 1 << length
    s, r = imms & (size - 1), immr & (size - 1)
    if s == size - 1:
        raise ValueError("reserved all-ones logical immediate")
    element = _rotate((1 << (s + 1)) - 1, r, size)
    return sum(element << bit for bit in range(0, 32, size))


def decode_arm64_u32(spec: FunctionSpec) -> tuple[Instruction, ...]:
    """Decode an entire straight-line leaf or reject it without mutation.

    Only W0..W17 and WZR may participate in arithmetic. The link register is
    accepted solely in RET X30. SP, platform/callee-saved registers, hidden
    parameters, unknown NZCV inputs, memory, calls, and branches are rejected.
    Trailing architectural NOPs are accepted as alignment padding.
    """
    code = spec.code
    if not isinstance(code, bytes) or not code or len(code) % 4:
        raise UnsupportedInstruction(f"{spec.name}: code must be nonempty complete 4-byte instructions")
    if len(code) // 4 > MAX_INSTRUCTIONS:
        raise UnsupportedInstruction(f"{spec.name}: instruction limit {MAX_INSTRUCTIONS} exceeded")
    if spec.address < 0 or spec.address % 4:
        raise UnsupportedInstruction(f"{spec.name}: unaligned/negative function address")
    result: list[Instruction] = []
    initialized, flags_known, returned = {0, 1, 31}, False, False

    for offset in range(0, len(code), 4):
        word = struct.unpack_from("<I", code, offset)[0]
        d, n, m, a = word & 31, (word >> 5) & 31, (word >> 16) & 31, (word >> 10) & 31
        op, args = "", ()
        fields: list[RegisterField] = []
        reads: set[int] = set()
        writes: set[int] = set()
        rf = wf = False

        def fail(reason: str) -> None:
            raise UnsupportedInstruction(f"{spec.name}+0x{offset:x} (0x{word:08x}): {reason}")

        def reg(label: str, shift: int, value: int, role: str) -> None:
            if value not in range(18) and value != 31:
                fail(f"W{value} is outside the supported caller-scratch ABI profile")
            fields.append(RegisterField(label, shift, value, role))
            if role in ("read", "read_write") and value != 31:
                reads.add(value)
            if role in ("write", "read_write") and value != 31:
                writes.add(value)

        if word == 0xD503201F:
            op = "NOP"
        elif returned:
            fail("non-NOP bytes after RET; ambiguous function extent")
        elif word == 0xD65F03C0:
            op, returned = "RET", True
            reads.add(0)
        elif word >> 31:
            fail("64-bit, branch, memory, system, or unsupported instruction")
        elif word & 0x1F800000 == 0x12800000:
            # Move wide: MOVN/MOVZ/MOVK, including their MOV aliases.
            kind, half, imm = (word >> 29) & 3, (word >> 21) & 3, (word >> 5) & 65535
            if kind == 1 or half > 1:
                fail("reserved 32-bit move-wide encoding")
            if kind == 3:
                op, args = "MOVK", (d, imm, half * 16)
                reg("Rd", 0, d, "read_write")
            else:
                value = imm << (half * 16)
                op, args = "MOVI", (d, ((~value) if kind == 0 else value) & U32)
                reg("Rd", 0, d, "write")
        elif word & 0x1F000000 == 0x0A000000:
            # Logical shifted register. R31 is ZR for every register field.
            kind, shift, amount, invert = (word >> 29) & 3, (word >> 22) & 3, (word >> 10) & 63, (word >> 21) & 1
            if amount > 31:
                fail("reserved W logical shift amount")
            wf = kind == 3
            op, args = "LOG_R", (d, n, m, shift, amount, kind, invert, int(wf))
            reg("Rd", 0, d, "write"); reg("Rn", 5, n, "read"); reg("Rm", 16, m, "read")
        elif word & 0x1F800000 == 0x12000000:
            # Logical immediate: non-flag-setting Rd=31 means SP, not ZR.
            kind = (word >> 29) & 3
            wf = kind == 3
            if d == 31 and not wf:
                fail("logical-immediate SP destination is unsupported")
            try:
                imm = _logical_immediate(word)
            except ValueError as exc:
                fail(str(exc))
            op, args = "LOG_I", (d, n, imm, kind, int(wf))
            reg("Rd", 0, d, "write"); reg("Rn", 5, n, "read")
        elif word & 0x1F800000 == 0x11000000:
            # ADD/SUB immediate: Rn=31 always names SP. With S=0 Rd=31 is SP.
            subtract, wf = (word >> 30) & 1, bool((word >> 29) & 1)
            if n == 31 or (d == 31 and not wf):
                fail("SP arithmetic is unsupported")
            imm = ((word >> 10) & 4095) << (12 if word & (1 << 22) else 0)
            op, args = "ARITH_I", (d, n, imm, subtract, int(wf))
            reg("Rd", 0, d, "write"); reg("Rn", 5, n, "read")
        elif word & 0x1F200000 == 0x0B000000:
            # ADD/SUB shifted register (NOT extended-register forms).
            shift, amount = (word >> 22) & 3, (word >> 10) & 63
            if shift == 3 or amount > 31:
                fail("reserved ADD/SUB shifted-register encoding")
            subtract, wf = (word >> 30) & 1, bool((word >> 29) & 1)
            op, args = "ARITH_R", (d, n, m, shift, amount, subtract, int(wf))
            reg("Rd", 0, d, "write"); reg("Rn", 5, n, "read"); reg("Rm", 16, m, "read")
        elif word & 0x1F800000 == 0x13000000:
            # SBFM/BFM/UBFM: extract, signed extract, insert, and shift aliases.
            kind, immr, imms = (word >> 29) & 3, (word >> 16) & 63, (word >> 10) & 63
            if kind == 3 or word & (1 << 22) or immr > 31 or imms > 31:
                fail("reserved 32-bit bitfield encoding")
            op, args = "BITFIELD", (d, n, immr, imms, kind)
            reg("Rd", 0, d, "read_write" if kind == 1 else "write"); reg("Rn", 5, n, "read")
        elif word & 0xFFE00000 == 0x13800000:
            amount = (word >> 10) & 63
            if amount > 31:
                fail("reserved 32-bit EXTR shift")
            op, args = "EXTR", (d, n, m, amount)
            reg("Rd", 0, d, "write"); reg("Rn", 5, n, "read"); reg("Rm", 16, m, "read")
        elif word & 0xFFE0FC00 in (0x1AC02000, 0x1AC02400, 0x1AC02800, 0x1AC02C00):
            kind = (word >> 10) & 3
            op, args = "SHIFT_R", (d, n, m, kind)
            reg("Rd", 0, d, "write"); reg("Rn", 5, n, "read"); reg("Rm", 16, m, "read")
        elif word & 0xFFE00000 == 0x1B000000:
            op, args = "MADD", (d, n, m, a, (word >> 15) & 1)
            reg("Rd", 0, d, "write"); reg("Rn", 5, n, "read"); reg("Rm", 16, m, "read"); reg("Ra", 10, a, "read")
        elif word & 0x3FE00800 == 0x1A800000:
            cond, variant = (word >> 12) & 15, (((word >> 30) & 1) << 1) | ((word >> 10) & 1)
            rf = cond < 14  # Both AL and NV are always true for CSEL.
            op, args = "CSEL", (d, n, m, cond, variant)
            reg("Rd", 0, d, "write"); reg("Rn", 5, n, "read"); reg("Rm", 16, m, "read")
        else:
            fail("instruction is outside the explicit u32 leaf whitelist")

        if not reads <= initialized:
            fail("read before definition / undeclared ABI input: " + ", ".join(f"W{r}" for r in sorted(reads - initialized)))
        if rf and not flags_known:
            fail("condition consumes undefined incoming NZCV flags")
        initialized.update(writes)
        flags_known |= wf
        result.append(Instruction(offset, word, op, args, frozenset(reads), frozenset(writes), tuple(fields), rf, wf))
    if not returned:
        raise UnsupportedInstruction(f"{spec.name}: no supported RET X30")
    return tuple(result)


def remap_registers(spec: FunctionSpec, mapping: Mapping[int, int]) -> bytes:
    """Same-length global permutation of only W8..W15 after whole-function validation."""
    allowed = set(range(8, 16))
    if set(mapping) != allowed or set(mapping.values()) != allowed:
        raise ValueError("mapping must be a complete permutation of W8..W15")
    decoded = decode_arm64_u32(spec)
    out = bytearray(spec.code)
    for inst in decoded:
        word = inst.word
        for field in inst.register_fields:
            if field.reg in allowed:
                word = (word & ~(31 << field.shift)) | (mapping[field.reg] << field.shift)
        struct.pack_into("<I", out, inst.offset, word)
    result = bytes(out)
    decode_arm64_u32(FunctionSpec(spec.name, result, spec.address))
    return result


def native_remap(spec: FunctionSpec, *, seed: int) -> tuple[bytes, dict]:
    """Native diversification only; no anti-extraction strength is asserted."""
    decoded = decode_arm64_u32(spec)
    regs = list(range(8, 16)); shuffled = regs.copy()
    rng = _rng(seed, spec, "native-registers"); rng.shuffle(shuffled)
    used = {f.reg for ins in decoded for f in ins.register_fields if f.reg in regs}
    if used and all(shuffled[r - 8] == r for r in used):
        shuffled = shuffled[1:] + shuffled[:1]
    out = remap_registers(spec, dict(zip(regs, shuffled)))
    changes = sum(spec.code[i:i + 4] != out[i:i + 4] for i in range(0, len(out), 4))
    return out, {"name": spec.name, "bytes": len(out), "instructions": len(decoded),
                 "changed_instructions": changes, "changed_bytes": sum(a != b for a, b in zip(spec.code, out)),
                 "mode": "native-register-diversification", "abi": "u32(u32,u32)"}


_REG_ARGS = {
    "MOVI": (0,), "MOVK": (0,), "LOG_R": (0, 1, 2), "LOG_I": (0, 1),
    "ARITH_R": (0, 1, 2), "ARITH_I": (0, 1), "BITFIELD": (0, 1),
    "EXTR": (0, 1, 2), "SHIFT_R": (0, 1, 2), "MADD": (0, 1, 2, 3),
    "CSEL": (0, 1, 2), "RET": (),
}

_RUNTIME_LICENSE = """/* Generated by binobf.
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Opus Arc
 *
 * This notice covers binobf's generated runtime support. It does not change
 * the license or ownership of the translated input functions or their data.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the \"Software\"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Reversible native-code virtualization; no security guarantee.
 */
"""

_C_HELPERS = r'''
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#if UINT_MAX != 0xffffffffU || UINT32_MAX != 0xffffffffU
#error "binobf runtime requires 32-bit unsigned int and uint32_t"
#endif
#if defined(__GNUC__) || defined(__clang__)
#define BNO_NOINLINE __attribute__((noinline))
#else
#define BNO_NOINLINE
#endif
static uint32_t BNO_mask(uint32_t n) { return n == 32u ? UINT32_MAX : ((UINT32_C(1) << n) - 1u); }
static uint32_t BNO_shift(uint32_t x, uint32_t kind, uint32_t n) {
    n &= 31u;
    if (!n) return x;
    switch (kind) {
    case 0: return x << n;
    case 1: return x >> n;
    case 2: return (x >> n) | ((0u - (x >> 31)) << (32u - n));
    case 3: return (x >> n) | (x << (32u - n));
    default: abort();
    }
}
static uint32_t BNO_field(uint32_t old, uint32_t x, uint32_t r, uint32_t s, uint32_t kind) {
    uint32_t width = s >= r ? s-r+1u : s+1u;
    uint32_t lsb = s >= r ? 0u : 32u-r;
    uint32_t mask = BNO_mask(width);
    uint32_t value = (s >= r ? x >> r : x) & mask;
    if (kind == 1u) return (old & ~(mask << lsb)) | (value << lsb);
    if (kind == 0u && (value & (UINT32_C(1) << (width-1u)))) value |= ~mask;
    return value << lsb;
}
static uint32_t BNO_cond(uint32_t cond, uint32_t n, uint32_t z, uint32_t c, uint32_t v) {
    uint32_t result;
    switch (cond >> 1) {
    case 0: result=z; break;
    case 1: result=c; break;
    case 2: result=n; break;
    case 3: result=v; break;
    case 4: result=c && !z; break;
    case 5: result=n==v; break;
    case 6: result=!z && (n==v); break;
    case 7: result=1u; break;
    default: abort();
    }
    return (cond & 1u) && cond != 15u ? !result : result;
}
'''


def _case_bodies() -> dict[str, str]:
    # a[] contains decoded words. Per-case bounds guard against malformed data.
    return {
        "MOVI": "if(a[0]>31u) abort(); d=a[0]; value=a[1];",
        "MOVK": "if(a[0]>31u || a[1]>65535u || (a[2]!=0u && a[2]!=16u)) abort(); d=a[0]; value=(r[d] & ~(UINT32_C(65535)<<a[2])) | (a[1]<<a[2]);",
        "LOG_R": """if(a[0]>31u || a[1]>31u || a[2]>31u || a[3]>3u || a[4]>31u || a[5]>3u || a[6]>1u || a[7]>1u) abort();
            d=a[0]; x=r[a[1]]; y=BNO_shift(r[a[2]],a[3],a[4]); if(a[6]) y=~y;
            value=(a[5]==0u || a[5]==3u)?x&y:(a[5]==1u?x|y:x^y);
            if(a[7]) { nf=value>>31; zf=value==0u; cf=0u; vf=0u; }""",
        "LOG_I": """if(a[0]>31u || a[1]>31u || a[3]>3u || a[4]>1u) abort();
            d=a[0]; x=r[a[1]]; y=a[2]; value=(a[3]==0u || a[3]==3u)?x&y:(a[3]==1u?x|y:x^y);
            if(a[4]) { nf=value>>31; zf=value==0u; cf=0u; vf=0u; }""",
        "ARITH_R": """if(a[0]>31u || a[1]>31u || a[2]>31u || a[3]>2u || a[4]>31u || a[5]>1u || a[6]>1u) abort();
            d=a[0]; x=r[a[1]]; y=BNO_shift(r[a[2]],a[3],a[4]); sub=a[5]; setf=a[6];
            value=sub?x-y:x+y;
            if(setf) { nf=value>>31; zf=value==0u; cf=sub?(x>=y):(uint32_t)(((uint64_t)x+y)>>32); vf=((sub?(x^y):~(x^y)) & (x^value))>>31; }""",
        "ARITH_I": """if(a[0]>31u || a[1]>31u || a[3]>1u || a[4]>1u) abort();
            d=a[0]; x=r[a[1]]; y=a[2]; sub=a[3]; setf=a[4]; value=sub?x-y:x+y;
            if(setf) { nf=value>>31; zf=value==0u; cf=sub?(x>=y):(uint32_t)(((uint64_t)x+y)>>32); vf=((sub?(x^y):~(x^y)) & (x^value))>>31; }""",
        "BITFIELD": "if(a[0]>31u || a[1]>31u || a[2]>31u || a[3]>31u || a[4]>2u) abort(); d=a[0]; value=BNO_field(r[d],r[a[1]],a[2],a[3],a[4]);",
        "EXTR": "if(a[0]>31u || a[1]>31u || a[2]>31u || a[3]>31u) abort(); d=a[0]; value=a[3]?(r[a[2]]>>a[3]) | (r[a[1]]<<(32u-a[3])):r[a[2]];",
        "SHIFT_R": "if(a[0]>31u || a[1]>31u || a[2]>31u || a[3]>3u) abort(); d=a[0]; value=BNO_shift(r[a[1]],a[3],r[a[2]]);",
        "MADD": "if(a[0]>31u || a[1]>31u || a[2]>31u || a[3]>31u || a[4]>1u) abort(); d=a[0]; product=(uint64_t)r[a[1]]*r[a[2]]; value=(uint32_t)(a[4]?(uint64_t)r[a[3]]-product:product+r[a[3]]);",
        "CSEL": """if(a[0]>31u || a[1]>31u || a[2]>31u || a[3]>15u || a[4]>3u) abort(); d=a[0];
            if(BNO_cond(a[3],nf,zf,cf,vf)) value=r[a[1]];
            else { value=r[a[2]]; if(a[4]==1u) value+=1u; else if(a[4]==2u) value=~value; else if(a[4]==3u) value=0u-value; }""",
        "RET": "RETURN_STATEMENT",
    }


def generate_c(functions: Sequence[FunctionSpec], *, seed: int) -> GeneratedSource:
    """Emit replacement C99 functions with the exact declared two-u32 ABI.

    Operand masks and opcode/register permutations are reversible obfuscation,
    not encryption. The manifest intentionally omits seeds and decoding maps.
    """
    if not functions:
        raise ValueError("at least one function is required")
    names = [f.name for f in functions]
    keywords = set("auto break case char const continue default do double else enum extern float for goto if inline int long register restrict return short signed sizeof static struct switch typedef union unsigned void volatile while _Bool _Complex _Imaginary uint32_t uint64_t".split())
    if len(set(names)) != len(names) or any(not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", n) or n in keywords for n in names):
        raise ValueError("function names must be unique non-keyword C identifiers")
    decoded = [(f, decode_arm64_u32(f)) for f in functions]
    prefix = "bno_" + hashlib.sha256(("\0".join(names) + str(seed)).encode()).hexdigest()[:16] + "_"
    if any(n.startswith(prefix) for n in names):
        raise ValueError("function name collides with generated runtime")
    parts = [_RUNTIME_LICENSE, _C_HELPERS]
    bodies = _case_bodies()
    stats = []
    for number, (spec, instructions) in enumerate(decoded):
        rng = _rng(seed, spec, "vm")
        registers = list(range(32)); rng.shuffle(registers)
        zero, arg0, arg1 = registers[31], registers[0], registers[1]
        opcode_values = rng.sample(range(1, 0xFFFFFFFF), len(bodies))
        opcodes = dict(zip(bodies, opcode_values))
        key0, key1, key2 = rng.getrandbits(32), rng.getrandbits(32) | 1, rng.getrandbits(32) | 1
        program = [i for i in instructions if i.op != "NOP"]
        rows = []
        for pc, inst in enumerate(program):
            args = list(inst.args)
            for index in _REG_ARGS[inst.op]:
                args[index] = registers[args[index]]
            raw = [opcodes[inst.op]] + args
            raw.extend(rng.getrandbits(32) for _ in range(9 - len(raw)))
            rows.append([(v ^ key0 ^ ((pc * key1) & U32) ^ ((slot * key2) & U32)) & U32 for slot, v in enumerate(raw)])
        array = f"BNO_code_{number}"
        run = f"BNO_run_{number}"
        parts.append(f"\nstatic const uint32_t {array}[{len(rows)}][9] = {{\n")
        parts.extend("    {" + ", ".join(f"UINT32_C(0x{v:08x})" for v in row) + "},\n" for row in rows)
        parts.append("};\n")
        parts.append(f"""static BNO_NOINLINE uint32_t {run}(uint32_t input0, uint32_t input1) {{
    uint32_t r[32]={{0}}, a[8], pc, slot, opcode;
    uint32_t nf=0u,zf=0u,cf=0u,vf=0u;
    r[{arg0}]=input0; r[{arg1}]=input1;
    for(pc=0u; pc<{len(rows)}u; ++pc) {{
        const volatile uint32_t *p={array}[pc];
        uint32_t base=UINT32_C(0x{key0:08x}) ^ (pc*UINT32_C(0x{key1:08x}));
        uint32_t d={zero}u,value=0u,x=0u,y=0u,sub=0u,setf=0u;
        uint64_t product=0u;
        opcode=p[0]^base;
        for(slot=0u;slot<8u;++slot) a[slot]=p[slot+1u]^base^((slot+1u)*UINT32_C(0x{key2:08x}));
        switch(opcode) {{
""")
        for op, body in bodies.items():
            if op == "RET":
                body = f"if(pc!={len(rows)-1}u) abort(); return r[{arg0}];"
            parts.append(f"        case UINT32_C(0x{opcodes[op]:08x}): {{ {body} }} break;\n")
        parts.append(f"""        default: abort();
        }}
        if(d!={zero}u) r[d]=value;
        r[{zero}]=0u;
    }}
    abort();
}}
uint32_t BNO_PUBLIC_{number}(uint32_t input0, uint32_t input1) {{ return {run}(input0,input1); }}
""")
        stats.append({"name": spec.name, "machine_bytes": len(spec.code), "machine_instructions": len(instructions),
                      "vm_instructions": len(program), "bytecode_bytes": len(rows)*36,
                      "semantic_opcodes_used": len({i.op for i in program}),
                      "uses_flags": any(i.reads_flags or i.writes_flags for i in program)})
    parts.append("\n#undef BNO_NOINLINE\n")
    source = "".join(parts).replace("BNO_", prefix)
    # Insert public symbols after private-placeholder replacement so a valid
    # input symbol containing "BNO_" cannot silently acquire a different ABI.
    source = re.sub(r"\b" + re.escape(prefix) + r"PUBLIC_(\d+)\b",
                    lambda match: names[int(match[1])], source)
    manifest = {"backend": "arm64-u32-native-vm", "abi": "uint32_t(uint32_t,uint32_t)",
                "functions": stats, "encoding": "reversible opcode/register/operand diversification",
                "original_native_code_embedded": False, "decoding_maps_in_manifest": False,
                "runtime": "self-contained C99 plus standard C abort; per-call local state"}
    return GeneratedSource(source, manifest)

"""Conservative, bounds-checked readers for little-endian ARM64 binaries.

Only existing, named function extents are exposed. No disassembly-based function
boundary guesses, load-command growth, or relocation rewriting is attempted.
"""
from dataclasses import dataclass, field
from pathlib import Path
import struct


class BinaryError(ValueError):
    pass


@dataclass(frozen=True)
class Function:
    name: str
    address: int
    offset: int
    size: int
    code: bytes
    section_index: int
    external: bool = True
    safe: bool = True
    reason: str = ""


@dataclass
class BinaryImage:
    data: bytes
    format: str
    kind: str
    functions: list = field(default_factory=list)
    has_signature: bool = False
    has_data: bool = False
    other_code: bool = False
    warnings: list = field(default_factory=list)
    symbol_aliases: bool = False

    @classmethod
    def read(cls, path):
        return parse(Path(path).read_bytes())

    def select(self, names):
        selected = []
        for name in names:
            matches = [f for f in self.functions if f.name == name]
            # Mach-O C names have a single platform underscore prefix.
            if not matches and self.format == "macho":
                matches = [f for f in self.functions if f.name == "_" + name]
            if len(matches) != 1:
                raise BinaryError(f"function {name!r}: expected one unambiguous symbol, found {len(matches)}")
            function = matches[0]
            if not function.safe:
                raise BinaryError(f"function {name!r}: {function.reason}")
            if function not in selected:
                selected.append(function)
        if not selected:
            raise BinaryError("at least one named function is required")
        ranges = sorted((f.offset, f.offset + f.size) for f in selected)
        if any(a[1] > b[0] for a, b in zip(ranges, ranges[1:])):
            raise BinaryError("selected functions overlap or alias one another")
        return selected

    def virtualizable(self):
        if self.kind != "object":
            raise BinaryError("virtualize requires a dedicated relocatable object, not an executable or library")
        if self.has_data or self.other_code or self.symbol_aliases or not self.functions:
            raise BinaryError("virtualize requires only distinct exported leaf functions: data, local code, or aliases were found")
        if any(not f.external or not f.safe for f in self.functions):
            raise BinaryError("virtualize cannot discard local functions, relocations, or unsafe function ranges")
        return self.functions


def _extent(data, offset, size, what):
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise BinaryError(f"truncated or invalid {what}")
    return data[offset:offset + size]


def _unpack(fmt, data, offset, what):
    _extent(data, offset, struct.calcsize(fmt), what)
    return struct.unpack_from(fmt, data, offset)


def _string(table, offset, what):
    if offset < 0 or offset >= len(table):
        raise BinaryError(f"invalid {what} string offset")
    end = table.find(b'\0', offset)
    if end < 0:
        raise BinaryError(f"unterminated {what} string")
    try:
        return table[offset:end].decode('utf-8')
    except UnicodeDecodeError:
        raise BinaryError(f"invalid UTF-8 in {what} name") from None


def _overlap(a, b, c, d):
    return a < d and c < b


def parse(data):
    data = bytes(data)
    if data[:4] == b'\xcf\xfa\xed\xfe':
        return _macho(data)
    if data[:4] == b'\x7fELF':
        return _elf(data)
    raise BinaryError("supported input: thin little-endian ARM64 Mach-O or ELF64; fat, PE, archives and bitcode are unsupported")


def _macho(data):
    _, cpu, subtype, filetype, ncmds, cmdbytes, flags, reserved = _unpack('<8I', data, 0, 'Mach-O header')
    if cpu != 0x0100000c or (subtype & 0xffffff) != 0:
        raise BinaryError("only generic arm64 Mach-O is supported; arm64e and other CPUs are rejected")
    kinds = {1: 'object', 2: 'executable', 6: 'shared'}
    if filetype not in kinds:
        raise BinaryError("unsupported Mach-O file type")
    _extent(data, 32, cmdbytes, 'Mach-O load commands')
    if ncmds > cmdbytes // 8:
        raise BinaryError("invalid load command count")
    image = BinaryImage(data, 'macho', kinds[filetype])
    pos, sections, symtab, data_ranges, starts, text_base = 32, [], None, [], None, None
    for _ in range(ncmds):
        cmd, size = _unpack('<II', data, pos, 'load command')
        if size < 8 or size % 8 or pos + size > 32 + cmdbytes:
            raise BinaryError("invalid load command size")
        if cmd == 0x19:  # LC_SEGMENT_64
            if size < 72:
                raise BinaryError('truncated segment command')
            seg = _unpack('<II16sQQQQiiII', data, pos, 'segment')
            segname, vmaddr, vmsize, fileoff, filesize, _, _, count, _ = seg[2:]
            if 72 + 80 * count != size:
                raise BinaryError('invalid segment section count')
            _extent(data, fileoff, filesize, 'segment file extent')
            if segname.rstrip(b'\0') == b'__TEXT':
                text_base = vmaddr
            for j in range(count):
                s = _unpack('<16s16sQQIIIIIIII', data, pos + 72 + 80*j, 'Mach-O section')
                name, segment, addr, length, off, align, reloff, nreloc, sf, _, _, _ = s
                name = name.rstrip(b'\0').decode('ascii', errors='replace')
                segment = segment.rstrip(b'\0').decode('ascii', errors='replace')
                zerofill = (sf & 255) in (1, 12, 18)
                if zerofill and sf & 0x80000400:
                    raise BinaryError('executable zero-fill section is unsupported')
                if not zerofill:
                    _extent(data, off, length, 'section contents')
                    if length and off < 32 + cmdbytes:
                        raise BinaryError('section overlaps Mach-O headers or load commands')
                    if length and not (fileoff <= off and off + length <= fileoff + filesize):
                        raise BinaryError('section extends outside its segment')
                _extent(data, reloff, 8*nreloc, 'section relocations')
                if align > 31:
                    raise BinaryError('invalid section alignment')
                sections.append(dict(name=name, segment=segment, address=addr, size=length, offset=off,
                                     reloc=nreloc, reloff=reloff, flags=sf, zero=zerofill))
        elif cmd == 2:
            if size != 24 or symtab is not None:
                raise BinaryError('invalid or repeated symbol table command')
            symtab = _unpack('<4I', data, pos + 8, 'Mach-O symbol table command')
        elif cmd == 0x1d:
            if size != 16:
                raise BinaryError('invalid code signature command')
            off, length = _unpack('<II', data, pos+8, 'signature extent')
            _extent(data, off, length, 'code signature')
            image.has_signature = bool(length)
        elif cmd in (0x26, 0x29):  # FUNCTION_STARTS / DATA_IN_CODE
            if size != 16:
                raise BinaryError('invalid linkedit data command')
            off, length = _unpack('<II', data, pos+8, 'linkedit extent')
            payload = _extent(data, off, length, 'linkedit data')
            if cmd == 0x26:
                starts = payload
            else:
                if length % 8:
                    raise BinaryError('invalid data-in-code entries')
                for o in range(0, length, 8):
                    start, n, _ = struct.unpack_from('<IHH', payload, o)
                    _extent(data, start, n, 'data-in-code range')
                    data_ranges.append((start, start+n))
        elif cmd == 0x21:  # LC_ENCRYPTION_INFO (32-bit) impossible in supported input
            raise BinaryError('encrypted Mach-O is unsupported')
        elif cmd == 0x2c:
            if size < 24:
                raise BinaryError('truncated encryption command')
            if struct.unpack_from('<I', data, pos+16)[0]:
                raise BinaryError('encrypted Mach-O is unsupported')
        pos += size
    if pos != 32 + cmdbytes:
        raise BinaryError('load-command sizes do not match the header')
    # File-backed section overlap can make a text write alter unrelated data.
    occupied = sorted((s['offset'], s['offset']+s['size']) for s in sections if s['size'] and not s['zero'])
    if any(a[1] > b[0] for a, b in zip(occupied, occupied[1:])):
        raise BinaryError('overlapping Mach-O sections')
    for s in sections:
        executable = bool(s['flags'] & 0x80000400)
        if executable and s['name'] != '__text' and s['size']:
            image.other_code = True
        if s['size'] and not executable and s['name'] not in ('__compact_unwind', '__eh_frame') and not s['flags'] & 0x02000000:
            image.has_data = True
    if symtab is None:
        image.warnings.append('No symbol table: named function protection is unavailable. Protect before stripping.')
        return image
    symoff, nsyms, stroff, strsize = symtab
    _extent(data, symoff, nsyms * 16, 'symbol entries')
    strings = _extent(data, stroff, strsize, 'symbol strings')
    metadata = [(symoff, symoff + nsyms*16), (stroff, stroff + strsize)]
    for s in sections:
        if not s['zero'] and any(_overlap(s['offset'],s['offset']+s['size'],a,b) for a,b in metadata if a < b):
            raise BinaryError('section overlaps Mach-O symbol metadata')
    symbols = []
    for j in range(nsyms):
        strx, typ, sec, desc, value = _unpack('<IBBHQ', data, symoff + 16*j, 'symbol')
        name = _string(strings, strx, 'symbol')
        if typ & 0xe0:  # debug/STAB records are not function boundaries
            continue
        if (typ & 0x0e) == 0x0e:
            if not 1 <= sec <= len(sections):
                raise BinaryError('symbol references an invalid section')
            s = sections[sec-1]
            if not s['address'] <= value <= s['address'] + s['size']:
                raise BinaryError('symbol outside its section')
            symbols.append((sec, value, name, bool(typ & 1), desc))
        elif typ & 1 and (typ & 0x0e) not in (0,):
            image.other_code = True  # absolute/indirect definitions cannot be discarded
    function_starts = set()
    if starts is not None and text_base is not None:
        total, value, shift, terminated = text_base, 0, 0, False
        for index, byte in enumerate(starts):
            value |= (byte & 127) << shift
            if byte & 128:
                shift += 7
                if shift > 63:
                    raise BinaryError('invalid ULEB128 function start')
                continue
            if value == 0:
                if any(starts[index+1:]):
                    raise BinaryError('data after function-start terminator')
                terminated = True
                break
            total += value
            if total > 0xffffffffffffffff or total % 4:
                raise BinaryError('invalid function-start address')
            function_starts.add(total)
            value, shift = 0, 0
        if starts and not terminated:
            raise BinaryError('unterminated function starts')
    for si, s in enumerate(sections, 1):
        if s['name'] != '__text' or not s['flags'] & 0x80000400:
            continue
        entries = [(v,n,e,d) for sec,v,n,e,d in symbols if sec == si and v < s['address'] + s['size']]
        # Assembler mapping/temporary labels do not define public functions.
        candidates = [(v,n,e,d) for v,n,e,d in entries if e or (not n.startswith(('L', 'ltmp', '$')) and image.kind != 'object')]
        boundaries = sorted({v for v,_,_,_ in entries} | {s['address'] + s['size']} | {v for v in function_starts if s['address'] <= v < s['address']+s['size']})
        for v, name, external, desc in candidates:
            end = next((a for a in boundaries if a > v), s['address']+s['size'])
            off, length = s['offset'] + v - s['address'], end - v
            problems = []
            if v % 4 or length <= 0 or length % 4:
                problems.append('unaligned function extent')
            if s['reloc']:
                problems.append('text relocations are unsupported')
            if function_starts and v not in function_starts:
                problems.append('symbol is not an LC_FUNCTION_STARTS entry')
            if any(_overlap(off,off+length,a,b) for a,b in data_ranges):
                problems.append('function overlaps data-in-code')
            if desc & 0x0080:  # N_WEAK_DEF
                problems.append('weak/coalesced definitions are unsupported')
            image.functions.append(Function(name,v,off,length,_extent(data,off,length,'function code'),si,external,not problems,'; '.join(problems)))
        if image.kind == 'object':
            covered = sorted({(f.address, f.address+f.size) for f in image.functions if f.section_index == si})
            if not covered or covered[0][0] != s['address'] or covered[-1][1] != s['address'] + s['size'] or any(a[1] != b[0] for a,b in zip(covered,covered[1:])):
                image.other_code = True
    addresses = [(f.section_index,f.address) for f in image.functions]
    image.symbol_aliases = len(addresses) != len(set(addresses))
    image.functions.sort(key=lambda f:(f.offset,f.name))
    return image


def _elf(data):
    if len(data) < 64 or data[4:7] != bytes((2,1,1)):
        raise BinaryError('only little-endian ELF64 version 1 is supported')
    typ, machine, version, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = _unpack('<HHIQQQIHHHHHH',data,16,'ELF header')
    if machine != 183 or version != 1 or typ not in (1,2,3) or ehsize != 64:
        raise BinaryError('unsupported ELF architecture, type or header')
    if shnum == 0 or shstrndx == 0xffff or phnum == 0xffff:
        raise BinaryError('ELF section table required; extended numbering is unsupported')
    if shentsize != 64 or shstrndx >= shnum:
        raise BinaryError('invalid ELF section table')
    _extent(data,shoff,shnum*64,'ELF sections')
    if phnum:
        if phentsize != 56:
            raise BinaryError('invalid ELF program-header size')
        _extent(data,phoff,phnum*56,'ELF program headers')
        for j in range(phnum):
            p = _unpack('<IIQQQQQQ',data,phoff+56*j,'program header')
            _extent(data,p[2],p[5],'segment contents')
            if p[0] == 1 and p[5] > p[6]:
                raise BinaryError('ELF load file size exceeds memory size')
    raw = [_unpack('<IIQQQQIIQQ',data,shoff+64*j,'section') for j in range(shnum)]
    if raw[shstrndx][1] != 3:
        raise BinaryError('ELF section names must reference a string table')
    names = _extent(data,raw[shstrndx][4],raw[shstrndx][5],'section names')
    sections=[]
    for j,s in enumerate(raw):
        name,st,fl,addr,off,length,link,info,align,entsize=s
        if st == 8 and fl & 4:
            raise BinaryError('executable NOBITS section is unsupported')
        if st != 8:
            _extent(data,off,length,'ELF section contents')
            if length and (off < 64 or _overlap(off,off+length,shoff,shoff+shnum*64) or
                           (phnum and _overlap(off,off+length,phoff,phoff+phnum*56))):
                raise BinaryError('ELF section overlaps file headers')
        if align and align & (align-1):
            raise BinaryError('invalid section alignment')
        sections.append(dict(name=_string(names,name,'section'),type=st,flags=fl,address=addr,offset=off,size=length,link=link,info=info,entsize=entsize))
    occupied=sorted((s['offset'],s['offset']+s['size']) for s in sections[1:] if s['size'] and s['type'] != 8)
    if any(a[1]>b[0] for a,b in zip(occupied,occupied[1:])):
        raise BinaryError('overlapping ELF sections')
    image=BinaryImage(data,'elf',{1:'object',2:'executable',3:'shared'}[typ])
    relocation_sections=set(); relocation_addresses=[]
    for s in sections:
        if s['type'] in (4,9):
            expected=24 if s['type']==4 else 16
            if s['entsize'] != expected or s['size'] % expected:
                raise BinaryError('invalid ELF relocation section')
            if s['info'] >= len(sections) or s['link'] >= len(sections):
                raise BinaryError('invalid relocation section reference')
            if typ==1 and s['size']:
                relocation_sections.add(s['info'])
            else:
                for p in range(s['offset'],s['offset']+s['size'],expected):
                    relocation_addresses.append(struct.unpack_from('<Q',data,p)[0])
        if s['flags'] & 2 and not s['flags'] & 4 and s['size'] and s['name'] not in ('.eh_frame','.ARM.exidx','.ARM.extab'):
            image.has_data=True
    seen=set(); symbol_points={}; all_function_ranges=[]
    for s in sections:
        if s['type'] not in (2,11):
            continue
        if s['entsize'] != 24 or s['size']%24 or s['link']>=len(sections) or sections[s['link']]['type']!=3:
            raise BinaryError('invalid ELF symbol table')
        strings_section=sections[s['link']]
        strings=_extent(data,strings_section['offset'],strings_section['size'],'ELF symbol strings')
        for p in range(s['offset'],s['offset']+s['size'],24):
            name,info,other,sec,value,length=_unpack('<IBBHQQ',data,p,'ELF symbol')
            name=_string(strings,name,'symbol')
            if sec==0 or sec>=0xff00:
                if sec==0xffff:
                    raise BinaryError('extended symbol section indexes are unsupported')
                if sec != 0 and info >> 4 != 0:
                    image.other_code = True
                continue
            if sec>=len(sections):
                raise BinaryError('symbol references invalid section')
            target=sections[sec]
            if typ == 1 and info >> 4 != 0 and (info & 15) != 2:
                image.other_code = True
            if not target['flags']&4:
                continue
            relative=value if typ==1 else value-target['address']
            if relative<0 or relative>target['size'] or length>target['size']-relative:
                raise BinaryError('ELF symbol outside its section')
            symbol_points.setdefault(sec,set()).add(relative)
            if (info&15) != 2:
                continue
            key=(sec,value,length,name)
            if key in seen:
                continue
            seen.add(key)
            off=target['offset']+relative
            problems=[]
            if length<=0 or relative%4 or length%4:
                problems.append('function has no aligned explicit size')
            if sec in relocation_sections or any(value<=a<value+length for a in relocation_addresses):
                problems.append('function has relocations')
            if info>>4 not in (0,1):
                problems.append('weak or nonstandard symbol binding')
            image.functions.append(Function(name,value,off,length,_extent(data,off,length,'ELF function'),sec,(info>>4)==1,not problems,'; '.join(problems)))
            all_function_ranges.append((sec,relative,relative+length))
    checked=[]
    for f in image.functions:
        s=sections[f.section_index]; rel=f.offset-s['offset']
        interior=any(rel<p<rel+f.size for p in symbol_points.get(f.section_index,()))
        overlapping=any(g.section_index==f.section_index and g.offset!=f.offset and _overlap(f.offset,f.offset+f.size,g.offset,g.offset+g.size) for g in image.functions)
        reason='function has an interior symbol or overlaps another function' if interior or overlapping else f.reason
        checked.append(Function(f.name,f.address,f.offset,f.size,f.code,f.section_index,f.external,f.safe and not (interior or overlapping),reason))
    image.functions=sorted(checked,key=lambda f:(f.offset,f.name))
    addresses=[(f.section_index,f.offset) for f in image.functions]
    image.symbol_aliases=len(addresses)!=len(set(addresses))
    if typ==1:
        for si,s in enumerate(sections):
            if not s['flags']&4 or not s['size']:
                continue
            ranges=sorted({(f.offset-s['offset'],f.offset-s['offset']+f.size) for f in image.functions if f.section_index==si})
            if not ranges or ranges[0][0]!=0 or ranges[-1][1]!=s['size'] or any(a[1]!=b[0] for a,b in zip(ranges,ranges[1:])):
                image.other_code=True
    if not image.functions:
        image.warnings.append('No sized function symbols: protect before stripping.')
    return image

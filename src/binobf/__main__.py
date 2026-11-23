"""Command-line entry point. Files are validated before any output is committed."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile

from . import __version__
from .binary import BinaryError, BinaryImage


def _seed(value):
    try:
        result=int(value,0)
    except ValueError:
        raise argparse.ArgumentTypeError('seed must be an integer, optionally prefixed by 0x') from None
    if result < 0 or result >= 1 << 256:
        raise argparse.ArgumentTypeError('seed must be between 0 and 2^256-1')
    return result


def _parser():
    p=argparse.ArgumentParser(prog='binobf',description='Selective ARM64 native-code and data obfuscation.')
    p.add_argument('--version',action='version',version='binobf '+__version__)
    sub=p.add_subparsers(dest='command',required=True)
    inspect=sub.add_parser('inspect',help='inspect supported binary formats without executing the input')
    inspect.add_argument('input',type=Path); inspect.add_argument('--json',action='store_true')
    protect=sub.add_parser('protect',help='diversify selected pure-u32 leaf functions in an existing binary')
    protect.add_argument('input',type=Path)
    protect.add_argument('-o','--output',type=Path,required=True)
    protect.add_argument('--function',action='append',required=True,help='exact symbol (repeatable)')
    protect.add_argument('--abi',choices=['u32x2'],default='u32x2',help='selected functions must be uint32_t(uint32_t,uint32_t)')
    protect.add_argument('--sign',choices=['none','ad-hoc'],default='none',help='ad-hoc re-sign modified Mach-O on macOS')
    virtualize=sub.add_parser('virtualize',help='replace all functions of a dedicated ARM64 object with private bytecode interpreters')
    virtualize.add_argument('input',type=Path)
    virtualize.add_argument('-o','--output',type=Path,required=True)
    virtualize.add_argument('--abi',choices=['u32x2'],required=True)
    virtualize.add_argument('--cc',help='C compiler executable, not a shell command')
    virtualize.add_argument('--target',choices=['arm64-apple-macos','aarch64-linux-gnu'],help='explicit Clang cross-compilation target')
    virtualize.add_argument('--emit-c',type=Path,help='also save generated C for private build diagnostics')
    data=sub.add_parser('pack-data',help='encode any data file as a paged, allocation-free C accessor')
    data.add_argument('input',type=Path)
    data.add_argument('-o','--output',type=Path,required=True,help='generated .c path')
    data.add_argument('--header',type=Path,help='generated header path (default: output with .h extension)')
    data.add_argument('--symbol',required=True,help='C identifier prefix of the size/read functions')
    data.add_argument('--block-size',type=int,default=4096)
    data.add_argument('--notice-ja',action='store_true',help='embed an ordinary Japanese license notice; not an AI security mechanism')
    for cmd in (protect,virtualize,data):
        cmd.add_argument('--seed',type=_seed,help='reproducible diversification seed; generated securely if omitted')
        cmd.add_argument('--force',action='store_true',help='replace an existing output, never the input')
        cmd.add_argument('--report',type=Path,help='optional private JSON build summary; no decoder maps')
    return p


def _check_output(path,source,force):
    if path.resolve() == source.resolve():
        raise ValueError('in-place modification is prohibited; choose a distinct output')
    if path.exists():
        if os.path.samefile(path,source):
            raise ValueError('output is a hard link to the input')
        if not force:
            raise ValueError(f'output exists: {path}; use --force to replace it')
        if path.is_dir():
            raise ValueError(f'output is a directory: {path}')
    if not path.parent.is_dir():
        raise ValueError(f'output directory does not exist: {path.parent}')


def _atomic(path,data,mode=0o644):
    fd,name=tempfile.mkstemp(prefix='.binobf-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.chmod(name,mode)
        os.replace(name,path)
    finally:
        if os.path.exists(name): os.unlink(name)


def _report(path,report,source,force):
    if path is not None:
        _check_output(path,source,force)
        _atomic(path,(json.dumps(report,indent=2,sort_keys=True)+'\n').encode())


def _info(image):
    from .vm import FunctionSpec, decode_arm64_u32
    functions=[]
    for f in image.functions:
        supported=f.safe; reason=f.reason
        if supported:
            try:
                decode_arm64_u32(FunctionSpec(f.name,f.code,f.address))
            except ValueError as e:
                supported=False; reason=str(e)
        functions.append({'name':f.name,'address':f.address,'file_offset':f.offset,'bytes':f.size,'eligible_u32x2':supported,'reason':reason})
    return {'format':image.format,'architecture':'arm64','kind':image.kind,'signed':image.has_signature,
            'functions':functions,'warnings':image.warnings}


def _protect(args,seed):
    from .vm import FunctionSpec, native_remap
    image=BinaryImage.read(args.input)
    chosen=image.select(args.function)
    if image.has_signature and args.sign=='none':
        raise ValueError('input has a code signature: use --sign ad-hoc on macOS, then apply your distribution signature after protection')
    if args.sign!='none' and (image.format!='macho' or platform.system()!='Darwin'):
        raise ValueError('--sign ad-hoc requires a Mach-O input and macOS codesign')
    output=bytearray(image.data); reports=[]; total=0
    for index,f in enumerate(chosen):
        child=int.from_bytes(hashlib.sha256(str(seed).encode()+b'\0'+f.name.encode()).digest(),'big')
        transformed,stats=native_remap(FunctionSpec(f.name,f.code,f.address),seed=child)
        if len(transformed)!=f.size:
            raise RuntimeError('internal error: native transform changed function size')
        count=sum(a!=b for a,b in zip(f.code,transformed))
        output[f.offset:f.offset+f.size]=transformed
        reports.append({'name':f.name,'bytes':f.size,'changed_bytes':count,**stats})
        total+=count
    if total==0:
        raise ValueError('selected functions have no eligible diversification; no output was written')
    if BinaryImage.read(args.input).data != image.data:
        raise ValueError('input changed during transformation')
    # Parse the complete result again before signing or committing it.
    from .binary import parse
    parse(output)
    mode=stat.S_IMODE(args.input.stat().st_mode)&0o777
    if args.sign=='ad-hoc':
        codesign=shutil.which('codesign')
        if not codesign: raise ValueError('codesign is unavailable')
        with tempfile.TemporaryDirectory(prefix='.binobf-sign-',dir=args.output.parent) as directory:
            staged=Path(directory)/'protected'
            staged.write_bytes(output); staged.chmod(mode)
            subprocess.run([codesign,'--force','--sign','-',str(staged)],check=True,capture_output=True,text=True)
            subprocess.run([codesign,'--verify','--strict',str(staged)],check=True,capture_output=True,text=True)
            output=staged.read_bytes()
    _atomic(args.output,output,mode)
    return {'operation':'native-diversification','format':image.format,'functions':reports,'input_sha256':hashlib.sha256(image.data).hexdigest(),'output_sha256':hashlib.sha256(output).hexdigest(),'encryption':False}


def _virtualize(args,seed):
    from .vm import FunctionSpec, generate_c
    image=BinaryImage.read(args.input)
    functions=image.virtualizable()
    specs=[]
    for f in functions:
        name=f.name[1:] if image.format=='macho' and f.name.startswith('_') else f.name
        specs.append(FunctionSpec(name,f.code,f.address))
    generated=generate_c(specs,seed=seed)
    if args.emit_c:
        _check_output(args.emit_c,args.input,args.force)
        if args.emit_c.resolve()==args.output.resolve():
            raise ValueError('--emit-c and -o must be different files')
    cc=args.cc or os.environ.get('CC') or shutil.which('cc')
    if not cc or not shutil.which(cc):
        raise ValueError('a C99 compiler is required; pass --cc /path/to/clang')
    host_arm=platform.machine().lower() in ('arm64','aarch64')
    native=(image.format=='macho' and platform.system()=='Darwin' and host_arm) or (image.format=='elf' and platform.system()=='Linux' and host_arm)
    if not native and not args.target:
        raise ValueError('object compilation must match ARM64 input; run on the target host or supply a Clang --target')
    if args.target and (args.target.startswith('arm64-apple') != (image.format=='macho')):
        raise ValueError('--target does not match the input object format')
    with tempfile.TemporaryDirectory(prefix='.binobf-vm-',dir=args.output.parent) as directory:
        c=Path(directory)/'protected.c'; obj=Path(directory)/'protected.o'
        c.write_text(generated.source,encoding='utf-8')
        command=[cc,'-std=c99','-O2','-fno-lto','-fvisibility=hidden','-c',str(c),'-o',str(obj)]
        if args.target:
            command[1:1]=['--target='+args.target]
        subprocess.run(command,check=True,capture_output=True,text=True)
        replacement=BinaryImage.read(obj)
        if replacement.format!=image.format or replacement.kind!='object':
            raise ValueError('compiler produced an unexpected architecture or object format')
        actual={f.name for f in replacement.functions if f.external}
        wanted={f.name for f in functions}
        if not wanted.issubset(actual):
            raise ValueError('compiler did not preserve all required public function symbols')
        compiled=obj.read_bytes()
    _atomic(args.output,compiled)
    if args.emit_c:
        _atomic(args.emit_c,generated.source.encode())
    return {'operation':'private-bytecode','input_sha256':hashlib.sha256(image.data).hexdigest(),
            'output_sha256':hashlib.sha256(compiled).hexdigest(),'functions':[f.name for f in functions],
            'encryption':False,'details':generated.manifest}


def _pack(args,seed):
    from .assets import pack,JAPANESE_NOTICE
    header=args.header or args.output.with_suffix('.h')
    _check_output(header,args.input,args.force)
    if header.resolve()==args.output.resolve():
        raise ValueError('C source and header output paths must be different')
    packed=pack(args.input.read_bytes(),args.symbol,seed=seed,block_size=args.block_size,notice=JAPANESE_NOTICE if args.notice_ja else None)
    _atomic(args.output,packed.source.encode())
    _atomic(header,packed.header.encode())
    return {'operation':'paged-data',**packed.statistics,'symbol':args.symbol,'notice_language':'ja' if args.notice_ja else None}


def main(argv=None):
    args=_parser().parse_args(argv)
    try:
        if not args.input.is_file():
            raise ValueError(f'input is not a file: {args.input}')
        if args.command=='inspect':
            info=_info(BinaryImage.read(args.input))
            if args.json:
                print(json.dumps(info,indent=2))
            else:
                print(f"{info['format']} arm64 {info['kind']}; {len(info['functions'])} named functions; signed={info['signed']}")
                for f in info['functions']:
                    state='eligible u32x2' if f['eligible_u32x2'] else 'unsupported: '+f['reason']
                    print(f"  {f['name']}: {f['bytes']} bytes; {state}")
                for warning in info['warnings']: print('  '+warning)
            return 0
        _check_output(args.output,args.input,args.force)
        if args.command=='pack-data' and args.header is None:
            args.header=args.output.with_suffix('.h')
        auxiliary=[p for p in (args.report,getattr(args,'emit_c',None),getattr(args,'header',None)) if p is not None]
        for path in auxiliary:
            _check_output(path,args.input,args.force)
        paths=[args.output.resolve()]+[p.resolve() for p in auxiliary]
        if len(paths)!=len(set(paths)):
            raise ValueError('all output paths must be distinct')
        seed=args.seed if args.seed is not None else secrets.randbits(128)
        if args.command=='protect': report=_protect(args,seed)
        elif args.command=='virtualize': report=_virtualize(args,seed)
        else: report=_pack(args,seed)
        _report(args.report,report,args.input,args.force)
        print(f"binobf: {report['operation']} -> {args.output}")
        return 0
    except subprocess.CalledProcessError as e:
        print('binobf: external tool failed: '+(e.stderr or e.stdout or str(e)).strip(),file=sys.stderr)
        return 2
    except (ValueError,OSError) as e:
        print('binobf: '+str(e),file=sys.stderr)
        return 2


if __name__=='__main__':
    raise SystemExit(main())

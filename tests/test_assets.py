import ctypes
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from binobf.assets import pack,JAPANESE_NOTICE
from test_cli import cli


class AssetTests(unittest.TestCase):
    def test_native_generated_reader_roundtrip_and_bounds(self):
        compiler=shutil.which('cc')
        self.assertIsNotNone(compiler,'C compiler required for release validation')
        rng=random.Random(84)
        data=b'binobf asset test\0'+bytes(rng.randrange(256) for _ in range(8221))
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            generated=pack(data,'example_asset',seed=11,block_size=256,notice=JAPANESE_NOTICE)
            (root/'asset.c').write_text(generated.source)
            self.assertNotIn('binobf asset test',generated.source)
            lib=root/('asset.dylib' if sys.platform=='darwin' else 'asset.so')
            subprocess.run([compiler,'-std=c99','-O2','-Wall','-Wextra','-Werror','-shared','-fPIC',str(root/'asset.c'),'-o',str(lib)],check=True,capture_output=True)
            native=ctypes.CDLL(str(lib))
            native.example_asset_size.restype=ctypes.c_size_t
            native.example_asset_read.argtypes=[ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t]
            native.example_asset_read.restype=ctypes.c_int
            self.assertEqual(native.example_asset_size(),len(data))
            cases=[(0,len(data)),(0,0),(len(data),0),(255,4),(256,257),(4095,4098),(len(data)-1,1)]
            cases += [(offset:=rng.randrange(len(data)),rng.randrange(len(data)-offset+1)) for _ in range(250)]
            for offset,n in cases:
                out=ctypes.create_string_buffer(n+1)
                self.assertEqual(native.example_asset_read(offset,out,n),0)
                self.assertEqual(out.raw[:n],data[offset:offset+n])
                self.assertEqual(out.raw[n:],b'\0')
            marker=ctypes.create_string_buffer(b'untouched')
            for offset,n in [(len(data)+1,0),(len(data),1),(1,ctypes.c_size_t(-1).value)]:
                self.assertEqual(native.example_asset_read(offset,marker,n),-1)
                self.assertEqual(marker.value,b'untouched')
            self.assertEqual(native.example_asset_read(0,None,1),-1)
            self.assertEqual(native.example_asset_read(len(data),None,0),0)
            library_bytes=lib.read_bytes()
            self.assertIn(JAPANESE_NOTICE.encode(),library_bytes)
            self.assertNotIn(data,library_bytes)

    def test_seeds_repeat_and_change_representation(self):
        data=bytes(range(256))*2
        first=pack(data,'sample',seed=1,block_size=64)
        self.assertEqual(first,pack(data,'sample',seed=1,block_size=64))
        self.assertNotEqual(first.source,pack(data,'sample',seed=2,block_size=64).source)
        self.assertFalse(first.statistics['encryption'])

    def test_cli_does_not_overwrite_input_or_collide_outputs(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); source=root/'input.bin'; source.write_bytes(b'hello asset')
            output=root/'packed.c'
            bad=cli('pack-data',source,'-o',output,'--symbol','asset','--report',root/'packed.h')
            self.assertNotEqual(bad.returncode,0)
            self.assertFalse(output.exists())
            good=cli('pack-data',source,'-o',output,'--symbol','asset','--notice-ja','--seed','42')
            self.assertEqual(good.returncode,0,good.stderr)
            self.assertTrue(output.with_suffix('.h').exists())
            self.assertEqual(source.read_bytes(),b'hello asset')
            repeat=cli('pack-data',source,'-o',output,'--symbol','asset')
            self.assertNotEqual(repeat.returncode,0)
            in_place=cli('pack-data',source,'-o',source,'--symbol','asset','--force')
            self.assertNotEqual(in_place.returncode,0)
            self.assertEqual(source.read_bytes(),b'hello asset')

    def test_invalid_sizes_and_symbols_are_rejected(self):
        for size in (0,16,65,131072):
            with self.assertRaises(ValueError): pack(b'data','asset',seed=1,block_size=size)
        with self.assertRaises(ValueError): pack(b'','asset',seed=1)
        with self.assertRaises(ValueError): pack(b'data','bad;name',seed=1)

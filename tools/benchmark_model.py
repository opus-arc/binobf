#!/usr/bin/env python3
"""Paired native f64-dot benchmarks; synthetic finite f32 input by default.

This measures a generated numeric kernel, not an application's audio engine.
Cold preparation is reported separately from hot row evaluation. No input
model or generated private integration material is retained by this tool.
"""
from array import array
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from binobf.model import MAX_BYTES, compile_model


def _output_target(output, source, force):
    if output is None:
        return
    if source is not None and (output.resolve() == source.resolve()
                              or (output.exists() and source.exists() and os.path.samefile(output, source))):
        raise ValueError('output must not replace or alias the input model')
    if output.is_dir() or not output.parent.is_dir():
        raise ValueError('output must be a file in an existing directory')
    if (output.exists() or output.is_symlink()) and not force:
        raise ValueError('output already exists; use --force to replace it')


def _write_result(path, text):
    descriptor, temporary = tempfile.mkstemp(prefix='.binobf-bench-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


_BASELINE = r'''#include <stddef.h>
#include <stdint.h>
#include <string.h>
typedef struct { uint64_t tag; double weights[@CHANNELS@]; } baseline_prepared;
static const unsigned char original_data[] =
@PAYLOAD@;
static inline float original_load(const unsigned char *p) {
    uint32_t bits=(uint32_t)p[0] | ((uint32_t)p[1]<<8)
                 | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
    float value; memcpy(&value,&bits,4); return value;
}
__attribute__((noinline))
int baseline_prepare(const float *weights, size_t count, baseline_prepared *prepared) {
    baseline_prepared next;
    if (!weights || !prepared || count != @CHANNELS@u) return -1;
    for (size_t i=0; i<@CHANNELS@u; ++i) {
        uint32_t bits; float value;
        memcpy(&bits, weights+i, 4);
        if ((bits & UINT32_C(0x7f800000)) == UINT32_C(0x7f800000)) return -1;
        memcpy(&value, &bits, 4);
        next.weights[i] = (double)value;
    }
    next.tag = UINT64_C(0xb4539986ab7451f3);
    *prepared = next;
    return 0;
}
__attribute__((noinline))
int baseline_evaluate(size_t row, const baseline_prepared *prepared, double *out) {
    const unsigned char *p; double sum = 0.0;
    if (row >= @ROWS@u || !prepared || !out || prepared->tag != UINT64_C(0xb4539986ab7451f3)) return -1;
    p = original_data + row * @CHANNELS@u * 4u;
@OPERATIONS@
    *out = sum;
    return 0;
}
'''

_PREPARE = r'''#include "model.h"
/* Benchmark-only wrapper. Production prepare remains static inline. */
__attribute__((noinline))
int benchmark_prepare(const float *weights, size_t count, bench_model_prepared *prepared) {
    return bench_model_prepare(weights, count, prepared);
}
'''

_DRIVER = r'''#define _POSIX_C_SOURCE 200809L
#include "model.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
typedef struct { uint64_t tag; double weights[@CHANNELS@]; } baseline_prepared;
extern int baseline_evaluate(size_t, const baseline_prepared *, double *);
extern int baseline_prepare(const float *, size_t, baseline_prepared *);
extern int benchmark_prepare(const float *, size_t, bench_model_prepared *);
static volatile double sink;
static double now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) abort();
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}
#define HOT_TIMER(NAME, TYPE, EVAL) \
static double NAME(const TYPE *ctx, size_t rows, size_t repeats) { \
    double value, sum=0.0, start=now(); \
    for (size_t repeat=0; repeat<repeats; ++repeat) \
        for (size_t row=0; row<rows; ++row) { \
            if (EVAL(row,ctx,&value)) abort(); \
            sum += value; \
        } \
    double elapsed=now()-start; sink=sum; return elapsed; \
}
HOT_TIMER(hot_baseline, baseline_prepared, baseline_evaluate)
HOT_TIMER(hot_model, bench_model_prepared, bench_model_evaluate)
#define COLD_TIMER(NAME, TYPE, PREPARE, FIELD) \
static double NAME(const float *sets, size_t repeats) { \
    TYPE ctx; double sum=0.0, start=now(); \
    for (size_t i=0; i<repeats; ++i) { \
        if (PREPARE(sets+(i%64u)*@CHANNELS@u,@CHANNELS@u,&ctx)) abort(); \
        sum += ctx.FIELD[0]; \
    } \
    double elapsed=now()-start; sink=sum; return elapsed; \
}
COLD_TIMER(cold_baseline, baseline_prepared, baseline_prepare, weights)
COLD_TIMER(cold_model, bench_model_prepared, benchmark_prepare, opaque_state)
static void print_times(const double *values) {
    for (size_t i=0; i<@ROUNDS@u; ++i) printf("%s%.0f",i ? "," : "",values[i]);
}
int main(int argc, char **argv) {
    const size_t rows=@ROWS@u, count=rows*@CHANNELS@u;
    float *matrix=(float *)malloc(count*sizeof(float));
    float weight_sets[64u*@CHANNELS@u]; uint32_t state=UINT32_C(0x3912abcd);
    bench_model_prepared model; baseline_prepared base;
    long double squares=0.0L, reference_squares=0.0L;
    double max_absolute=0.0, max_scaled=0.0; size_t different=0;
    if (argc!=2 || !matrix) return 2;
    FILE *file=fopen(argv[1],"rb");
    if (!file || fread(matrix,sizeof(float),count,file)!=count || fclose(file)) return 3;
    for (size_t i=0; i<64u*@CHANNELS@u; ++i) {
        state ^= state<<13; state ^= state>>17; state ^= state<<5;
        weight_sets[i]=(float)((int)(state & UINT32_C(0x01ffffff))-16777216)*(1.0f/16777216.0f);
    }
    if (baseline_prepare(weight_sets,@CHANNELS@u,&base) || bench_model_prepare(weight_sets,@CHANNELS@u,&model)) return 4;
    for (size_t row=0; row<rows; ++row) {
        double a,b; long double reference=0.0L,scale=0.0L;
        if (baseline_evaluate(row,&base,&a) || bench_model_evaluate(row,&model,&b)) return 5;
        for (size_t c=0; c<@CHANNELS@u; ++c) {
            long double p=(long double)matrix[row*@CHANNELS@u+c]*(long double)weight_sets[c];
            reference+=p; scale+=fabsl(p);
        }
        long double error=(long double)b-reference;
        if (!isfinite(a) || !isfinite(b) || fabsl(error)>4.0L*@CHANNELS@u*DBL_EPSILON*scale) return 6;
        double absolute=fabs(b-a);
        if (absolute>max_absolute) max_absolute=absolute;
        if (scale && (double)(fabsl(error)/scale)>max_scaled) max_scaled=(double)(fabsl(error)/scale);
        squares+=error*error; reference_squares+=reference*reference; different+=a!=b;
    }
    printf("{\"validation\":{\"rows\":%zu,\"long_double_mantissa_bits\":%d,"
           "\"different_from_baseline\":%zu,\"max_absolute_vs_baseline\":%.17g,"
           "\"max_scaled_error_vs_reference\":%.17g,\"relative_rms_error_vs_reference\":%.17g},"
           "\"workloads\":[",rows,LDBL_MANT_DIG,different,max_absolute,max_scaled,
           reference_squares ? (double)sqrtl(squares/reference_squares) : 0.0);
    for (int work=0; work<3; ++work) {
        const size_t scan=work==1 ? rows : 1u;
        const size_t repeats=(@CALLS@u+scan-1u)/scan;
        const size_t warm=(repeats/4u) ? repeats/4u : 1u;
        double a[@ROUNDS@],b[@ROUNDS@];
        for (int i=0; i<2; ++i) {
            if (work==2) { cold_baseline(weight_sets,warm); cold_model(weight_sets,warm); }
            else { hot_baseline(&base,scan,warm); hot_model(&model,scan,warm); }
        }
        for (size_t round=0; round<@ROUNDS@u; ++round) {
            if (work==2) {
                if (round&1u) { b[round]=cold_model(weight_sets,repeats); a[round]=cold_baseline(weight_sets,repeats); }
                else { a[round]=cold_baseline(weight_sets,repeats); b[round]=cold_model(weight_sets,repeats); }
            } else {
                if (round&1u) { b[round]=hot_model(&model,scan,repeats); a[round]=hot_baseline(&base,scan,repeats); }
                else { a[round]=hot_baseline(&base,scan,repeats); b[round]=hot_model(&model,scan,repeats); }
            }
        }
        printf("%s{\"name\":\"%s\",\"calls_per_round\":%zu,\"baseline_ns\":[",work ? "," : "",
               work==0 ? "one-row" : (work==1 ? "full-matrix" : "cold-prepare"),scan*repeats);
        print_times(a); printf("],\"model_ns\":["); print_times(b); printf("]}");
    }
    printf("]}\n"); free(matrix); return sink==HUGE_VAL;
}
'''


def benchmark(args):
    if not 2 <= args.channels <= 16 or not 1 <= args.rows <= MAX_BYTES // (4 * args.channels):
        raise ValueError('channels must be 2..16 and synthetic row count must fit 64 MiB')
    if not 3 <= args.rounds <= 21 or not 10000 <= args.calls <= 100000000:
        raise ValueError('rounds must be 3..21; calls must be 10,000..100,000,000')
    if not 0 <= args.seed < (1 << 256):
        raise ValueError('seed must be between 0 and 2^256-1')
    _output_target(args.output, args.input, args.force)
    if args.input:
        with args.input.open('rb') as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError('input exceeds the 64 MiB model limit')
        origin = 'supplied finite f32 file'
    else:
        rng = random.Random(args.seed)
        raw = b''.join(struct.pack('<f', rng.uniform(-1.0, 1.0))
                       for _ in range(args.rows * args.channels))
        origin = 'deterministic synthetic finite f32'
    generated = compile_model(raw, 'bench_model', args.channels, seed=args.seed)
    rows = generated.statistics['rows']
    compiler = shutil.which(args.compiler)
    if compiler is None:
        raise ValueError('C compiler is unavailable')
    flags = ['-std=c99', '-O2', '-Wall', '-Wextra', '-Werror', '-fno-fast-math', '-fno-lto']
    replacements = {'@ROWS@': str(rows), '@CHANNELS@': str(args.channels),
                    '@ROUNDS@': str(args.rounds), '@CALLS@': str(args.calls),
                    '@OPERATIONS@': '\n'.join(f'    sum += (double)original_load(p + {4*i}u) * prepared->weights[{i}];'
                                               for i in range(args.channels)),
                    '@PAYLOAD@': '\n'.join('    "' + ''.join(f'\\x{x:02x}' for x in raw[i:i+64]) + '"'
                                             for i in range(0, len(raw), 64))}
    def expand(text):
        for token, value in replacements.items():
            text = text.replace(token, value)
        return text
    with tempfile.TemporaryDirectory(prefix='binobf-model-benchmark-') as directory:
        work = Path(directory)
        for name, content in [('model.c', generated.source), ('model.h', generated.header),
                              ('baseline.c', expand(_BASELINE)), ('prepare.c', _PREPARE),
                              ('driver.c', expand(_DRIVER))]:
            (work / name).write_text(content)
        native = array('I'); native.frombytes(raw)
        if sys.byteorder != 'little':
            native.byteswap()
        (work / 'reference.f32').write_bytes(native.tobytes())
        command = [compiler, *flags, *[str(work / name) for name in ('model.c', 'baseline.c', 'prepare.c', 'driver.c')],
                   '-lm', '-o', str(work / 'bench')]
        subprocess.run(command, check=True, capture_output=True, text=True)
        result = json.loads(subprocess.run([str(work / 'bench'), str(work / 'reference.f32')],
                                           check=True, capture_output=True, text=True).stdout)
    for workload in result['workloads']:
        ratios = [m / b for m, b in zip(workload['model_ns'], workload['baseline_ns'])]
        workload.update(paired_model_over_baseline=ratios, median_model_over_baseline=statistics.median(ratios),
                        median_baseline_ns_per_call=statistics.median(workload['baseline_ns']) / workload['calls_per_round'],
                        median_model_ns_per_call=statistics.median(workload['model_ns']) / workload['calls_per_round'])
    result.update(platform=platform.platform(), compiler=subprocess.run([compiler, '--version'], capture_output=True, text=True).stdout.splitlines()[0],
                  flags=flags, input_origin=origin, input_bytes=len(raw), input_sha256=hashlib.sha256(raw).hexdigest(),
                  rows=rows, channels=args.channels, rounds=args.rounds, statistics=generated.statistics,
                  warmup='Two untimed quarter-length runs of each variant before each workload.',
                  hot_baseline='Original static contiguous f32 payload; same loads, binary64 dot and row/null/context-tag checks, separate TU, no LTO.',
                  cold_baseline='Same finite-f32 argument validation and f64 context initialization, without the paired transform.',
                  cold_measurement='Separate noinline benchmark wrappers around preparation. Production static-inline preparation can optimize differently.',
                  limits=['Host microbenchmark, not a complete application or a performance guarantee.',
                          'Validation and preparation are excluded from the hot evaluation timings.',
                          'Signed dyadic representation remains reversible and permits component reuse.'])
    text = json.dumps(result, indent=2) + '\n'
    if args.output:
        _output_target(args.output, args.input, args.force)
        _write_result(args.output, text)
    return text


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, help='optional row-major little-endian finite f32 model')
    parser.add_argument('--channels', type=int, default=4)
    parser.add_argument('--rows', type=int, default=32768, help='synthetic rows when no input is supplied')
    parser.add_argument('--seed', type=lambda value: int(value, 0), default=20261123)
    parser.add_argument('--rounds', type=int, default=7)
    parser.add_argument('--calls', type=int, default=5000000, help='minimum calls per timed round')
    parser.add_argument('--compiler', default='cc')
    parser.add_argument('--output', type=Path, help='optional JSON output; stdout is always printed')
    parser.add_argument('--force', action='store_true')
    args = parser.parse_args(argv)
    try:
        print(benchmark(args), end='')
        return 0
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f'benchmark_model: {error}', file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr, file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

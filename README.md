# binobf

binobf is a selective ARM64 binary obfuscation toolkit. It reads compiled
machine code, diversifies eligible native functions, and can replace isolated
integer functions with per-function bytecode interpreters. It also packs
arbitrary binary assets into a shuffled, encoded page representation. The 0.2
development branch adds per-bucket data programs and a paired numeric-model
representation that is consumed directly by a generated dot-product kernel.

The project is application-independent. It contains no piano model, soundbank,
application-specific rules, or third-party proprietary binaries.

**Version 0.2.0-dev is research code, not a new stable protection grade.** It
provides concrete transformations and correctness checks, not a claim of
unbreakable encryption, universal executable virtualization, or AI resistance.
The published 0.1.0 release remains available separately. The new data modes
require rebuilding the application; they do not wrap an arbitrary released CLI.

[中文说明](README.zh-CN.md)

## Build

```sh
sh ./build.sh --test-only
python3 ./bin/binobf --version
```

Python 3.10 or later is required. Binary inspection and native diversification
use only the Python standard library. A C99 compiler is required for VM object
generation, generated asset code, and runtime tests. On macOS, install the
command-line developer tools.

To build and verify source archives on any supported development host:

```sh
sh ./build.sh --platform source
```

To build the macOS release on an **actual Apple Silicon macOS host**:

```sh
sh ./build.sh --platform macos-arm64
```

The release gate executes original and transformed ARM64 code, links and runs
virtualized objects, verifies ad-hoc code signatures, and repeats the tests
from both extracted archives. A source build on another CPU does not establish
native ARM64 correctness. Release archives contain the frontend, implementation,
examples, and tests; they are not self-contained Python runtimes.

## Install

Extract a release archive and run `./bin/binobf --help`. Add that archive's `bin`
directory to your `PATH`, or use the full path. Verify `SHA256SUMS` before use.
There is no Homebrew formula in this first version.

## Usage

### Inspect and select

```sh
binobf inspect engine.o
binobf inspect engine --json
```

Supported containers are thin, little-endian ARM64 Mach-O objects, executables
and dynamic libraries, and AArch64 ELF64 objects, executables and shared objects.
Named function symbols must be available. Run protection **before stripping**.
Inspection never executes the input.

A function is eligible only if its complete instruction sequence satisfies the
strict profile below. Unsupported code remains a visible reason in inspection;
a requested unsupported transformation fails instead of silently copying it.

### Native diversification

```sh
binobf protect engine.o -o engine.protected.o --function control_step
# Re-link the application with engine.protected.o.
```

For a signed macOS executable:

```sh
binobf protect engine -o engine.protected --function control_step --sign ad-hoc
```

This mode permutes eligible W8–W15 temporary registers throughout each selected
function. It preserves instruction count, function size, addresses and operation
order. It does not virtualize hot code or modify floating-point/SIMD operations.
The default seed is freshly generated; `--seed 1234` makes a build repeatable.
Repeat `--function` to select several functions.

**This mode supplies native-code diversity, not substantial semantic hiding by
itself.** Register normalization can remove much of its effect. Unselected
functions remain byte-for-byte unchanged before optional signing. Equal
instruction count is not a measured zero-overhead guarantee.

### Selective virtualization

Put the small integer functions you want to protect in a dedicated object:

```sh
cc -O2 -fno-lto -c examples/control.c -o control.o
binobf inspect control.o
binobf virtualize control.o -o control.protected.o --abi u32x2
cc application.o control.protected.o -o application
```

This is a **compiled-object replacement**, not a source obfuscator. The translator
reads the original object's ARM64 instruction words. It generates and compiles
new C99 wrappers with the same exported function names, per-function opcode
assignments and register layouts, and encoded instruction operands. The output
contains the VM implementation and its bytecode, not a preserved copy of the
original native function body. No JIT or writable-executable memory is needed.

All functions in the dedicated input object must be eligible. Additional data,
local code, aliases, weak definitions, and text relocations are rejected rather
than discarded. Native compilation must match the input format and ARM64 CPU.
For an appropriately configured Clang cross compiler, use `--cc /path/to/clang`
and `--target arm64-apple-macos` or `--target aarch64-linux-gnu`.

Use virtualization for **infrequently called control/selection logic**. The
interpreter adds work to every operation; do not put sample-by-sample DSP,
rendering loops, or other measured hot paths into it by default. Benchmark the
whole application under its intended workload.

The optional `--emit-c private-vm.c` retains generated implementation details for
local diagnostics. Keep that file and any reproducible seed/build report private
when distributing a protected application. Do not enable LTO for the generated
VM translation unit.

### General binary data

```sh
binobf pack-data model.bin -o model.packed.c --symbol model --notice-ja
cc -O2 -fno-lto -c model.packed.c -o model.packed.o
```

This creates `model.packed.c` and `model.packed.h`. Any file format can be used;
no model-specific schema is required. Link the generated object and use:

```c
#include "model.packed.h"
unsigned char block[4096];
if (model_read(offset, block, sizeof block) != 0) {
    /* Invalid range; the destination has not been modified. */
}
```

The generated API exposes `model_size()` and `model_read(offset, output, length)`.
Pages are shuffled and their words reversibly encoded; reads decode only the
requested range into the caller's buffer, with no allocations or global plaintext
cache. Default page size is 4096 bytes; `--block-size` accepts powers of two from
64 to 65536. The first version supports up to 64 MiB per input asset.

**This is data obfuscation, not cryptographic encryption.** A reverser who finds
and reuses the read routine can recover the asset. Decoded buffers and legitimately
observable program outputs remain observable. Link only the packed object; do
not also embed or distribute the original asset. The generated source exposes
the representation and should remain a private build intermediate.

`--notice-ja` embeds a Japanese notice referring to the host application's license
and permitted use. It is an ordinary license notice, not an instruction that can
control an AI system or prevent disclosure. It does not alter binobf's MIT license.

### Diverse data programs (experimental)

```sh
binobf pack-data model.bin -o model.packed.c --symbol model --profile diverse
```

This preserves the `size`/`read` interface and selects eight or sixteen buckets
per build. Each active bucket has its own reversible unsigned-integer program,
page permutation and word placement. There is no global per-page key or page-map
array to copy into an extractor. A decoder written for the legacy representation
must be adapted, or the application reader can be reused directly.

The generated payload uses adjacent escaped C strings, avoiding one integer
initializer expression per stored byte. GCC and Clang support the long combined
literals; a strictly minimal C99 implementation need not. Do not compile these
translation units with `-Wpedantic -Werror` or LTO. The existing `legacy` profile
remains the default for compatibility. This is still a reversible reader, and
the added operations are not free; measure the paths on which it will run.

### Numeric model with a paired consumer (experimental)

```sh
binobf compile-model matrix.f32 -o matrix.compiled.c --symbol matrix --channels 6
cc -std=c99 -O2 -fno-lto -c matrix.compiled.c -o matrix.compiled.o
```

Input consists of finite, little-endian IEEE binary32 values in complete
row-major rows, with 2–16 columns and at most 64 MiB. The generator permutes
columns and applies signed power-of-two scales chosen to preserve every stored
float exactly. It generates the paired weight transformation in a private
integration header and a native row evaluator. Stored model bytes are unchanged
in size, apart from the C string terminator; generated support code adds space.

```c
#include "matrix.compiled.h"
matrix_prepared prepared;
/* Prepare once when these weights change, outside the per-row hot loop. */
if (matrix_prepare(weights, matrix_channels, &prepared) != 0) {
    /* Reject invalid pointers, count, or non-finite weights. */
}
double value;
if (matrix_evaluate(row, &prepared, &value) != 0) {
    /* Reject an invalid row or unprepared/wrong-model context. */
}
```

`prepare` is static inline so it can be compiled into the real consuming code.
The evaluator uses the transformed data directly: it exposes no general
plaintext-byte reader, allocates no memory, and maintains no decoded matrix
cache. Keep the generated C and header private to the application build, and
do not compile or ship the original matrix as well. This interface applies to
row dot products; it does not automatically transform arbitrary DSP algorithms,
stateful filters, neural networks, or existing machine code.

**This removes a convenient plaintext interface, not the ability to reconstruct
the model.** The transformation is mathematically reversible. Basis-weight
queries recover the matrix if the preparation/evaluation path is accessible;
the stored representation and consuming kernel can be reused together. Context
tags catch accidental mixups and are not authentication. Signed column
permutation and dyadic scaling alone are weak against a determined analyst.

Numerical contract: IEEE round-to-nearest, gradual underflow, no fast-math or
reassociation, and successfully prepared, unmodified contexts. Products of f32
inputs and f32 weights are exact in the f64 accumulator; column order changes
summation rounding. For `n` columns, the absolute error against the exact sum is
bounded by `gamma(n-1) * sum(abs(products))`, where
`gamma(k) = k * 2^-53 / (1 - k * 2^-53)`. This is not a bit-identical-output
guarantee or a guarantee of small relative error near cancellation. The generated
code rejects fast-math builds; runtime floating-point modes remain the caller's
responsibility.

### Measure data-access cost

```sh
python3 tools/benchmark_data.py --help
python3 tools/benchmark_data.py
python3 tools/benchmark_model.py
```

The benchmark compares a memcpy control, the legacy reader and the diverse
reader using separate translation units and both sequential and short random
reads. Correctness is checked outside the timed region. It reports the host,
compiler, workload and paired-round results. Ratios apply to those accessors,
not the application's total CPU time or audio latency. Do not infer performance
on Apple Silicon from a Linux x86 host result.

The model benchmark compares the generated evaluator with a native f64 dot
product using the original f32 data and equivalent argument checks. It records
one-row and full-matrix workloads, summation differences, and cold weight
preparation separately. CI records both microbenchmarks on Linux and native
Apple Silicon without using noisy timing ratios as pass/fail thresholds.

## Supported instruction profile

Both code modes currently require complete, straight-line, two-argument unsigned
32-bit leaf functions with ABI `uint32_t f(uint32_t, uint32_t)`. Supported families
include move-wide, logical register/immediate, add/subtract, shifts/rotates,
bitfield, multiply/add/subtract, condition flags, conditional select, and return.

The backend validates instruction encodings, register definitions and condition
flags. It accepts architectural NOP alignment after the final `RET X30`. It
rejects stack access, pointers, memory instructions, calls, branches, 64-bit
arithmetic, FP/SIMD, atomics, system instructions, incoming undefined flags,
platform/callee-saved registers, and instructions outside its whitelist.

Compiler optimizations can select an unsupported instruction even for a small
C function. Inspect the actual object; eligibility is not inferred from C source.
`u32x2` is an explicit ABI contract, not a type recovered from binary symbols.
Handwritten assembly with alternate interior entry points is outside the contract.

## Verification and release

```sh
sh ./build.sh --test-only
sh ./build.sh --platform macos-arm64
```

Tests cover malformed container rejection, function boundaries, relocation and
metadata exclusions, generated-C execution against independent integer references,
asset readback and bounds, native numeric-model behavior and basis-recovery
limitations, reproducible archives, and archive-tamper detection.
macOS CI additionally exercises real ARM64 native and virtualized code, including
post-link transformation and re-signing. A tagged release is published only after
these native tests and archive verification succeed.

Outputs never overwrite the input. Existing outputs require `--force`. A failed
validation produces no transformed output. `--report file.json` saves an optional
private build summary without decoder maps. Standard output does not print the
seed or generated decoder tables.

## Scope and limitations

The 0.2 data research has an explicit negative result: in stripped Linux x86-64
standalone harnesses, the diverse profile removed the tested plaintext
fingerprints and broke a fixed legacy extractor, but reusing the internal reader
still recovered a complete 44 MiB corpus exactly (176/176 records). This is why
the new profile is optional and no stronger confidentiality grade is claimed.
The model tests also demonstrate numeric matrix recovery through basis-weight
queries when its preparation/evaluation interface is available. A separate
stripped-model reverse-analysis trial is incomplete; it is not a passed gate.
These are data-path experiments, not evidence of a protected whole application.

This release establishes a small, auditable implementation with fail-closed
boundaries. It is not a drop-in protector for arbitrary C++, PE/x86, fat Mach-O,
ARM64e, stripped binaries without symbols, or entire existing applications.
It does not automatically discover important algorithms or sensitive data.

Native diversification is modest; VM and asset encodings are recoverable from a
client-controlled process. The interpreter can be analyzed or reused, and memory
can be inspected. No measured claim is made that a professional reverser or an
AI-assisted analyst cannot reconstruct behavior. Raising that cost substantially
requires further backends and independent attack evaluation.

Code modification invalidates an existing signature. `--sign ad-hoc` is for local
verification, not Developer ID distribution or notarization. Apply your normal
Developer ID signing and notarization **after** all transformations. Protecting a
nested binary also requires re-signing its containing bundle. No signing identity
or private key is included in this project.

## License and references

Original implementation: [MIT](LICENSE). See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
for implementation provenance and architecture references. No code from commercial
protectors or third-party obfuscation engines is bundled in this release.

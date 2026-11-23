# Changelog

## 0.2.0-dev — Data-path research

- Add an opt-in `pack-data --profile diverse` with build-specific bucket
  programs and arithmetic page/word layouts, keeping the legacy default.
- Emit diverse payloads as escaped C strings instead of byte initializer lists
  to reduce compiler resource use for large models.
- Add `compile-model` for finite row-major f32 matrices with 2–16 columns:
  exact stored-value transformations, a private inline weight preparation
  routine, and a direct native f64 dot-product consumer without a raw-read API
  or decoded whole-matrix cache.
- Bound input reads at 64 MiB and validate output collisions before generation.
- Add compiled differential/bounds tests, numerical error checks, C++ header
  integration and a negative basis-query recovery test.
- Add a repeatable native data-access benchmark. Keep performance costs and
  successful recovery attacks visible; neither new mode is encryption or an
  established professional/AI-resistant protection tier.

## 0.1.0 — Initial experimental release

- Add bounds-checked ARM64 Mach-O and AArch64 ELF64 container inspection.
- Diversify selected strict-u32 leaf functions without changing code size.
- Replace eligible standalone objects with compiled per-function private-bytecode
  interpreters while preserving the declared two-u32 ABI and export names.
- Add generic paged data encoding with an allocation-free C read interface and
  optional Japanese license notice.
- Reject unsupported instruction encodings, relocations, ambiguous function
  ranges, unsupported exported definitions and input/output collisions.
- Add independent runtime references, adversarial container tests, Apple Silicon
  native execution/signature gates and deterministic release archive verification.

This version does not provide cryptographic encryption, arbitrary executable
virtualization, or a claim of professional/AI-proof reverse-engineering resistance.

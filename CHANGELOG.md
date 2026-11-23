# Changelog

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

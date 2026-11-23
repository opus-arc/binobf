# Third-party notices and implementation provenance

The Python frontend, binary readers, AArch64 decoder, VM emitter, paged asset
encoder, model representation generator, tests and packaging scripts are original code distributed
under the MIT license in this repository. No third-party obfuscator implementation
or proprietary application/model data is vendored.

Python and the C compiler are external build/runtime prerequisites, not bundled
copies. GitHub Actions uses official checkout, Python setup and artifact actions,
pinned by commit in the workflow files. Their own repositories retain their
licenses; those actions are not embedded into the protected application.

Architecture and format references used when designing the implementation:

- Arm A-profile A64 instruction set reference:
  <https://developer.arm.com/documentation/ddi0602/latest>
- Arm AAPCS64 calling convention:
  <https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst>
- Apple's Mach-O format declarations:
  <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h>
- System V ELF generic ABI:
  <https://gabi.xinuos.com/elf/>
- Apple's code signing guidance:
  <https://developer.apple.com/library/archive/technotes/tn2206/>
- Tigress data encoding design documentation (representation changes and
  corresponding operations): <https://tigress.wtf/encodeData.html>
- O-MVLL strings encoding documentation (generated decoding and runtime
  plaintext limitations): <https://obfuscator.re/omvll/passes/strings-encoding/>

These are references to public specifications and platform documentation. They
are not endorsements of binobf or evidence of resistance to reverse engineering.
The 0.2 experiments use these last two documents as design references; no
Tigress or O-MVLL source code is copied or bundled, and their licenses do not
license any part of this repository by implication.

The generated VM runtime and resource accessor are also MIT-licensed original
code. Retain the binobf copyright and MIT notice when redistributing substantial
portions of generated implementation code, as required by that license. This does
not require disclosure of an application's own algorithms or data and does not
change their license.

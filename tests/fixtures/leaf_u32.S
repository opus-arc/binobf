/* Original portable-preprocessor fixture for AArch64 ELF and Mach-O. */
#ifdef __APPLE__
#define NAME(x) _##x
#else
#define NAME(x) x
#endif

.text
.p2align 2
.globl NAME(mix32)
#ifndef __APPLE__
.type mix32, %function
#endif
NAME(mix32):
    add w8, w0, w1
    eor w9, w8, w1
    lsl w10, w9, #5
    add w0, w10, w9
    ret
#ifndef __APPLE__
.size mix32, .-mix32
#endif

.p2align 2
.globl NAME(select32)
#ifndef __APPLE__
.type select32, %function
#endif
NAME(select32):
    cmp w0, w1
    csel w8, w0, w1, hi
    eor w0, w8, w1
    ret
#ifndef __APPLE__
.size select32, .-select32
.section .note.GNU-stack,"",%progbits
#endif

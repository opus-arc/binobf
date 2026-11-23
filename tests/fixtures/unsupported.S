#ifdef __APPLE__
#define NAME(x) _##x
#else
#define NAME(x) x
#endif
.text
.p2align 2
.globl NAME(unsupported_load)
#ifndef __APPLE__
.type unsupported_load, %function
#endif
NAME(unsupported_load):
    ldr w0, [x0]
    ret
#ifndef __APPLE__
.size unsupported_load, .-unsupported_load
.section .note.GNU-stack,"",%progbits
#endif

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

extern uint32_t mix32(uint32_t, uint32_t);
extern uint32_t select32(uint32_t, uint32_t);

static int check(uint32_t x, uint32_t y, uint64_t *digest) {
    uint32_t z = (x + y) ^ y;
    uint32_t expected_mix = (z << 5) + z;
    uint32_t expected_select = ((x > y) ? x : y) ^ y;
    uint32_t actual_mix = mix32(x, y);
    uint32_t actual_select = select32(x, y);
    if (actual_mix != expected_mix || actual_select != expected_select) {
        fprintf(stderr, "semantic mismatch: %08" PRIx32 " %08" PRIx32 "\n", x, y);
        return 0;
    }
    *digest = (*digest ^ actual_mix) * UINT64_C(1099511628211) ^ actual_select;
    return 1;
}

int main(void) {
    static const uint32_t edges[] = {0, 1, 31, 32, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff};
    uint64_t digest = UINT64_C(1469598103934665603);
    for (unsigned a = 0; a < sizeof edges / sizeof edges[0]; ++a)
        for (unsigned b = 0; b < sizeof edges / sizeof edges[0]; ++b)
            if (!check(edges[a], edges[b], &digest)) return 1;
    uint32_t random = UINT32_C(20261123);
    for (unsigned i = 0; i < 10000; ++i) {
        random = random * UINT32_C(1664525) + UINT32_C(1013904223);
        uint32_t x = random;
        random = random * UINT32_C(1664525) + UINT32_C(1013904223);
        if (!check(x, random, &digest)) return 1;
    }
    printf("ok %016" PRIx64 "\n", digest);
    return 0;
}

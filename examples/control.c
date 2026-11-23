/* Small cold-control example, independent of any application or model. */
#include <stdint.h>

uint32_t control_step(uint32_t state, uint32_t event) {
    uint32_t next = state * UINT32_C(1664525) + event + UINT32_C(1013904223);
    return next ^ (next >> 16);
}

uint32_t control_select(uint32_t a, uint32_t b) {
    return a < b ? (a + UINT32_C(17)) ^ b : (b - UINT32_C(23)) ^ a;
}

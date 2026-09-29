#include "lwip/opt.h"
#include "lwip/sys.h"

#include <time.h>

/* Milliseconds from a monotonic clock, for lwIP's timers. */
u32_t sys_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u32_t)((u64_t)ts.tv_sec * 1000u + (u64_t)ts.tv_nsec / 1000000u);
}

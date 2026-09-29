#ifndef CFERRET_ATOMICS_H
#define CFERRET_ATOMICS_H

#include <stdint.h>

/// Atomic accessors for counters in memory shared between the app and the
/// packet tunnel extension (an mmap'd file in the App Group container).

static inline uint64_t ferret_atomic_load_u64(const uint64_t *p) {
    return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

static inline void ferret_atomic_store_u64(uint64_t *p, uint64_t v) {
    __atomic_store_n(p, v, __ATOMIC_RELEASE);
}

static inline uint64_t ferret_atomic_add_u64(uint64_t *p, uint64_t v) {
    return __atomic_add_fetch(p, v, __ATOMIC_ACQ_REL);
}

#endif

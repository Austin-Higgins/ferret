#ifndef FERRET_LWIP_ARCH_CC_H
#define FERRET_LWIP_ARCH_CC_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* Never abort inside the packet tunnel: log and carry on. */
#define LWIP_PLATFORM_DIAG(x)   do { printf x; } while (0)
#define LWIP_PLATFORM_ASSERT(x) do { fprintf(stderr, "lwIP assertion: %s (%s:%d)\n", x, __FILE__, __LINE__); } while (0)

#if defined(__APPLE__)
#define LWIP_RAND() ((u32_t)arc4random())
#else
#define LWIP_RAND() ((u32_t)random())
#endif

#define LWIP_NO_CTYPE_H 0

#endif

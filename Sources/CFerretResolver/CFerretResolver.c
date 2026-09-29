#include "CFerretResolver.h"

#include <string.h>

#if defined(__APPLE__)
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <sys/socket.h>

int ferret_system_dns_servers(char *out, int max) {
    struct __res_state state;
    memset(&state, 0, sizeof(state));
    if (res_ninit(&state) != 0) {
        return 0;
    }
    union res_sockaddr_union servers[16];
    int count = res_getservers(&state, servers, 16);
    int written = 0;
    for (int i = 0; i < count && written < max; i++) {
        const struct sockaddr *sa = (const struct sockaddr *)&servers[i];
        socklen_t len = sa->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
        char host[NI_MAXHOST];
        if (getnameinfo(sa, len, host, sizeof(host), NULL, 0, NI_NUMERICHOST) != 0) {
            continue;
        }
        /* Drop any "%en0" scope suffix. */
        char *percent = strchr(host, '%');
        if (percent) {
            *percent = '\0';
        }
        strncpy(out + written * 64, host, 63);
        out[written * 64 + 63] = 0;
        written++;
    }
    res_ndestroy(&state);
    return written;
}
#else
int ferret_system_dns_servers(char *out, int max) {
    (void)out;
    (void)max;
    return 0;
}
#endif

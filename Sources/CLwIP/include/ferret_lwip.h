#ifndef FERRET_LWIP_H
#define FERRET_LWIP_H

#include <stddef.h>
#include <stdint.h>

/* Ferret's narrow C API over lwIP, so Swift never touches lwIP macros or pbufs.
 * All functions must be called from the same serial queue. lwIP is global:
 * there is one stack per process. Connection handles are opaque pointers;
 * `connection_id` values are chosen by the caller in `accept`. */

typedef struct ferret_tcp_callbacks {
    void *context;
    /* lwIP produced an IP packet for the phone. */
    void (*output)(void *context, const uint8_t *packet, size_t length);
    /* A connection from the phone completed its handshake. Return a non-zero id to
     * accept it, or 0 to reset it. */
    uintptr_t (*accept)(void *context, void *connection);
    /* Data from the phone. A NULL `data` means the phone closed its sending side. */
    void (*received)(void *context, uintptr_t connection_id, const uint8_t *data, size_t length);
    /* The phone acknowledged `length` bytes we sent. */
    void (*sent)(void *context, uintptr_t connection_id, size_t length);
    /* The connection failed or was reset; its handle is already freed. */
    void (*failed)(void *context, uintptr_t connection_id, int error);
} ferret_tcp_callbacks;

typedef struct ferret_tcp_endpoints {
    /* 4 or 16 meaningful bytes. */
    uint8_t local_address[16];
    uint8_t remote_address[16];
    int is_ipv6;
    /* The destination the app connected to (lwIP's "local" side). */
    uint16_t local_port;
    /* The phone's source port. */
    uint16_t remote_port;
} ferret_tcp_endpoints;

/* Starts the stack. Returns 0 on success. Calling twice is an error. */
int ferret_lwip_start(const ferret_tcp_callbacks *callbacks);
void ferret_lwip_stop(void);

/* Feeds one IP packet from the phone into the stack. */
void ferret_lwip_input(const uint8_t *packet, size_t length);

/* Runs lwIP's timers; call every 250 ms. */
void ferret_lwip_check_timeouts(void);

void ferret_tcp_get_endpoints(void *connection, ferret_tcp_endpoints *out);

/* Queues data for the phone. Returns bytes accepted (may be less than length). */
size_t ferret_tcp_write(void *connection, const uint8_t *data, size_t length);
size_t ferret_tcp_send_buffer_space(void *connection);
void ferret_tcp_flush(void *connection);

/* Tells lwIP the app consumed `length` bytes, reopening the receive window. */
void ferret_tcp_consumed(void *connection, size_t length);

/* Half-close: no more data towards the phone. */
int ferret_tcp_shutdown_write(void *connection);
/* Full close. Returns 0 on success; on failure the caller should abort. */
int ferret_tcp_close(void *connection);
void ferret_tcp_abort(void *connection);

/* Number of live TCP connections, for memory guard rails. */
int ferret_tcp_active_count(void);

#endif

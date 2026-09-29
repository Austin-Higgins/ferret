#include "ferret_lwip.h"

#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/ip4_frag.h"
#include "lwip/ip6_frag.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"

#include <string.h>

struct tcp_pcb_listen *ferret_listen_any_pcb = NULL;

static struct netif ferret_netif;
static ferret_tcp_callbacks ferret_callbacks;
static int ferret_started = 0;
static int ferret_active = 0;
/* Scratch buffer for flattening pbuf chains towards the phone. */
static uint8_t ferret_out_buffer[65536];

struct netif *ferret_route_netif(void) {
    return ferret_started ? &ferret_netif : NULL;
}

static void emit(struct pbuf *p) {
    if (!ferret_callbacks.output || p->tot_len > sizeof(ferret_out_buffer)) {
        return;
    }
    u16_t copied = pbuf_copy_partial(p, ferret_out_buffer, p->tot_len, 0);
    ferret_callbacks.output(ferret_callbacks.context, ferret_out_buffer, copied);
}

static err_t netif_output4(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr) {
    LWIP_UNUSED_ARG(netif);
    LWIP_UNUSED_ARG(ipaddr);
    emit(p);
    return ERR_OK;
}

static err_t netif_output6(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr) {
    LWIP_UNUSED_ARG(netif);
    LWIP_UNUSED_ARG(ipaddr);
    emit(p);
    return ERR_OK;
}

static err_t netif_setup(struct netif *netif) {
    netif->name[0] = 'f';
    netif->name[1] = 't';
    netif->mtu = 1500;
    netif->output = netif_output4;
    netif->output_ip6 = netif_output6;
    netif->flags = NETIF_FLAG_LINK_UP;
    return ERR_OK;
}

/* --- TCP callbacks -------------------------------------------------------- */

static err_t on_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    uintptr_t id = (uintptr_t)arg;
    LWIP_UNUSED_ARG(pcb);
    if (p == NULL) {
        ferret_callbacks.received(ferret_callbacks.context, id, NULL, 0);
        return ERR_OK;
    }
    if (err != ERR_OK) {
        pbuf_free(p);
        return err;
    }
    for (struct pbuf *q = p; q != NULL; q = q->next) {
        if (q->len > 0) {
            ferret_callbacks.received(ferret_callbacks.context, id, (const uint8_t *)q->payload, q->len);
        }
    }
    pbuf_free(p);
    return ERR_OK;
}

static err_t on_sent(void *arg, struct tcp_pcb *pcb, u16_t len) {
    LWIP_UNUSED_ARG(pcb);
    ferret_callbacks.sent(ferret_callbacks.context, (uintptr_t)arg, len);
    return ERR_OK;
}

static void on_err(void *arg, err_t err) {
    ferret_active--;
    ferret_callbacks.failed(ferret_callbacks.context, (uintptr_t)arg, err);
}

static err_t on_accept(void *arg, struct tcp_pcb *pcb, err_t err) {
    LWIP_UNUSED_ARG(arg);
    if (err != ERR_OK || pcb == NULL) {
        return ERR_VAL;
    }
    uintptr_t id = ferret_callbacks.accept(ferret_callbacks.context, pcb);
    if (id == 0) {
        tcp_abort(pcb);
        return ERR_ABRT;
    }
    ferret_active++;
    tcp_arg(pcb, (void *)id);
    tcp_recv(pcb, on_recv);
    tcp_sent(pcb, on_sent);
    tcp_err(pcb, on_err);
    tcp_nagle_disable(pcb);
    return ERR_OK;
}

/* --- Public API ----------------------------------------------------------- */

int ferret_lwip_start(const ferret_tcp_callbacks *callbacks) {
    if (ferret_started || callbacks == NULL) {
        return -1;
    }
    ferret_callbacks = *callbacks;
    lwip_init();

    ip4_addr_t addr, mask, gw;
    IP4_ADDR(&addr, 10, 111, 0, 1);
    IP4_ADDR(&mask, 255, 255, 255, 255);
    IP4_ADDR(&gw, 0, 0, 0, 0);
    if (netif_add(&ferret_netif, &addr, &mask, &gw, NULL, netif_setup, ip_input) == NULL) {
        return -2;
    }
    ip6_addr_t addr6;
    IP6_ADDR(&addr6, PP_HTONL(0xfd666572UL), PP_HTONL(0x72657400UL), 0, PP_HTONL(0x00000001UL));
    netif_ip6_addr_set(&ferret_netif, 0, &addr6);
    netif_ip6_addr_set_state(&ferret_netif, 0, IP6_ADDR_PREFERRED);
    netif_set_default(&ferret_netif);
    netif_set_up(&ferret_netif);
    netif_set_link_up(&ferret_netif);

    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (pcb == NULL) {
        return -3;
    }
    /* Any port works: the patched tcp_in.c matches this listener for every SYN. */
    if (tcp_bind(pcb, IP_ANY_TYPE, 1) != ERR_OK) {
        tcp_abort(pcb);
        return -4;
    }
    struct tcp_pcb *listener = tcp_listen_with_backlog(pcb, 0xff);
    if (listener == NULL) {
        return -5;
    }
    ferret_listen_any_pcb = (struct tcp_pcb_listen *)listener;
    tcp_accept(listener, on_accept);
    ferret_started = 1;
    return 0;
}

void ferret_lwip_stop(void) {
    if (!ferret_started) {
        return;
    }
    /* Abort every connection; lwIP calls on_err for each. */
    while (tcp_active_pcbs != NULL) {
        tcp_abort(tcp_active_pcbs);
    }
    if (ferret_listen_any_pcb != NULL) {
        tcp_close((struct tcp_pcb *)ferret_listen_any_pcb);
        ferret_listen_any_pcb = NULL;
    }
    netif_remove(&ferret_netif);
    ferret_started = 0;
    ferret_active = 0;
}

void ferret_lwip_input(const uint8_t *packet, size_t length) {
    if (!ferret_started || length == 0 || length > 0xFFFF) {
        return;
    }
    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)length, PBUF_RAM);
    if (p == NULL) {
        return;
    }
    memcpy(p->payload, packet, length);
    if (ferret_netif.input(p, &ferret_netif) != ERR_OK) {
        pbuf_free(p);
    }
}

void ferret_lwip_check_timeouts(void) {
    if (ferret_started) {
        sys_check_timeouts();
    }
}

void ferret_tcp_get_endpoints(void *connection, ferret_tcp_endpoints *out) {
    struct tcp_pcb *pcb = (struct tcp_pcb *)connection;
    memset(out, 0, sizeof(*out));
    out->local_port = pcb->local_port;
    out->remote_port = pcb->remote_port;
    if (IP_IS_V6(&pcb->local_ip)) {
        out->is_ipv6 = 1;
        memcpy(out->local_address, ip_2_ip6(&pcb->local_ip)->addr, 16);
        memcpy(out->remote_address, ip_2_ip6(&pcb->remote_ip)->addr, 16);
    } else {
        memcpy(out->local_address, &ip_2_ip4(&pcb->local_ip)->addr, 4);
        memcpy(out->remote_address, &ip_2_ip4(&pcb->remote_ip)->addr, 4);
    }
}

size_t ferret_tcp_write(void *connection, const uint8_t *data, size_t length) {
    struct tcp_pcb *pcb = (struct tcp_pcb *)connection;
    size_t space = tcp_sndbuf(pcb);
    size_t n = length < space ? length : space;
    if (n > 0xFFFF) {
        n = 0xFFFF;
    }
    if (n == 0) {
        return 0;
    }
    if (tcp_write(pcb, data, (u16_t)n, TCP_WRITE_FLAG_COPY) != ERR_OK) {
        return 0;
    }
    return n;
}

size_t ferret_tcp_send_buffer_space(void *connection) {
    return tcp_sndbuf((struct tcp_pcb *)connection);
}

void ferret_tcp_flush(void *connection) {
    tcp_output((struct tcp_pcb *)connection);
}

void ferret_tcp_consumed(void *connection, size_t length) {
    struct tcp_pcb *pcb = (struct tcp_pcb *)connection;
    while (length > 0) {
        u16_t chunk = length > 0xFFFF ? 0xFFFF : (u16_t)length;
        tcp_recved(pcb, chunk);
        length -= chunk;
    }
}

int ferret_tcp_shutdown_write(void *connection) {
    return tcp_shutdown((struct tcp_pcb *)connection, 0, 1);
}

int ferret_tcp_close(void *connection) {
    struct tcp_pcb *pcb = (struct tcp_pcb *)connection;
    tcp_arg(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_sent(pcb, NULL);
    tcp_err(pcb, NULL);
    err_t err = tcp_close(pcb);
    if (err == ERR_OK) {
        ferret_active--;
    } else {
        /* Restore nothing: the caller aborts on failure. */
    }
    return err;
}

void ferret_tcp_abort(void *connection) {
    struct tcp_pcb *pcb = (struct tcp_pcb *)connection;
    tcp_arg(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_sent(pcb, NULL);
    tcp_err(pcb, NULL);
    tcp_abort(pcb);
    ferret_active--;
}

int ferret_tcp_active_count(void) {
    return ferret_active;
}

# lwIP in Ferret

Vendored from lwIP `STABLE-2_2_1_RELEASE` (BSD licence, see `LICENSE`), core and
headers only (headers in `lwip-include/`). Everything Ferret changes is wrapped in `#if FERRET_LWIP`:

1. `core/ipv4/ip4.c`, `core/ipv6/ip6.c`: accept packets for any unicast
   destination. The packet tunnel terminates the phone's connections to every
   server, so there is no single "local" address.
2. `core/tcp_in.c`: a SYN to any port matches the single wildcard listener
   `ferret_listen_any_pcb`, and the new connection keeps the destination port
   the app connected to instead of the listener's port.

Routing back to the phone uses lwIP's own `LWIP_HOOK_IP4_ROUTE_SRC` and
`LWIP_HOOK_IP6_ROUTE` hooks (see `lwip-include/lwipopts.h`), so no routing code is patched.

The port layer lives in `port/` and Ferret's glue API in `ferret_lwip.c`.

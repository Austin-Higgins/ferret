#ifndef FERRET_LWIPOPTS_H
#define FERRET_LWIPOPTS_H

/* Ferret's lwIP configuration: TCP only (UDP is relayed in Swift), IPv4 and
 * IPv6, single-threaded (NO_SYS) and driven from one dispatch queue in the
 * packet tunnel extension. Sized for the extension's memory budget. */

#ifndef FERRET_LWIP
#define FERRET_LWIP 1
#endif

#define NO_SYS                          1
#define SYS_LIGHTWEIGHT_PROT            0
#define LWIP_TIMERS                     1

/* Memory: use the system allocator so idle connections cost nothing. */
#define MEM_LIBC_MALLOC                 1
#define MEMP_MEM_MALLOC                 1
#define MEM_ALIGNMENT                   8
#define LWIP_ALLOW_MEM_FREE_FROM_OTHER_CONTEXT 0

/* Protocols */
#define LWIP_IPV4                       1
#define LWIP_IPV6                       1
#define LWIP_TCP                        1
#define LWIP_UDP                        0
#define LWIP_RAW                        0
#define LWIP_ICMP                       0
#define LWIP_IGMP                       0
#define LWIP_DNS                        0
#define LWIP_DHCP                       0
#define LWIP_AUTOIP                     0
#define LWIP_ACD                        0
#define LWIP_ARP                        0
#define LWIP_ETHERNET                   0
#define LWIP_IPV6_MLD                   0
#define LWIP_IPV6_AUTOCONFIG            0
#define LWIP_IPV6_DHCP6                 0
#define LWIP_IPV6_SEND_ROUTER_SOLICIT   0
#define LWIP_ND6_QUEUEING               0
#define LWIP_IPV6_SCOPES                0
#define LWIP_ICMP6                      1
#define LWIP_NETCONN                    0
#define LWIP_SOCKET                     0
#define LWIP_ALTCP                      0
#define LWIP_HAVE_LOOPIF                0
#define LWIP_NETIF_LOOPBACK             0
#define LWIP_SINGLE_NETIF               0
#define IP_FORWARD                      0
#define LWIP_IPV6_FORWARD               0
#define IP_REASSEMBLY                   1
#define IP_FRAG                         0
#define LWIP_IPV6_REASS                 1
#define LWIP_IPV6_FRAG                  0
#define LWIP_STATS                      0
#define LWIP_STATS_DISPLAY              0
#define PPP_SUPPORT                     0

/* TCP tuning. The tunnel MTU is 1500; this MSS leaves room for IPv6 and options. */
#define TCP_MSS                         1360
#define TCP_WND                         (32 * TCP_MSS)
#define TCP_SND_BUF                     (32 * TCP_MSS)
#define TCP_SND_QUEUELEN                ((4 * (TCP_SND_BUF) + (TCP_MSS - 1)) / (TCP_MSS))
#define TCP_QUEUE_OOSEQ                 1
#define TCP_LISTEN_BACKLOG              0
#define LWIP_TCP_KEEPALIVE              0
#define LWIP_TCP_TIMESTAMPS             0
#define LWIP_WND_SCALE                  0
#define TCP_OVERSIZE                    TCP_MSS
#define LWIP_TCP_SACK_OUT               0
#define MEMP_NUM_TCP_PCB                1024
#define MEMP_NUM_TCP_PCB_LISTEN         2
#define MEMP_NUM_TCP_SEG                4096
#define PBUF_POOL_SIZE                  256

/* Checksums: verify what the phone sends, generate what lwIP sends. */
#define CHECKSUM_GEN_IP                 1
#define CHECKSUM_GEN_TCP                1
#define CHECKSUM_CHECK_IP               1
#define CHECKSUM_CHECK_TCP              1

/* Callbacks and hooks */
#define LWIP_CALLBACK_API               1
#define LWIP_EVENT_API                  0
#define LWIP_NETIF_API                  0
#define LWIP_NETIF_STATUS_CALLBACK      0
#define LWIP_NETIF_LINK_CALLBACK        0

struct netif;
struct ip4_addr;
struct ip6_addr;
extern struct netif *ferret_route_netif(void);
#define LWIP_HOOK_IP4_ROUTE_SRC(src, dest)  ferret_route_netif()
#define LWIP_HOOK_IP6_ROUTE(src, dest)      ferret_route_netif()

/* LWIP_DEBUG and LWIP_NOASSERT are tested with #ifdef, so they are left
 * undefined: debug output off, assertions routed to LWIP_PLATFORM_ASSERT. */

#endif /* FERRET_LWIPOPTS_H */

#ifndef CFERRET_RESOLVER_H
#define CFERRET_RESOLVER_H

/// Copies the system's configured DNS server addresses as numeric strings into
/// `out`, a buffer of `max` * 64 bytes (one NUL-terminated string per 64 bytes). Returns how many were written. Called by the
/// packet tunnel before it installs its own network settings.
int ferret_system_dns_servers(char *out, int max);

#endif

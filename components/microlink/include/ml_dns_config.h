#pragma once

/* Tailnet DNS settings from the control plane (Mattboxx Edition).
 *
 * Every netmap may carry the node's own MagicDNS name (Node.Name) and the
 * tailnet's DNS settings (DNSConfig): global resolvers, split-DNS routes,
 * search domains and extra records. This module keeps a bounded copy so the
 * application can answer names the way a Tailscale client would.
 *
 * Bounds: names up to ML_DNS_NAME_MAX-1 characters, ML_DNS_MAX_* entries per
 * list; anything beyond, and any resolver that is not plain IPv4 on port 53
 * (DoH, DoT, IPv6), is skipped and counted in `ignored`, never guessed. A
 * map without DNSConfig keeps the previous settings; a DNSConfig replaces
 * them as a whole. Storage lives in PSRAM (about 3 KB) and is allocated on
 * the first DNSConfig. Addresses are IPv4 in network byte order.
 *
 * Holding settings is not using them: the application decides, behind its
 * own switches, whether names, routes or resolvers are applied. */

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ML_DNS_NAME_MAX        64
#define ML_DNS_MAX_RESOLVERS   4
#define ML_DNS_MAX_ROUTES      8
#define ML_DNS_MAX_ROUTE_ADDRS 2
#define ML_DNS_MAX_DOMAINS     4
#define ML_DNS_MAX_EXTRA       32

typedef struct {
    uint32_t version;       /* +1 on every applied DNSConfig or name change */
    bool present;           /* a DNSConfig has been received */
    bool magic_dns;         /* DNSConfig.Proxied: MagicDNS on in the admin console */
    uint8_t resolvers;      /* usable global resolvers */
    uint8_t routes;         /* split-DNS routes kept */
    uint8_t domains;        /* search domains kept */
    uint8_t extra;          /* IPv4 extra records kept */
    uint16_t ignored;       /* entries skipped: unsupported or over a bound */
    char self[ML_DNS_NAME_MAX];   /* own MagicDNS name, lower case, no final dot */
} ml_dns_summary_t;

/* Route lookup results. */
#define ML_DNS_ROUTE_NONE   0   /* no route covers the name */
#define ML_DNS_ROUTE_FWD    1   /* forward to *addr_nbo */
#define ML_DNS_ROUTE_LOCAL  2   /* route without resolvers: answered by MagicDNS, never forwarded */

typedef struct cJSON cJSON;

/* Apply one netmap (full or incremental): Node.Name and DNSConfig. */
void ml_dns_apply_map(const cJSON *map);
/* Forget everything (logout, key change). */
void ml_dns_reset(void);

bool ml_dns_self_name(char out[ML_DNS_NAME_MAX]);
/* Exact (case-insensitive, final dot ignored) IPv4 extra record. */
bool ml_dns_extra_lookup(const char *name, uint32_t *ip_nbo);
/* Bare name completed with the search domains, first match wins. */
bool ml_dns_extra_lookup_search(const char *bare, uint32_t *ip_nbo);
/* Longest matching split-DNS route; with several resolvers the first one. */
int ml_dns_route(const char *name, uint32_t *addr_nbo);
/* First usable global resolver ("override local DNS"), 0 if none. */
uint32_t ml_dns_global_resolver(void);
void ml_dns_summary(ml_dns_summary_t *out);

#ifdef __cplusplus
}
#endif

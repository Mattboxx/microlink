/* Bounded, fail-closed IP authorization for the single MicroLink instance.
 * Original implementation, Mattboxx Edition. SPDX-License-Identifier: MIT
 * Protocol semantics: tailscale/tailcfg.FilterRule and MapResponse (not Go code).
 * No allocation, logging, network I/O or blocking mutex on the packet path.
 */
#include "ml_policy.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#ifdef ML_POLICY_HOST_TEST
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
#include <pthread.h>
static pthread_mutex_t policy_lock = PTHREAD_MUTEX_INITIALIZER;
#define LOCK() pthread_mutex_lock(&policy_lock)
#define UNLOCK() pthread_mutex_unlock(&policy_lock)
extern void *policy_test_alloc(size_t);
extern uint32_t policy_test_now(void);
#define ALLOC(n) policy_test_alloc(n)
#define NOW() policy_test_now()
#else
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "lwip/sockets.h"
static portMUX_TYPE policy_lock = portMUX_INITIALIZER_UNLOCKED;
#define LOCK() taskENTER_CRITICAL(&policy_lock)
#define UNLOCK() taskEXIT_CRITICAL(&policy_lock)
/* Never consume scarce internal heap for a large policy snapshot. */
#define ALLOC(n) heap_caps_malloc((n), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)
#define NOW() ((uint32_t)(esp_timer_get_time() / 1000))
#endif
#include "lwip/pbuf.h"

#define GROUPS 32
/* Expanded ACL rules (SrcIPs x DstPorts) are sized by the map too; a policy
 * with groups/grants over a 20-device tailnet passes 128 easily. */
#define MAX_ENTRIES 262144u
/* Peers and prefixes have no fixed count: each snapshot is sized by the map
 * (PSRAM). These bounds only guard size arithmetic; a map that large could
 * not be received by an ESP32 anyway. */
#define MAX_PEERS 65536u
#define MAX_PREFIXES 1048576u
#define FLOWS 32
#define NAME_LEN 64

typedef struct { uint8_t lo[16], hi[16], family, bits; } ip_range;
typedef struct {
    ip_range src, dst;
    uint8_t protocols[32], group;
    uint16_t first, last;
} entry;
typedef struct {
    uint64_t id;
    uint8_t key[32];
    uint32_t first, count;   /* prefixes: pool[first .. first+count) */
    time_t expires;
    bool active;
} peer;
typedef struct {
    uint8_t src[16], dst[16], family, protocol, flags, icmp;
    uint16_t sport, dport;
} tuple;
typedef struct {
    tuple reverse;
    uint8_t key[32];
    uint32_t epoch, touched, replied; /* replied: last admitted reply, 0 = none */
    bool used;
} flow;
typedef struct {
    unsigned count;
    bool filters_known, peers_known, local_known;
    char groups[GROUPS][NAME_LEN];
    uint32_t local_first, local_count;   /* own prefixes in pool */
    time_t expires;
    uint32_t peer_count, pool_count;     /* used entries */
    /* Everything above (and peers[0..peer_count), pool[0..pool_count)) is the
     * authority; published snapshots are canonical (active peers in map
     * order, each one's prefixes, then the own ones), so equal authority
     * compares equal. */
    uint32_t peer_cap, pool_cap, entry_cap;
    peer *peers;                         /* inside this allocation */
    ip_range *pool;
    entry *entries;                      /* count used (p->count) */
    /* Ownership index of published snapshots (NULL on working copies):
     * peer prefixes sorted by family, length (longest first) and network;
     * one group per (family, length). */
    struct owner_ix {uint32_t prefix, peer;} *index;
    struct owner_group {uint8_t family, bits; uint32_t start, end;} *ix_groups;
    uint32_t index_count, ix_group_count;
    uint32_t epoch;
    /* Everything above is immutable once published. Never copy mutable reader
     * references or flow state while concurrent packet readers update them. */
    flow flows[FLOWS];
    unsigned refs;
    bool retired;
} policy;
static policy *current;
static uint32_t epoch;
static bool suspended;
/* Set before a MapRequest whose first response is the complete map (not
 * OmitPeers); consumed by that map, cleared when the session ends. */
static bool s_expect_full;
static uint32_t suspended_at;
#define RESUME_WINDOW_MS 30000u
static uint8_t loss_mode = ML_POLICY_LOSS_KEEP;
static uint32_t loss_grace_ms = 300000u;

/* True while data must be blocked because the control transport is down.
 * Reads plain words only; callers already hold LOCK where they test
 * current/suspended together. */
static bool blocked(void) {
    if (!suspended || loss_mode == ML_POLICY_LOSS_KEEP) return false;
    if (loss_mode == ML_POLICY_LOSS_BOUNDED) return (uint32_t)(NOW() - suspended_at) >= loss_grace_ms;
    return true;
}

void ml_policy_set_control_loss(uint8_t mode, uint32_t grace_s) {
    if (mode > ML_POLICY_LOSS_STRICT) mode = ML_POLICY_LOSS_KEEP;
    if (grace_s < 30) grace_s = 30;
    if (grace_s > 86400) grace_s = 86400;
    LOCK();loss_mode=mode;loss_grace_ms=grace_s*1000u;UNLOCK();
}

void ml_policy_get_control_loss(uint8_t *mode, uint32_t *grace_s) {
    LOCK();
    if (mode) *mode = loss_mode;
    if (grace_s) *grace_s = loss_grace_ms / 1000u;
    UNLOCK();
}

static policy *acquire(void) {
    LOCK(); policy *p = current; if (p) p->refs++; UNLOCK(); return p;
}
static void release(policy *p) {
    if (!p) return;
    LOCK(); bool dispose = --p->refs == 0 && p->retired; UNLOCK();
    if (dispose) free(p);
}
static void publish(policy *p) {
    if (p) {p->refs=0;p->retired=false;memset(p->flows,0,sizeof p->flows);}
    LOCK();
    policy *old = current;
    if (p) { p->refs = 0; p->retired = false; p->epoch = ++epoch; }
    else ++epoch;
    current = p;
    suspended=false;
    bool dispose = old && !old->refs;
    if (old) old->retired = true;
    UNLOCK();
    if (dispose) free(old);
}
void ml_policy_reset(void) { publish(NULL); }

/* One block: the policy, then entry_cap rules, peer_cap peers and pool_cap
 * prefixes (rules first: they need the strictest alignment of the three). */
#define IX_MAX_GROUPS (33 + 129)   /* IPv4 /0../32, IPv6 /0../128 */
static policy *policy_alloc_ix(uint32_t peer_cap, uint32_t pool_cap, uint32_t entry_cap, bool with_index) {
    if (peer_cap > MAX_PEERS || pool_cap > MAX_PREFIXES || entry_cap > MAX_ENTRIES) return NULL;
    /* Every array starts on a 16-byte boundary: an entry is 106 bytes with
     * 2-byte alignment, so with an odd number of rules the peer table (64-bit
     * fields) used to start on a 2-byte boundary -- a LoadStoreAlignment
     * exception (restart) on the ESP32-S3, undefined behaviour anywhere. */
    #define POLICY_ALIGN(x) (((x) + (size_t)15) & ~(size_t)15)
    size_t at_entries = POLICY_ALIGN(sizeof(policy));
    size_t at_peers = POLICY_ALIGN(at_entries + (size_t)entry_cap * sizeof(entry));
    size_t at_pool = POLICY_ALIGN(at_peers + (size_t)peer_cap * sizeof(peer));
    size_t bytes = at_pool + (size_t)pool_cap * sizeof(ip_range);
    size_t ix_at = POLICY_ALIGN(bytes);
    size_t groups_at = POLICY_ALIGN(ix_at + (size_t)pool_cap * sizeof(struct owner_ix));
    if (with_index) bytes = groups_at + IX_MAX_GROUPS * sizeof(struct owner_group);
    #undef POLICY_ALIGN
    policy *p = ALLOC(bytes);
    if (!p) return NULL;
    memset(p, 0, bytes);
    p->peer_cap = peer_cap; p->pool_cap = pool_cap; p->entry_cap = entry_cap;
    p->entries = (entry *)((uint8_t *)p + at_entries);
    p->peers = (peer *)((uint8_t *)p + at_peers);
    p->pool = (ip_range *)((uint8_t *)p + at_pool);
    if (with_index) {
        p->index = (struct owner_ix *)((uint8_t *)p + ix_at);
        p->ix_groups = (struct owner_group *)((uint8_t *)p + groups_at);
    }
    return p;
}
static policy *policy_alloc(uint32_t peer_cap, uint32_t pool_cap, uint32_t entry_cap) {
    return policy_alloc_ix(peer_cap, pool_cap, entry_cap, false);
}
static const ip_range *s_ix_pool;   /* qsort context: the coordinator is the only writer */
static int ix_order(const void *x, const void *y) {
    const ip_range *a = &s_ix_pool[((const struct owner_ix *)x)->prefix], *b = &s_ix_pool[((const struct owner_ix *)y)->prefix];
    if (a->family != b->family) return a->family < b->family ? -1 : 1;
    if (a->bits != b->bits) return a->bits > b->bits ? -1 : 1;   /* longest first */
    int c = memcmp(a->lo, b->lo, 16);
    if (c) return c;
    uint32_t pa = ((const struct owner_ix *)x)->peer, pb = ((const struct owner_ix *)y)->peer;
    return pa < pb ? -1 : pa > pb;
}
static void build_index(policy *p) {
    uint32_t n = 0;
    for (uint32_t i = 0; i < p->peer_count; i++)
        for (uint32_t j = 0; j < p->peers[i].count; j++) p->index[n++] = (struct owner_ix){p->peers[i].first + j, i};
    s_ix_pool = p->pool;
    qsort(p->index, n, sizeof *p->index, ix_order);
    s_ix_pool = NULL;
    uint32_t g = 0;
    for (uint32_t k = 0; k < n; k++) {
        const ip_range *r = &p->pool[p->index[k].prefix];
        if (!g || p->ix_groups[g - 1].family != r->family || p->ix_groups[g - 1].bits != r->bits) {
            if (g) p->ix_groups[g - 1].end = k;
            p->ix_groups[g++] = (struct owner_group){r->family, r->bits, k, k};
        }
    }
    if (g) p->ix_groups[g - 1].end = n;
    p->index_count = n; p->ix_group_count = g;
}
/* Canonical copy: header, active peers in order with their prefixes packed,
 * then the own prefixes. extra_* reserve room for an update. */
static policy *policy_canonical(const policy *src, uint32_t extra_peers, uint32_t extra_pool, uint32_t extra_entries) {
    uint32_t peers = 0, pool = src->local_count;
    for (uint32_t i = 0; i < src->peer_count; i++)
        if (src->peers[i].active) { peers++; pool += src->peers[i].count; }
    if (extra_peers > MAX_PEERS - peers || extra_pool > MAX_PREFIXES - pool
        || extra_entries > MAX_ENTRIES - src->count) return NULL;
    bool final = !extra_peers && !extra_pool && !extra_entries;   /* a snapshot to publish */
    policy *p = policy_alloc_ix(peers + extra_peers, pool + extra_pool, src->count + extra_entries, final);
    if (!p) return NULL;
    memcpy(p, src, offsetof(policy, peer_cap));
    memcpy(p->entries, src->entries, src->count * sizeof(entry));
    p->peer_count = 0; p->pool_count = 0;
    for (uint32_t i = 0; i < src->peer_count; i++) {
        const peer *a = &src->peers[i];
        if (!a->active) continue;
        peer *b = &p->peers[p->peer_count++];
        memcpy(b, a, sizeof *b); b->first = p->pool_count;   /* bytes, padding included */
        memcpy(&p->pool[p->pool_count], &src->pool[a->first], a->count * sizeof(ip_range));
        p->pool_count += a->count;
    }
    memcpy(&p->pool[p->pool_count], &src->pool[src->local_first], src->local_count * sizeof(ip_range));
    p->local_first = p->pool_count; p->pool_count += src->local_count;
    if (p->index) build_index(p);
    return p;
}
static bool same_authority_data(const policy *a, const policy *b) {
    return !memcmp(a, b, offsetof(policy, peer_cap))
        && !memcmp(a->entries, b->entries, a->count * sizeof(entry))
        && !memcmp(a->peers, b->peers, a->peer_count * sizeof(peer))
        && !memcmp(a->pool, b->pool, a->pool_count * sizeof(ip_range));
}
void ml_policy_suspend(void) {
    LOCK();if(!suspended){suspended=true;suspended_at=NOW();}s_expect_full=false;UNLOCK();
}

static const cJSON *get(const cJSON *o, const char *key) {
    return cJSON_GetObjectItemCaseSensitive(o, key);
}
static bool unique(const cJSON *o) {
    for (const cJSON *a = o->child; a; a = a->next) {
        if (!a->string) return false;
        for (const cJSON *b = a->next; b; b = b->next)
            if (b->string && !strcmp(a->string, b->string)) return false;
    }
    return true;
}
static bool same_casefold(const char *a,const char *b) {
    while (*a && *b) {
        unsigned x=(unsigned char)*a++,y=(unsigned char)*b++;
        if (x>='A'&&x<='Z') x+='a'-'A';
        if (y>='A'&&y<='Z') y+='a'-'A';
        if (x!=y) return false;
    }
    return *a==*b;
}
/* The older peer parser is case-insensitive. Reject alternate spellings of
 * security fields rather than giving it a different interpretation. */
static bool exact_auth_fields(const cJSON *o) {
    const char *names[]={"KeepAlive","PacketFilter","PacketFilters","Node","Peers","PeersChanged","PeersRemoved","PeersChangedPatch",
        "ID","NodeID","Key","KeyExpiry","Addresses","AllowedIPs","Expired","IsJailed","UnsignedPeerAPIOnly"};
    for (const cJSON *v=o->child;v;v=v->next) for (unsigned i=0;i<sizeof names/sizeof names[0];i++)
        if (same_casefold(v->string,names[i]) && strcmp(v->string,names[i])) return false;
    return true;
}
static bool number(const cJSON *v, uint64_t max, uint64_t *out) {
    if (!cJSON_IsNumber(v) || !isfinite(v->valuedouble) || v->valuedouble < 0
        || v->valuedouble > (double)max || floor(v->valuedouble) != v->valuedouble) return false;
    *out = (uint64_t)v->valuedouble; return true;
}
static bool ip_parse(const char *s, uint8_t out[16], uint8_t *family) {
    memset(out, 0, 16);
    if (inet_pton(AF_INET, s, out) == 1) { *family = 4; return true; }
    if (inet_pton(AF_INET6, s, out) == 1) { *family = 6; return true; }
    return false;
}
/* Wildcard, IP, CIDR and inclusive IP range. IPv4-mapped IPv6 stays IPv6. */
static bool range_parse(const char *text, ip_range *out) {
    char s[100];
    if (!text || !*text || strlen(text) >= sizeof s) return false;
    memset(out, 0, sizeof *out);
    if (!strcmp(text, "*")) { memset(out->hi, 255, 16); return true; }
    strcpy(s, text);
    char *slash = strchr(s, '/'), *dash = strchr(s, '-');
    if (slash && dash) return false;
    if (slash) *slash++ = 0;
    if (dash) *dash++ = 0;
    if (!ip_parse(s, out->lo, &out->family)) return false;
    unsigned bytes = out->family == 4 ? 4 : 16;
    out->bits = bytes * 8;
    memcpy(out->hi, out->lo, 16);
    if (dash) {
        uint8_t family;
        if (!ip_parse(dash, out->hi, &family) || family != out->family
            || memcmp(out->lo, out->hi, bytes) > 0) return false;
    }
    if (slash) {
        unsigned bits = 0;
        if (!*slash) return false;
        for (const char *c = slash; *c; c++) {
            if (*c < '0' || *c > '9' || bits > 128) return false;
            bits = bits * 10 + (unsigned)(*c - '0');
        }
        if (bits > bytes * 8) return false;
        out->bits = bits;
        for (unsigned i = 0; i < bytes; i++) {
            unsigned n = bits > i * 8 ? bits - i * 8 : 0;
            uint8_t mask = n >= 8 ? 255 : (uint8_t)(255 << (8 - n));
            out->lo[i] &= mask; out->hi[i] |= (uint8_t)~mask;
        }
    }
    return true;
}
static bool contains(const ip_range *r, const uint8_t ip[16], uint8_t family) {
    unsigned bytes = family == 4 ? 4 : 16;
    return (!r->family || r->family == family)
        && memcmp(r->lo, ip, bytes) <= 0 && memcmp(ip, r->hi, bytes) <= 0;
}
/* Why the last update was refused (static text, never map content). */
static const char *s_detail = "";
#define REFUSE(why) do { s_detail = (why); return false; } while (0)
static bool prefixes(policy *p, const cJSON *a, uint32_t *first, uint32_t *count) {
    if (!cJSON_IsArray(a)) return false;
    *first = p->pool_count; *count = 0;
    for (const cJSON *v = a->child; v; v = v->next) {
        if (p->pool_count >= p->pool_cap) return false;
        if (!cJSON_IsString(v) || strchr(v->valuestring, '-')
            || !strcmp(v->valuestring, "*") || !range_parse(v->valuestring, &p->pool[p->pool_count])) return false;
        p->pool_count++; (*count)++;
    }
    return true;
}
/* AllowedIPs, or Addresses when AllowedIPs is absent/null (as before). */
static const cJSON *node_ips(const cJSON *n) {
    const cJSON *ips = cJSON_GetObjectItemCaseSensitive(n, "AllowedIPs");
    return !ips || cJSON_IsNull(ips) ? cJSON_GetObjectItemCaseSensitive(n, "Addresses") : ips;
}
static uint32_t list_size(const cJSON *a) { return cJSON_IsArray(a) ? (uint32_t)cJSON_GetArraySize(a) : 0; }
/* Room an update can need on top of the copied authority. */
/* Expanded rules of one filter list: SrcIPs x DstPorts per rule. */
static uint64_t rule_room(const cJSON *rules) {
    uint64_t n = 0;
    if (cJSON_IsArray(rules)) for (const cJSON *r = rules->child; r; r = r->next)
        n += (uint64_t)list_size(cJSON_GetObjectItemCaseSensitive(r, "SrcIPs"))
           * list_size(cJSON_GetObjectItemCaseSensitive(r, "DstPorts"));
    return n;
}
static bool update_room(const cJSON *map, uint32_t *peers, uint32_t *pool, uint32_t *entries) {
    const char *lists[] = {"Peers", "PeersChanged"};
    uint64_t n = 0, ips = 0;
    for (unsigned l = 0; l < 2; l++) {
        const cJSON *list = cJSON_GetObjectItemCaseSensitive(map, lists[l]);
        n += list_size(list);
        if (cJSON_IsArray(list)) for (const cJSON *v = list->child; v; v = v->next) ips += list_size(node_ips(v));
    }
    const cJSON *self = cJSON_GetObjectItemCaseSensitive(map, "Node");
    if (cJSON_IsObject(self)) ips += list_size(node_ips(self));
    uint64_t rules = rule_room(cJSON_GetObjectItemCaseSensitive(map, "PacketFilter"));
    const cJSON *groups = cJSON_GetObjectItemCaseSensitive(map, "PacketFilters");
    if (cJSON_IsObject(groups)) for (const cJSON *g = groups->child; g; g = g->next) rules += rule_room(g);
    if (n > MAX_PEERS || ips > MAX_PREFIXES || rules > MAX_ENTRIES) return false;
    *peers = (uint32_t)n; *pool = (uint32_t)ips; *entries = (uint32_t)rules;
    return true;
}
static int key_order(const void *x, const void *y) {
    const peer *a = *(const peer *const *)x, *b = *(const peer *const *)y;
    return memcmp(a->key, b->key, 32);
}
static int id_order(const void *x, const void *y) {
    const peer *a = *(const peer *const *)x, *b = *(const peer *const *)y;
    return a->id < b->id ? -1 : a->id > b->id;
}
/* Two active peers with one ID or one key: refuse (sorted, not quadratic). */
static bool active_unique(const policy *p) {
    uint32_t n = 0;
    for (uint32_t i = 0; i < p->peer_count; i++) n += p->peers[i].active;
    if (n < 2) return true;
    const peer **v = ALLOC(n * sizeof *v);
    if (!v) REFUSE("no-memory");
    n = 0;
    for (uint32_t i = 0; i < p->peer_count; i++) if (p->peers[i].active) v[n++] = &p->peers[i];
    bool ok = true;
    qsort(v, n, sizeof *v, key_order);
    for (uint32_t i = 1; ok && i < n; i++) ok = memcmp(v[i - 1]->key, v[i]->key, 32) != 0;
    qsort(v, n, sizeof *v, id_order);
    for (uint32_t i = 1; ok && i < n; i++) ok = v[i - 1]->id != v[i]->id;
    free(v);
    if (!ok) REFUSE("duplicate-peer");
    return true;
}
static bool key_parse(const cJSON *v, uint8_t out[32]) {
    if (!cJSON_IsString(v)) return false;
    const char *s = v->valuestring;
    if (!strncmp(s, "nodekey:", 8)) s += 8;
    if (strlen(s) != 64) return false;
    unsigned nonzero = 0;
    for (unsigned i = 0; i < 32; i++) {
        unsigned b = 0;
        for (unsigned j = 0; j < 2; j++) {
            unsigned c = (unsigned char)s[i*2+j];
            unsigned n = c >= '0' && c <= '9' ? c-'0' : c >= 'a' && c <= 'f' ? c-'a'+10
                       : c >= 'A' && c <= 'F' ? c-'A'+10 : 99;
            if (n > 15) return false;
            b = b * 16 + n;
        }
        out[i] = b; nonzero |= b;
    }
    return nonzero != 0;
}
/* tailcfg uses UTC RFC3339 timestamps. Unsupported offsets fail closed. */
static bool expiration(const cJSON *v, time_t *out) {
    *out = 0;
    if (!v || cJSON_IsNull(v)) return true;
    if (!cJSON_IsString(v)) return false;
    const char *s = v->valuestring;
    size_t len = strlen(s);
    if (len < 20 || s[4]!='-' || s[7]!='-' || s[10]!='T' || s[13]!=':' || s[16]!=':') return false;
    for (unsigned i = 0; i < 19; i++)
        if (i!=4 && i!=7 && i!=10 && i!=13 && i!=16 && (s[i]<'0'||s[i]>'9')) return false;
    unsigned y = (s[0]-'0')*1000+(s[1]-'0')*100+(s[2]-'0')*10+s[3]-'0';
    unsigned m = (s[5]-'0')*10+s[6]-'0', d = (s[8]-'0')*10+s[9]-'0';
    unsigned h = (s[11]-'0')*10+s[12]-'0', min = (s[14]-'0')*10+s[15]-'0', sec = (s[17]-'0')*10+s[18]-'0';
    if (len > 20) {
        if (s[19] != '.' || len < 22) return false;
        for (size_t i=20;i<len-1;i++) if (s[i]<'0'||s[i]>'9') return false;
    }
    if (s[len-1]!='Z' || m<1 || m>12 || d<1 || d>31 || h>23 || min>59 || sec>59) return false;
    if (y == 1) return !strcmp(s,"0001-01-01T00:00:00Z");
    if (y < 1970 || y > 2099) return false;
    static const unsigned days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    bool leap = y%4==0 && (y%100!=0 || y%400==0);
    if (d > days[m-1]+(m==2 && leap)) return false;
    uint64_t n = 0;
    for (unsigned yr=1970;yr<y;yr++) n += 365+(yr%4==0 && (yr%100!=0 || yr%400==0));
    for (unsigned mo=1;mo<m;mo++) n += days[mo-1]+(mo==2 && leap);
    *out = (time_t)(((n+d-1)*24+h)*3600+min*60+sec); return true;
}
static bool usable(const cJSON *node) {
    const char *flags[] = {"Expired", "IsJailed", "UnsignedPeerAPIOnly"};
    for (unsigned i=0;i<3;i++) {
        const cJSON *v=get(node,flags[i]);
        if (v && !cJSON_IsNull(v) && (!cJSON_IsBool(v) || cJSON_IsTrue(v))) return false;
    }
    return true;
}
static bool peer_updates(policy *p, const cJSON *map, bool session_full) {
    const cJSON *full = get(map,"Peers"), *changed = get(map,"PeersChanged");
    if (session_full && (!full || cJSON_IsNull(full))) {
        /* First map of a session without Peers: Peers is omitempty, so an
         * empty tailnet omits it. The complete list is empty. */
        for (uint32_t i=0;i<p->peer_count;i++) p->peers[i].active=false;
        p->peers_known=true;
    }
    const cJSON *removed=get(map,"PeersRemoved"), *patches=get(map,"PeersChangedPatch");
    if (full && !cJSON_IsNull(full)) {
        if (!cJSON_IsArray(full)) REFUSE("peers-shape");
        if (full->child) {
            /* A nonempty full map precludes peer deltas (tailcfg/mapSession). */
            changed=removed=patches=NULL;
        } else if ((changed && changed->child) || (removed && removed->child) || (patches && patches->child)) {
            /* Some serializers include Peers:[] on a genuine delta. */
            full=NULL;
        }
        if (full) {for (uint32_t i=0;i<p->peer_count;i++) p->peers[i].active=false; p->peers_known=true;}
    } else full = NULL;
    /* Remove BEFORE upsert, matching the reference mapSession. Slot reuse is
     * private to the unpublished candidate: no permissive intermediate state.
     * If an ID is removed and re-added in this map, the new Node wins. */
    if (removed && !cJSON_IsNull(removed)) {
        if (!cJSON_IsArray(removed)) REFUSE("removed-shape");
        for (const cJSON *v=removed->child;v;v=v->next) {
            uint64_t id;if (!number(v,9007199254740991ULL,&id)) REFUSE("peer-id");
            for (uint32_t i=0;i<p->peer_count;i++) if (p->peers[i].id==id) p->peers[i].active=false;
        }
    }
    for (unsigned pass=0;pass<2;pass++) {
        const cJSON *list = pass ? changed : full;
        if (!list || cJSON_IsNull(list)) continue;
        if (!cJSON_IsArray(list)) REFUSE("peers-shape");
        for (const cJSON *v=list->child;v;v=v->next) {
            uint64_t id;
            if (!cJSON_IsObject(v) || !unique(v) || !exact_auth_fields(v)) REFUSE("peer-shape");
            if (!number(get(v,"ID"),9007199254740991ULL,&id) || !id) REFUSE("peer-id");
            int64_t slot=-1;
            for (uint32_t i=0;i<p->peer_count;i++) if (p->peers[i].active && p->peers[i].id==id) slot=i;
            if (!pass && slot>=0) REFUSE("duplicate-peer"); /* Duplicate ID in full map. */
            if (slot<0) {
                if (p->peer_count>=p->peer_cap) REFUSE("peer-room");
                slot=p->peer_count++;
            }
            peer *a=&p->peers[slot]; memset(a,0,sizeof *a); a->id=id;
            if (!key_parse(get(v,"Key"),a->key)) REFUSE("peer-key");
            if (!expiration(get(v,"KeyExpiry"),&a->expires)) REFUSE("peer-expiry");
            if (!prefixes(p,node_ips(v),&a->first,&a->count)) REFUSE("peer-prefixes");
            a->active=usable(v);
        }
    }
    if (patches && !cJSON_IsNull(patches)) {
        if (!cJSON_IsArray(patches)) REFUSE("patch-shape");
        for (const cJSON *v=patches->child;v;v=v->next) {
            uint64_t id; if (!cJSON_IsObject(v)||!unique(v)||!exact_auth_fields(v)
                || get(v,"AllowedIPs") || get(v,"Addresses") || !number(get(v,"NodeID"),9007199254740991ULL,&id)) REFUSE("patch-shape");
            for (uint32_t i=0;i<p->peer_count;i++) if (p->peers[i].active && p->peers[i].id==id) {
                const cJSON *key=get(v,"Key"), *exp=get(v,"KeyExpiry");
                if (key && !cJSON_IsNull(key)) {
                    uint8_t rotated[32];
                    if (!key_parse(key,rotated)) REFUSE("peer-key");
                    /* Key rotation (seamless renewal): the new key replaces
                     * the old one in this snapshot, so the old key loses
                     * authority now. A key held by another active peer is
                     * refused by active_unique() below. */
                    memcpy(p->peers[i].key,rotated,32);
                }
                if (exp && !cJSON_IsNull(exp) && !expiration(exp,&p->peers[i].expires)) REFUSE("peer-expiry");
                if (!usable(v)) p->peers[i].active=false;
            }
        }
    }
    const cJSON *node=get(map,"Node");
    if (node && !cJSON_IsNull(node)) {
        if (!cJSON_IsObject(node)||!unique(node)||!exact_auth_fields(node)) REFUSE("self-shape");
        if (!expiration(get(node,"KeyExpiry"),&p->expires)) REFUSE("self-expiry");
        if (!prefixes(p,node_ips(node),&p->local_first,&p->local_count)) REFUSE("self-prefixes");
        p->local_known=usable(node);
    }
    return active_unique(p);
}
static int group_find(policy *p,const char *name) {
    for (unsigned i=0;i<GROUPS;i++) if (!strcmp(p->groups[i],name)) return (int)i;
    return -1;
}
static void group_remove(policy *p,int id) {
    if (id<0) return;
    unsigned n=0;
    for (unsigned i=0;i<p->count;i++) if (p->entries[i].group!=id) p->entries[n++]=p->entries[i];
    p->count=n; p->groups[id][0]=0;
}
static bool group_apply(policy *p,const char *name,const cJSON *rules) {
    if (!name || !*name || strlen(name)>=NAME_LEN) return false;
    int id=group_find(p,name); group_remove(p,id);
    if (cJSON_IsNull(rules)) return true;
    if (!cJSON_IsArray(rules)) return false;
    if (id<0) for (unsigned i=0;i<GROUPS;i++) if (!p->groups[i][0]) {id=(int)i;break;}
    if (id<0) return false;
    strcpy(p->groups[id],name);
    for (const cJSON *r=rules->child;r;r=r->next) {
        if (!cJSON_IsObject(r)||!unique(r)) return false;
        for (const cJSON *f=r->child;f;f=f->next)
            if (strcmp(f->string,"SrcIPs") && strcmp(f->string,"SrcBits") && strcmp(f->string,"DstPorts")
                && strcmp(f->string,"IPProto") && strcmp(f->string,"CapGrant")) return false;
        const cJSON *srcs=get(r,"SrcIPs"), *dsts=get(r,"DstPorts"), *caps=get(r,"CapGrant");
        if (caps && !cJSON_IsNull(caps) && (!cJSON_IsArray(caps) || cJSON_GetArraySize(caps))) {
            /* Application capability grants do not authorize IP traffic. */
            if (dsts && !cJSON_IsNull(dsts) && cJSON_GetArraySize(dsts)) return false;
            continue;
        }
        const cJSON *bits=get(r,"SrcBits"), *protos=get(r,"IPProto");
        if (bits && !cJSON_IsNull(bits) && (!cJSON_IsArray(bits)||cJSON_GetArraySize(bits))) return false;
        if (!cJSON_IsArray(srcs) || (dsts && !cJSON_IsNull(dsts) && !cJSON_IsArray(dsts))) return false;
        if (!dsts || cJSON_IsNull(dsts)) continue;
        uint8_t mask[32]={0};
        if (!protos || cJSON_IsNull(protos) || (cJSON_IsArray(protos)&&!protos->child)) {
            mask[0]|=1<<1; mask[0]|=1<<6; mask[17/8]|=1<<(17%8); mask[58/8]|=1<<(58%8);
        } else {
            if (!cJSON_IsArray(protos)) return false;
            for (const cJSON *v=protos->child;v;v=v->next) {
                uint64_t n; if (!number(v,255,&n)) return false;
                mask[n/8]|=(uint8_t)(1<<(n%8));
            }
        }
        for (const cJSON *s=srcs->child;s;s=s->next) for (const cJSON *d=dsts->child;d;d=d->next) {
            /* "cap:<name>" matches peers holding a node capability; this
             * client does not track peer capabilities, so such a source
             * admits nobody (never more than the policy allows), and the
             * rest of the policy still applies. */
            if (cJSON_IsString(s) && !strncmp(s->valuestring,"cap:",4)) continue;
            if (p->count>=p->entry_cap) REFUSE("filter-room");
            if (!cJSON_IsString(s)||!cJSON_IsObject(d)||!unique(d)) return false;
            for (const cJSON *f=d->child;f;f=f->next)
                if (strcmp(f->string,"IP") && strcmp(f->string,"Ports") && strcmp(f->string,"Bits")) return false;
            const cJSON *ip=get(d,"IP"), *ports=get(d,"Ports"), *dbits=get(d,"Bits");
            uint64_t first,last;
            if (!cJSON_IsString(ip)||!cJSON_IsObject(ports)||!unique(ports)
                || !number(get(ports,"First"),65535,&first)||!number(get(ports,"Last"),65535,&last)
                || first>last || (dbits && !cJSON_IsNull(dbits))) return false;
            entry *e=&p->entries[p->count++]; memset(e,0,sizeof *e);
            if (!range_parse(s->valuestring,&e->src)||!range_parse(ip->valuestring,&e->dst)) return false;
            memcpy(e->protocols,mask,32); e->group=id; e->first=first; e->last=last;
        }
    }
    return true;
}
/* Last rejection reason: a static code for diagnostics, never map content. */
static const char *s_reject="none";
void ml_policy_expect_full_map(void) {LOCK();s_expect_full=true;UNLOCK();}
const char *ml_policy_last_reject(void) {return s_reject;}
bool ml_policy_apply(const cJSON *map) {
    s_reject="none";
    if (!cJSON_IsObject(map)||!unique(map)||!exact_auth_fields(map)) {s_reject=!cJSON_IsObject(map)?"not-object":!unique(map)?"duplicate-key":"auth-field-shape";ml_policy_reset();return false;}
    const cJSON *keepalive=get(map,"KeepAlive");
    if (keepalive && !cJSON_IsNull(keepalive) && !cJSON_IsBool(keepalive)) {s_reject="keepalive-type";ml_policy_reset();return false;}
    if (cJSON_IsTrue(keepalive)) return true; /* Not a policy/netmap update. */
    const char *keys[]={"PacketFilter","PacketFilters","Peers","PeersChanged","PeersRemoved","PeersChangedPatch","Node"};
    bool changed=false;
    for (unsigned i=0;i<sizeof keys/sizeof keys[0];i++) {
        const cJSON *v=get(map,keys[i]);
        if (v && !cJSON_IsNull(v)) changed=true;
    }
    if (!changed) return true; /* Keepalive/omitted/null fields retain same-session state. */
    uint32_t room_peers,room_pool,room_entries;
    if (!update_room(map,&room_peers,&room_pool,&room_entries)) {s_reject="too-large";ml_policy_reset();return false;}
    policy *old=acquire();
    LOCK();bool resuming=suspended;uint32_t outage=NOW()-suspended_at;bool was_blocked=blocked();UNLOCK();
    /* Reconnects must not apply deltas to unseen stale authority. A complete
     * map is built from empty state, never the saved pre-outage filters. */
    LOCK();bool session_full=s_expect_full && cJSON_IsObject(get(map,"Node"));if(session_full)s_expect_full=false;UNLOCK();
    bool complete=session_full || (cJSON_IsArray(get(map,"Peers")) && cJSON_IsObject(get(map,"Node"))
        && (cJSON_IsArray(get(map,"PacketFilter")) || cJSON_IsObject(get(map,"PacketFilters"))));
    /* Never apply a delta to unconfirmed authority. The reconnect asks for a
     * complete map, so a delta (or a malformed partial map) first is an anomaly
     * and fails closed in every control-loss mode. */
    if(resuming&&!complete){s_reject="delta-while-suspended";release(old);ml_policy_reset();return false;}
    /* A complete map is built from empty state; a delta from the current
     * authority, with room for the update. */
    policy *next=old&&!resuming ? policy_canonical(old,room_peers,room_pool,room_entries) : policy_alloc(room_peers,room_pool,room_entries);
    if (!next) {s_reject="no-memory";release(old);ml_policy_reset();return false;}
    s_detail="";
    bool valid=peer_updates(next,map,session_full);
    if(!valid)s_reject=*s_detail?s_detail:"peer-update";
    const cJSON *base=get(map,"PacketFilter"), *groups=get(map,"PacketFilters");
    bool replace_base=base && !cJSON_IsNull(base);
    if (replace_base) valid=valid && cJSON_IsArray(base);
    bool clear_all=false;
    if (groups && !cJSON_IsNull(groups)) {
        valid=valid && cJSON_IsObject(groups) && unique(groups);
        const cJSON *clear=get(groups,"*");
        if (clear) {
            if (!cJSON_IsNull(clear)) valid=false;
            clear_all=true;
        }
    }
    /* Remove all replaced/deleted groups BEFORE capacity checks on additions.
     * Named deltas are unordered: a valid at-capacity replace must not depend
     * on whether JSON lists the new group before the removed one. */
    if (replace_base) {group_remove(next,group_find(next,"base"));next->filters_known=true;}
    /* A complete map without any filter field: no rules (PacketFilter is
     * omitempty; an empty list blocks everything). */
    if (session_full && !replace_base && !(groups && !cJSON_IsNull(groups))) {
        next->count=0;memset(next->groups,0,sizeof next->groups);next->filters_known=true;
    }
    if (clear_all) {next->count=0;memset(next->groups,0,sizeof next->groups);next->filters_known=true;}
    if (groups && !cJSON_IsNull(groups)) {
        for (const cJSON *g=groups->child;valid && g;g=g->next) {
            if (!strcmp(g->string,"*")) continue;
            valid=*g->string && strlen(g->string)<NAME_LEN && (cJSON_IsNull(g)||cJSON_IsArray(g));
            group_remove(next,group_find(next,g->string));
            next->filters_known=true;
        }
    }
    if (valid && replace_base && !clear_all && !get(groups,"base")) valid=group_apply(next,"base",base);
    if (groups && !cJSON_IsNull(groups)) for (const cJSON *g=groups->child;valid && g;g=g->next) {
        if (strcmp(g->string,"*") && !cJSON_IsNull(g)) valid=group_apply(next,g->string,g);
    }
    if (!valid) {if(!strcmp(s_reject,"none"))s_reject=*s_detail?s_detail:"packet-filter";release(old);free(next);ml_policy_reset();return false;}
    /* Publish the canonical (compact) form: equal authority compares equal. */
    policy *canon=policy_canonical(next,0,0,0);
    free(next);
    if (!canon) {s_reject="no-memory";release(old);ml_policy_reset();return false;}
    next=canon;
    /* Endpoint/Online patches and identical refreshes are not revocations.
     * Do not tear down return traffic on every normal map heartbeat. */
    bool same_authority=old && (!resuming||outage<RESUME_WINDOW_MS||!was_blocked)
        && same_authority_data(next,old);
    release(old);
    if (same_authority) {LOCK();suspended=false;UNLOCK();free(next);return true;}
    publish(next); return true;
}
static uint16_t u16(const uint8_t *b) {return (uint16_t)((b[0]<<8)|b[1]);}
/* Bounded header walk. Quotes may contain only IP + eight transport bytes.
 * Routing/AH/ESP, non-atomic fragments and unknown options stay fail-closed. */
static bool decode_at(const struct pbuf *packet,unsigned base,unsigned end,bool quoted,tuple *t,unsigned *transport) {
    uint8_t h[60], tr[20]; memset(t,0,sizeof *t);
    if (!packet || end>packet->tot_len || end<base+20 || pbuf_copy_partial(packet,h,20,base)!=20) return false;
    unsigned off,total;
    t->family=h[0]>>4;
    if (t->family==4) {
        off=(h[0]&15)*4; total=u16(h+2);
        if (off<20 || off>60 || total<off || (u16(h+6)&0xbfff)) return false;
        if (end<base+off || pbuf_copy_partial(packet,h,off,base)!=off) return false;
        for (unsigned i=20;i<off;) {
            unsigned type=h[i++];
            if (!type) break;
            if (type==1) continue;
            if (type!=148 || i+3>off || h[i]!=4) return false; /* Router Alert only. */
            i+=3;
        }
        memcpy(t->src,h+12,4); memcpy(t->dst,h+16,4); t->protocol=h[9];
    } else if (t->family==6) {
        if (end<base+40 || pbuf_copy_partial(packet,h,40,base)!=40 || !u16(h+4)) return false;
        off=40; total=40+u16(h+4);
        memcpy(t->src,h+8,16); memcpy(t->dst,h+24,16); t->protocol=h[6];
        unsigned walked=0;
        while (t->protocol==0 || t->protocol==60 || t->protocol==44) {
            uint8_t ext[8];
            if (++walked>4 || off>256 || total<off+8 || end<base+off+8
                || pbuf_copy_partial(packet,ext,8,base+off)!=8) return false;
            unsigned length=8;
            if (t->protocol==44) {
                if (ext[1] || u16(ext+2)) return false; /* Atomic fragment only. */
            } else {
                if (t->protocol==0 && off!=40) return false;
                length=((unsigned)ext[1]+1)*8;
                if (length>256 || off+length>296 || total<off+length || end<base+off+length) return false;
                for (unsigned i=2;i<length;) {
                    uint8_t option[2];
                    if (pbuf_copy_partial(packet,option,1,base+off+i)!=1) return false;
                    i++;if (!option[0]) continue;
                    if (i>=length || pbuf_copy_partial(packet,option+1,1,base+off+i)!=1) return false;
                    i++;if (i+option[1]>length || (option[0]!=1 && !(t->protocol==0 && option[0]==5 && option[1]==2))) return false;
                    i+=option[1];
                }
            }
            t->protocol=ext[0];off+=length;
        }
    } else return false;
    if ((!quoted && total>end-base) || total<off+8 || end<base+off+8) return false;
    if (t->protocol!=6 && t->protocol!=17 && t->protocol!=1 && t->protocol!=58) return false;
    unsigned minimum=t->protocol==6 && !quoted?20:8;
    if (total<off+(t->protocol==6?20:8) || pbuf_copy_partial(packet,tr,minimum,base+off)!=minimum) return false;
    if (t->protocol==6 || t->protocol==17) {
        t->sport=u16(tr);t->dport=u16(tr+2);
        if (t->protocol==6 && !quoted) {
            unsigned n=(tr[12]>>4)*4;
            if (n<20 || n>total-off) return false;
            t->flags=tr[13];
        } else if (t->protocol==17 && (u16(tr+4)<8 || u16(tr+4)!=total-off)) return false;
    } else {
        t->icmp=tr[0];
        if (t->family==4 ? t->protocol!=1 : t->protocol!=58) return false;
        bool echo=t->family==4 ? tr[0]==0 || tr[0]==8 : tr[0]==128 || tr[0]==129;
        if (echo) {if (tr[1]) return false;t->sport=t->dport=u16(tr+4);}
        else if (quoted || (t->family==4 ? !((tr[0]==3 && tr[1]<=15)||(tr[0]==11 && tr[1]<=1)||(tr[0]==12 && tr[1]<=2))
                                       : !((tr[0]==1 && tr[1]<=7)||(tr[0]==2 && !tr[1])||(tr[0]==3 && tr[1]<=1)||(tr[0]==4 && tr[1]<=2)))) return false;
    }
    if (t->family==4) {
        if (!t->src[0] || t->src[0]==127 || t->src[0]>=224 || !t->dst[0] || t->dst[0]==127
            || t->dst[0]>=224 || (t->dst[0]==169 && t->dst[1]==254)) return false;
    } else {
        static const uint8_t zero[16]={0}, loop[16]={[15]=1};
        if (!memcmp(t->src,zero,16)||!memcmp(t->dst,zero,16)||!memcmp(t->dst,loop,16)
            || t->src[0]==255 || t->dst[0]==255 || (t->dst[0]==0xfe && (t->dst[1]&0xc0)==0x80)) return false;
    }
    if (transport) *transport=base+off;
    return true;
}
static bool decode(const struct pbuf *packet,tuple *t) {
    return packet && decode_at(packet,0,packet->tot_len,false,t,NULL);
}
static bool error_tuple(const tuple *t) {
    return t->protocol==1 ? t->icmp!=0 && t->icmp!=8
         : t->protocol==58 && t->icmp!=128 && t->icmp!=129;
}
static bool peer_owns_scan(const policy *p,const uint8_t key[32],const uint8_t ip[16],uint8_t family);
/* Longest-prefix ownership through the index: for each prefix length, longest
 * first, the networks equal to ip masked to that length (one binary search).
 * Same result as the scan: expired peers are skipped, two peers at the
 * longest matching length tie (no owner). */
static bool peer_owns(const policy *p,const uint8_t key[32],const uint8_t ip[16],uint8_t family) {
    if (!p->index) return peer_owns_scan(p,key,ip,family);
    time_t now=time(NULL);
    int best=-1, owner=-1; bool tied=false;
    unsigned bytes=family==4?4:16;
    for (uint32_t g=0; g<p->ix_group_count && owner<0; g++) {
        const struct owner_group *G=&p->ix_groups[g];
        if (G->family!=family) continue;
        uint8_t net[16]={0};
        for (unsigned i=0;i<bytes;i++) {
            unsigned n=G->bits>i*8?G->bits-i*8:0;
            net[i]=ip[i]&(n>=8?255:(uint8_t)(255<<(8-n)));
        }
        uint32_t lo=G->start, hi=G->end;
        while (lo<hi) {   /* first entry with network >= net */
            uint32_t mid=lo+(hi-lo)/2;
            if (memcmp(p->pool[p->index[mid].prefix].lo,net,16)<0) lo=mid+1; else hi=mid;
        }
        for (uint32_t k=lo;k<G->end && !memcmp(p->pool[p->index[k].prefix].lo,net,16);k++) {
            const peer *a=&p->peers[p->index[k].peer];
            if (!a->active || (a->expires && (now<1700000000 || now>=a->expires))) continue;
            if (owner<0) {owner=(int)p->index[k].peer;best=G->bits;}
            else if (owner!=(int)p->index[k].peer) tied=true;
        }
    }
    if (family==4 && ip[0]==100 && (ip[1]&0xc0)==0x40 && best!=32) return false;
    static const uint8_t tail6[6]={0xfd,0x7a,0x11,0x5c,0xa1,0xe0};
    if (family==6 && !memcmp(ip,tail6,6) && best!=128) return false;
    return owner>=0 && !tied && !memcmp(p->peers[owner].key,key,32);
}
/* Reference scan (working copies; the differential host test). */
static bool peer_owns_scan(const policy *p,const uint8_t key[32],const uint8_t ip[16],uint8_t family) {
    int best=-1, owner=-1; bool tied=false;
    time_t now=time(NULL);
    for (uint32_t i=0;i<p->peer_count;i++) {
        const peer *a=&p->peers[i];
        if (!a->active || (a->expires && (now<1700000000 || now>=a->expires))) continue;
        for (uint32_t j=0;j<a->count;j++) if (contains(&p->pool[a->first+j],ip,family)) {
            int bits=p->pool[a->first+j].bits;
            if (bits>best) {best=bits;owner=(int)i;tied=false;}
            else if (bits==best && owner!=(int)i) tied=true;
        }
    }
    /* Exit/subnet routes must not impersonate another tailnet node. */
    if (family==4 && ip[0]==100 && (ip[1]&0xc0)==0x40 && best!=32) return false;
    static const uint8_t tail6[6]={0xfd,0x7a,0x11,0x5c,0xa1,0xe0};
    if (family==6 && !memcmp(ip,tail6,6) && best!=128) return false;
    return owner>=0 && !tied && !memcmp(p->peers[owner].key,key,32);
}
static bool complete_unexpired(const policy *p) {
    time_t now=time(NULL);
    return p && p->filters_known && p->peers_known && p->local_known
        && (!p->expires || (now>=1700000000 && now<p->expires));
}
/* Enforced now: current, complete, unexpired and not blocked by the
 * control-loss mode. */
static bool ready(const policy *p) {
    LOCK();bool enabled=!blocked() && current==p;UNLOCK();
    return enabled && complete_unexpired(p);
}
/* Confirmed by the live control session (no transport loss since). */
static bool fresh(const policy *p) {
    LOCK();bool enabled=!suspended && current==p;UNLOCK();
    return enabled && complete_unexpired(p);
}
bool ml_policy_reply_age(uint8_t protocol,const uint8_t remote_ip4[4],uint16_t remote_port,uint32_t *age_ms) {
    if(!remote_ip4||!age_ms)return false;
    policy *p=acquire();if(!p)return false;
    bool found=false;uint32_t now=NOW(),best=0;LOCK();
    if(current==p&&!blocked())for(unsigned i=0;i<FLOWS;i++){
        const flow *f=&p->flows[i];
        if(!f->used||!f->replied||f->epoch!=p->epoch||f->reverse.family!=4||f->reverse.protocol!=protocol
            ||f->reverse.sport!=remote_port||memcmp(f->reverse.src,remote_ip4,4))continue;
        uint32_t age=now-f->replied;if(!found||age<best){best=age;found=true;}
    }
    UNLOCK();release(p);if(found)*age_ms=best;return found;
}
bool ml_policy_authority_active(void) {
    policy *p=acquire();bool ok=p&&fresh(p);release(p);return ok;
}
void ml_policy_get_status(ml_policy_status_t *out) {
    if(!out)return;
    memset(out,0,sizeof *out);policy *p=acquire();
    if(!p)return;
    out->authority_ready=ready(p);out->peer_authority=p->peers_known;out->self_expires=(int64_t)p->expires;
    out->filter_authority=p->filters_known;out->self_authority=p->local_known;
    out->expanded_rules=p->count;
    for(uint32_t i=0;i<p->peer_count;i++)if(p->peers[i].active)out->peers++;
    uint32_t now=NOW();LOCK();
    out->control_stale=suspended&&!blocked()&&current==p;
    out->stale_ms=suspended?(uint32_t)(now-suspended_at):0;
    if(current==p&&!blocked()){
        for(unsigned i=0;i<FLOWS;i++){
            const flow *f=&p->flows[i];uint32_t timeout=f->reverse.protocol==6?120000:f->reverse.protocol==17?30000:10000;
            if(f->used && f->epoch==p->epoch && now-f->touched<=timeout)out->return_flows++;
        }
    }else memset(out,0,sizeof *out);
    UNLOCK();release(p);
}
int ml_policy_peer_status(const uint8_t key[32]) {
    policy *p=acquire();int status=-1;time_t now=time(NULL);
    if (p && p->peers_known && key) {
        status=0;
        for (uint32_t i=0;i<p->peer_count;i++) {
            const peer *a=&p->peers[i];
            if (a->active && !memcmp(a->key,key,32)
                && (!a->expires || (now>=1700000000 && now<a->expires))) {status=1;break;}
        }
    }
    LOCK();if (current!=p || suspended) status=-1;UNLOCK();release(p);return status;
}
static bool same(const tuple *a,const tuple *b) {
    return a->family==b->family && a->protocol==b->protocol && a->sport==b->sport && a->dport==b->dport
        && !memcmp(a->src,b->src,16) && !memcmp(a->dst,b->dst,16);
}
int ml_policy_peer_key(uint64_t id,uint8_t key[32]) {
    if(!id||!key)return 0;
    policy *p=acquire();int status=-1;time_t now=time(NULL);
    if(p&&p->peers_known){
        status=0;
        for(uint32_t i=0;i<p->peer_count;i++)if(p->peers[i].active&&p->peers[i].id==id
            &&(!p->peers[i].expires||(now>=1700000000&&now<p->peers[i].expires))){memcpy(key,p->peers[i].key,32);status=1;break;}
    }
    LOCK();if(current!=p||suspended)status=-1;UNLOCK();release(p);return status;
}
static bool flow_allowed(policy *p,const tuple *t,const uint8_t key[32],bool reply) {
    if (t->protocol==6 && (t->flags&0x02) && !(t->flags&0x10)) return false;
    if ((t->protocol==1 && t->icmp!=0)||(t->protocol==58 && t->icmp!=129)) return false;
    bool ok=false; uint32_t now=NOW();
    LOCK();
    if (current==p&&!blocked()) for (unsigned i=0;i<FLOWS;i++) {
        flow *f=&p->flows[i]; uint32_t limit=t->protocol==6?120000:t->protocol==17?30000:10000;
        if (f->used && f->epoch==p->epoch && now-f->touched<=limit && !memcmp(f->key,key,32) && same(&f->reverse,t)) {
            f->touched=now;if(reply)f->replied=now?now:1;ok=true;break;
        }
    }
    UNLOCK();return ok;
}
static bool local_owns(const policy *p,const uint8_t ip[16],unsigned family) {
    for (uint32_t i=0;i<p->local_count;i++) if (contains(&p->pool[p->local_first+i],ip,family)) return true;
    return false;
}
bool ml_policy_fragment_epoch(const uint8_t src[16],const uint8_t dst[16],unsigned family,const uint8_t key[32],uint32_t *out) {
    if(!src||!dst||!key||!out||(family!=4&&family!=6))return false;
    policy *p=acquire();bool ok=ready(p)&&peer_owns(p,key,src,(uint8_t)family)&&local_owns(p,dst,family);
    LOCK();ok=ok&&current==p&&!blocked();if(ok)*out=p->epoch;UNLOCK();release(p);return ok;
}
bool ml_policy_tx_fragment_epoch(const uint8_t src[16],const uint8_t dst[16],unsigned family,const uint8_t key[32],uint32_t *out) {
    if(!src||!dst||!key||!out||(family!=4&&family!=6))return false;
    if(family==4){
        if(!src[0]||src[0]==127||src[0]>=224||!dst[0]||dst[0]==127||dst[0]>=224
           ||(dst[0]==169&&dst[1]==254))return false;
    }else{
        static const uint8_t zero[16]={0},loop[16]={[15]=1};
        if(!memcmp(src,zero,16)||!memcmp(dst,zero,16)||!memcmp(dst,loop,16)||src[0]==255||dst[0]==255
           ||(dst[0]==0xfe&&(dst[1]&0xc0)==0x80))return false;
    }
    /* TX uses the receiving peer's independent service policy. Local inbound
     * grants do not apply to client-originated TCP/UDP traffic or its fragments. */
    policy *p=acquire();bool ok=ready(p)&&peer_owns(p,key,dst,(uint8_t)family);
    LOCK();ok=ok&&current==p&&!blocked();if(ok)*out=p->epoch;UNLOCK();release(p);return ok;
}
static bool rule_allowed(const policy *p,const tuple *t) {
    for (unsigned i=0;i<p->count;i++) {
        const entry *e=&p->entries[i];
        if (!(e->protocols[t->protocol/8] & (1<<(t->protocol%8))) || !contains(&e->src,t->src,t->family)
            || !contains(&e->dst,t->dst,t->family)) continue;
        if (t->protocol==1 || t->protocol==58 || (t->dport>=e->first && t->dport<=e->last)) return true;
    }
    return false;
}
static bool related_error(policy *p,const struct pbuf *packet,const tuple *outer,const uint8_t key[32],bool inbound) {
    tuple checked,quote;unsigned off;
    if (!decode_at(packet,0,packet->tot_len,false,&checked,&off)) return false;
    /* Do not let WG padding extend a deliberately truncated ICMP quote. */
    uint8_t sizes[6];if (pbuf_copy_partial(packet,sizes,6,0)!=6) return false;
    unsigned end=outer->family==4 ? u16(sizes+2) : 40+u16(sizes+4);
    if (!decode_at(packet,off+8,end,true,&quote,NULL) || quote.family!=outer->family
        || memcmp(outer->dst,quote.src,16)) return false;
    if (!inbound) return peer_owns(p,key,quote.src,quote.family) && local_owns(p,quote.dst,quote.family)
                         && (rule_allowed(p,&quote) || flow_allowed(p,&quote,key,false));
    if (!local_owns(p,quote.src,quote.family) || !peer_owns(p,key,quote.dst,quote.family)) return false;
    tuple reverse=quote;memcpy(reverse.src,quote.dst,16);memcpy(reverse.dst,quote.src,16);
    reverse.sport=quote.dport;reverse.dport=quote.sport;
    /* Bound error admission to a successfully sent flow, same WG key/epoch.
     * Error traffic never creates or refreshes state (no keepalive by errors). */
    bool ok=false;uint32_t now=NOW();LOCK();
    if (current==p) for (unsigned i=0;i<FLOWS;i++) {
        const flow *f=&p->flows[i];uint32_t limit=quote.protocol==6?120000:quote.protocol==17?30000:10000;
        if (f->used && f->epoch==p->epoch && now-f->touched<=limit
            && !memcmp(f->key,key,32) && same(&f->reverse,&reverse)) {ok=true;break;}
    }
    UNLOCK();return ok;
}
bool ml_policy_rx(const struct pbuf *packet,const uint8_t key[32]) {
    tuple t; if (!key || !decode(packet,&t)) return false;
    policy *p=acquire(); bool ok=false;
    if (!ready(p)||!peer_owns(p,key,t.src,t.family)) goto done;
    if (!local_owns(p,t.dst,t.family)) goto done;
    if (error_tuple(&t)) {ok=related_error(p,packet,&t,key,true);goto done;}
    if (flow_allowed(p,&t,key,true)) {ok=true;goto done;}
    ok=rule_allowed(p,&t);
done:
    /* A concurrently revoked snapshot cannot grant a new packet. Admission is
     * linearized here, BEFORE translation/queueing, not at socket delivery. */
    LOCK(); ok=ok && current==p && !blocked(); UNLOCK();
    release(p); return ok;
}
bool ml_policy_tx(const struct pbuf *packet,const uint8_t key[32]) {
    tuple t; if (!key || !decode(packet,&t)) return false;
    policy *p=acquire(); bool ok=ready(p) && peer_owns(p,key,t.dst,t.family);
    if (ok && error_tuple(&t)) ok=related_error(p,packet,&t,key,false);
    LOCK();ok=ok && current==p && !blocked();UNLOCK();release(p);return ok;
}
void ml_policy_sent(const struct pbuf *packet,const uint8_t key[32]) {
    ml_policy_sent_epoch(packet,key,0);
}
void ml_policy_sent_epoch(const struct pbuf *packet,const uint8_t key[32],uint32_t expected) {
    tuple t; if (!key || !decode(packet,&t)) return;
    if (error_tuple(&t)) return;
    bool initiate=t.protocol==17 || (t.protocol==6 && (t.flags&0x12)==0x02)
        || (t.protocol==1 && t.icmp==8) || (t.protocol==58 && t.icmp==128);
    policy *p=acquire();
    if (!ready(p)||(expected&&p->epoch!=expected)||!peer_owns(p,key,t.dst,t.family)) {release(p);return;}
    tuple reverse=t;
    memcpy(reverse.src,t.dst,16);memcpy(reverse.dst,t.src,16);reverse.sport=t.dport;reverse.dport=t.sport;
    uint32_t now=NOW();int slot=-1;uint32_t oldest=0;
    LOCK();
    if (current==p && !blocked()) {
        for (unsigned i=0;i<FLOWS;i++) {
            flow *f=&p->flows[i];
            if (f->used && f->epoch==p->epoch && !memcmp(f->key,key,32) && same(&f->reverse,&reverse)) {slot=(int)i;break;}
            if (!f->used || slot<0 || now-f->touched>oldest) {slot=(int)i;oldest=now-f->touched;}
        }
        bool existing=slot>=0 && p->flows[slot].used && same(&p->flows[slot].reverse,&reverse) && !memcmp(p->flows[slot].key,key,32);
        if (slot>=0 && (initiate || existing)) {
            flow *f=&p->flows[slot];if(!existing)f->replied=0;
            f->reverse=reverse;memcpy(f->key,key,32);f->epoch=p->epoch;f->touched=now;f->used=true;
        }
    }
    UNLOCK();release(p);
}

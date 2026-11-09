/* Tailnet DNS settings from the control plane: see ml_dns_config.h. */
#include "ml_dns_config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"

#ifdef ML_DNS_HOST_TEST
#define LOCK()   do {} while (0)
#define UNLOCK() do {} while (0)
#define STORE_ALLOC(n) calloc(1, (n))
#define STORE_FREE(p) free(p)
#define SELF_ATTR
#else
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_heap_caps.h"
#include "esp_attr.h"
static SemaphoreHandle_t s_mtx;
static portMUX_TYPE s_init_mux = portMUX_INITIALIZER_UNLOCKED;
static void lock(void)
{
    if (!s_mtx) {
        SemaphoreHandle_t m = xSemaphoreCreateMutex();
        taskENTER_CRITICAL(&s_init_mux);
        if (!s_mtx) {s_mtx = m; m = NULL;}
        taskEXIT_CRITICAL(&s_init_mux);
        if (m) vSemaphoreDelete(m);
    }
    if (s_mtx) xSemaphoreTake(s_mtx, portMAX_DELAY);
}
#define LOCK()   lock()
#define UNLOCK() do { if (s_mtx) xSemaphoreGive(s_mtx); } while (0)
#define STORE_ALLOC(n) heap_caps_calloc(1, (n), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)
#define STORE_FREE(p) heap_caps_free(p)
#define SELF_ATTR EXT_RAM_BSS_ATTR
#endif

typedef struct {
    char domain[ML_DNS_NAME_MAX];
    uint8_t n;
    uint32_t addr[ML_DNS_MAX_ROUTE_ADDRS];
} route_t;

typedef struct {
    char name[ML_DNS_NAME_MAX];
    uint32_t ip;
} extra_t;

typedef struct {
    bool magic_dns;
    uint8_t n_res, n_routes, n_domains, n_extra;
    uint16_t ignored;
    uint32_t res[ML_DNS_MAX_RESOLVERS];
    route_t routes[ML_DNS_MAX_ROUTES];
    char domains[ML_DNS_MAX_DOMAINS][ML_DNS_NAME_MAX];
    extra_t extra[ML_DNS_MAX_EXTRA];
} store_t;

static store_t *s_store;
static uint32_t s_version;
static SELF_ATTR char s_self[ML_DNS_NAME_MAX];

/* Lower case, no final dot; false if empty, too long or not a DNS name. */
static bool norm(const char *in, char out[ML_DNS_NAME_MAX])
{
    if (!in) return false;
    size_t n = strlen(in);
    while (n && in[n - 1] == '.') n--;
    if (!n || n >= ML_DNS_NAME_MAX) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)in[i];
        if (!(isalnum(c) || c == '-' || c == '.' || c == '_')) return false;
        out[i] = (char)tolower(c);
    }
    out[n] = 0;
    return true;
}

/* Plain dotted IPv4, optionally ":53". */
static bool parse_v4(const char *s, uint32_t *nbo)
{
    if (!s) return false;
    unsigned a, b, c, d, port = 53;
    char tail[8] = "";
    int got = sscanf(s, "%3u.%3u.%3u.%3u%7s", &a, &b, &c, &d, tail);
    if (got < 4 || a > 255 || b > 255 || c > 255 || d > 255) return false;
    if (got == 5) {
        char *end = NULL;
        if (tail[0] != ':') return false;
        port = (unsigned)strtoul(tail + 1, &end, 10);
        if (!end || *end || port != 53) return false;
    }
    if (!(a | b | c | d)) return false;
    uint8_t q[4] = {(uint8_t)a, (uint8_t)b, (uint8_t)c, (uint8_t)d};
    memcpy(nbo, q, 4);
    return true;
}

static void parse_resolvers(const cJSON *arr, uint32_t *out, uint8_t max, uint8_t *n, uint16_t *ignored)
{
    const cJSON *r;
    cJSON_ArrayForEach(r, arr) {
        uint32_t ip;
        const cJSON *addr = cJSON_GetObjectItemCaseSensitive(r, "Addr");
        if (cJSON_IsString(addr) && parse_v4(addr->valuestring, &ip) && *n < max) out[(*n)++] = ip;
        else (*ignored)++;
    }
}

static void parse_config(store_t *c, const cJSON *dns)
{
    memset(c, 0, sizeof *c);
    c->magic_dns = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(dns, "Proxied"));
    parse_resolvers(cJSON_GetObjectItemCaseSensitive(dns, "Resolvers"), c->res, ML_DNS_MAX_RESOLVERS, &c->n_res, &c->ignored);
    const cJSON *routes = cJSON_GetObjectItemCaseSensitive(dns, "Routes"), *rt;
    cJSON_ArrayForEach(rt, routes) {
        route_t r = {0};
        uint16_t bad = 0;
        if (c->n_routes >= ML_DNS_MAX_ROUTES || !norm(rt->string, r.domain)) {c->ignored++; continue;}
        parse_resolvers(rt, r.addr, ML_DNS_MAX_ROUTE_ADDRS, &r.n, &bad);
        c->ignored += bad;
        /* A route whose resolvers were all unsupported must not turn into a
         * "local" route that answers NXDOMAIN: skip it instead. */
        if (!r.n && cJSON_GetArraySize(rt) > 0) {c->ignored++; continue;}
        c->routes[c->n_routes++] = r;
    }
    const cJSON *dom;
    cJSON_ArrayForEach(dom, cJSON_GetObjectItemCaseSensitive(dns, "Domains")) {
        if (c->n_domains < ML_DNS_MAX_DOMAINS && cJSON_IsString(dom) && norm(dom->valuestring, c->domains[c->n_domains])) c->n_domains++;
        else c->ignored++;
    }
    const cJSON *rec;
    cJSON_ArrayForEach(rec, cJSON_GetObjectItemCaseSensitive(dns, "ExtraRecords")) {
        const cJSON *name = cJSON_GetObjectItemCaseSensitive(rec, "Name"), *type = cJSON_GetObjectItemCaseSensitive(rec, "Type"),
                    *value = cJSON_GetObjectItemCaseSensitive(rec, "Value");
        bool a_type = !type || (cJSON_IsString(type) && (!type->valuestring[0] || !strcmp(type->valuestring, "A")));
        extra_t e = {0};
        if (c->n_extra < ML_DNS_MAX_EXTRA && a_type && cJSON_IsString(name) && norm(name->valuestring, e.name) &&
            cJSON_IsString(value) && strchr(value->valuestring, ':') == NULL && parse_v4(value->valuestring, &e.ip))
            c->extra[c->n_extra++] = e;
        else c->ignored++;
    }
}

void ml_dns_apply_map(const cJSON *map)
{
    if (!map) return;
    const cJSON *node = cJSON_GetObjectItemCaseSensitive(map, "Node");
    const cJSON *name = node ? cJSON_GetObjectItemCaseSensitive(node, "Name") : NULL;
    char self[ML_DNS_NAME_MAX];
    bool have_self = cJSON_IsString(name) && norm(name->valuestring, self);
    const cJSON *dns = cJSON_GetObjectItemCaseSensitive(map, "DNSConfig");
    bool have_dns = cJSON_IsObject(dns);
    if (!have_self && !have_dns) return;
    store_t *fresh = NULL;
    if (have_dns) {
        fresh = STORE_ALLOC(sizeof *fresh);
        if (!fresh) return;                         /* keep the previous settings */
        parse_config(fresh, dns);
    }
    store_t *old = NULL;
    LOCK();
    if (have_self && strcmp(s_self, self)) {memcpy(s_self, self, sizeof s_self); s_version++;}
    if (fresh) {old = s_store; s_store = fresh; s_version++;}
    UNLOCK();
    if (old) STORE_FREE(old);
}

void ml_dns_reset(void)
{
    LOCK();
    store_t *old = s_store;
    s_store = NULL; s_self[0] = 0; s_version++;
    UNLOCK();
    if (old) STORE_FREE(old);
}

bool ml_dns_self_name(char out[ML_DNS_NAME_MAX])
{
    LOCK();
    memcpy(out, s_self, ML_DNS_NAME_MAX);
    UNLOCK();
    return out[0] != 0;
}

static bool extra_find(const char *n, uint32_t *ip)
{
    for (int i = 0; s_store && i < s_store->n_extra; i++)
        if (!strcmp(s_store->extra[i].name, n)) {*ip = s_store->extra[i].ip; return true;}
    return false;
}

bool ml_dns_extra_lookup(const char *name, uint32_t *ip_nbo)
{
    char n[ML_DNS_NAME_MAX];
    if (!norm(name, n)) return false;
    LOCK();
    bool ok = extra_find(n, ip_nbo);
    UNLOCK();
    return ok;
}

bool ml_dns_extra_lookup_search(const char *bare, uint32_t *ip_nbo)
{
    char n[ML_DNS_NAME_MAX], full[ML_DNS_NAME_MAX];
    if (!norm(bare, n) || strchr(n, '.')) return false;
    bool ok = false;
    LOCK();
    for (int i = 0; !ok && s_store && i < s_store->n_domains; i++) {
        int w = snprintf(full, sizeof full, "%s.%s", n, s_store->domains[i]);
        if (w > 0 && w < (int)sizeof full) ok = extra_find(full, ip_nbo);
    }
    UNLOCK();
    return ok;
}

int ml_dns_route(const char *name, uint32_t *addr_nbo)
{
    char n[ML_DNS_NAME_MAX];
    if (!norm(name, n)) return ML_DNS_ROUTE_NONE;
    size_t nl = strlen(n), best = 0;
    int kind = ML_DNS_ROUTE_NONE;
    LOCK();
    for (int i = 0; s_store && i < s_store->n_routes; i++) {
        const route_t *r = &s_store->routes[i];
        size_t dl = strlen(r->domain);
        bool match = nl == dl ? !strcmp(n, r->domain) : nl > dl && n[nl - dl - 1] == '.' && !strcmp(n + nl - dl, r->domain);
        if (!match || dl <= best) continue;
        best = dl;
        if (r->n) {kind = ML_DNS_ROUTE_FWD; if (addr_nbo) *addr_nbo = r->addr[0];}
        else kind = ML_DNS_ROUTE_LOCAL;
    }
    UNLOCK();
    return kind;
}

uint32_t ml_dns_global_resolver(void)
{
    LOCK();
    uint32_t r = s_store && s_store->n_res ? s_store->res[0] : 0;
    UNLOCK();
    return r;
}

void ml_dns_summary(ml_dns_summary_t *out)
{
    memset(out, 0, sizeof *out);
    LOCK();
    out->version = s_version;
    memcpy(out->self, s_self, sizeof out->self);
    if (s_store) {
        out->present = true;
        out->magic_dns = s_store->magic_dns;
        out->resolvers = s_store->n_res; out->routes = s_store->n_routes;
        out->domains = s_store->n_domains; out->extra = s_store->n_extra; out->ignored = s_store->ignored;
    }
    UNLOCK();
}

/* Exact 64-bit integers in control-server JSON (see ml_json_id.h). */
#include "ml_json_id.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t *s_ids;   /* exact values, by token number */
static size_t s_count, s_cap;

#define JSON_ID_EXACT_LIMIT 9007199254740992.0   /* 2^53: every integer below it is exact as a double */
#define JSON_ID_TOKEN_BASE  90000000000000.0     /* tokens are -(base + n): 15 characters at most */

void ml_json_ids_clear(void)
{
    free(s_ids);
    s_ids = NULL;
    s_count = s_cap = 0;
}

static bool json_ids_add(uint64_t exact)
{
    if (s_count >= ML_JSON_IDS_MAX) return false;
    if (s_count == s_cap) {
        size_t cap = s_cap ? s_cap * 2 : 64;
        if (cap > ML_JSON_IDS_MAX) cap = ML_JSON_IDS_MAX;
        uint64_t *grown = realloc(s_ids, cap * sizeof *grown);
        if (!grown) return false;
        s_ids = grown;
        s_cap = cap;
    }
    s_ids[s_count++] = exact;
    return true;
}

bool ml_json_ids_scan(char *text, size_t len)
{
    ml_json_ids_clear();
    bool in_string = false, escaped = false;
    char prev = 0;   /* last character outside strings and whitespace */
    for (size_t i = 0; text && i < len; i++) {
        char c = text[i];
        if (in_string) {
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') { in_string = false; prev = '"'; }
            continue;
        }
        if (c == '"') { in_string = true; continue; }
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        if (c >= '0' && c <= '9' && (prev == ':' || prev == '[' || prev == ',')) {
            size_t start = i;
            while (i < len && text[i] >= '0' && text[i] <= '9') i++;
            size_t digits = i - start;
            char next = i < len ? text[i] : 0;
            bool integer = next != '.' && next != 'e' && next != 'E';
            /* Below 16 digits every value is under 2^53 and exact already;
             * above 20 it is no 64-bit integer (left as it is, refused). */
            if (integer && digits >= 16 && digits <= 20 && text[start] != '0') {
                char literal[21];
                memcpy(literal, text + start, digits);
                literal[digits] = 0;
                bool overflow = digits == 20 && strcmp(literal, "18446744073709551615") > 0;
                if (!overflow) {
                    if (!json_ids_add(strtoull(literal, NULL, 10))) {
                        ml_json_ids_clear();
                        return false;
                    }
                    char token[24];
                    int n = snprintf(token, sizeof token, "-%.0f", JSON_ID_TOKEN_BASE + (double)(s_count - 1));
                    memset(text + start, ' ', digits);
                    memcpy(text + start + digits - (size_t)n, token, (size_t)n);
                }
            }
            prev = '0';
            i--;   /* the loop moves past the last digit */
            continue;
        }
        prev = c;
    }
    return true;
}

bool ml_json_u64(const cJSON *item, uint64_t max, uint64_t *out)
{
    if (!cJSON_IsNumber(item) || !isfinite(item->valuedouble) || floor(item->valuedouble) != item->valuedouble)
        return false;
    double v = item->valuedouble;
    uint64_t exact;
    if (v >= 0) {
        if (v >= JSON_ID_EXACT_LIMIT) return false;   /* rounded: not from a scanned message */
        exact = (uint64_t)v;
    } else {
        double n = -v - JSON_ID_TOKEN_BASE;
        if (n < 0 || n >= (double)s_count) return false;   /* not a token of the last message */
        exact = s_ids[(size_t)n];
    }
    if (exact > max) return false;
    *out = exact;
    return true;
}

/* Exact 64-bit integers (node IDs) in control-server JSON.
 *
 * cJSON keeps every number as a double, which is exact only up to 2^53.
 * Tailscale node IDs are int64, and IDs of recently created nodes are above
 * 2^53: read through valuedouble they came out rounded, so the policy
 * refused them (whole map refused, tunnel blocked: "reason=peer-id") and two
 * nodes could share one ID.
 *
 * Before a control message is parsed, ml_json_ids_scan() replaces each
 * integer literal of 16 or more digits (outside strings) in place, with the
 * same length, by blanks and a token "-<base + n>" that a double holds
 * exactly, and keeps the exact value as entry n. ml_json_u64() turns a
 * parsed number back into the exact integer: small ones directly, tokens
 * through the table. Every integer of 16+ digits in a control message is an
 * ID; no other reader of the map uses such numbers. Single task
 * (coordination): the table holds the last scanned message. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "cJSON.h"

#define ML_JSON_IDS_MAX 16384   /* large integers kept per message (8 bytes each) */

/* Rewrites text[0..len) as described above. False when out of memory or
 * over ML_JSON_IDS_MAX: the table is then empty, and every token or large
 * integer of the message fails in ml_json_u64() (fail closed). */
bool ml_json_ids_scan(char *text, size_t len);
/* The exact value of a JSON integer in [0, max]; false otherwise. */
bool ml_json_u64(const cJSON *item, uint64_t max, uint64_t *out);
void ml_json_ids_clear(void);

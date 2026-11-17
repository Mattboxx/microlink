/* When a RegisterRequest carries the auth key.
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The control plane consumes a single-use auth key at the first registration
 * and refuses it afterwards ("invalid key"), also when the node key is
 * already registered (tailscale/tailscale#19501). The reference client only
 * presents the key to log in (tsnet: "Authkey is set; but state is ...
 * Ignoring authkey"). MicroLink registers on every control reconnect, so
 * presenting the key each time took a working single-use registration
 * offline at the first reconnect or restart.
 *
 * Rule: present the key only while this identity has not been accepted with
 * this key. A record of the accepted identity (node public key + a hash of
 * the key, never the key) persists across restarts. The server stays the
 * authority: a refused key is retried once without it (the device may
 * already be registered, e.g. the response to the consuming registration
 * was lost), and a server that asks for authorization gets the key once. */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#define ML_REG_MARKER_LEN 64

typedef struct {
    bool registered;   /* this identity was accepted with this key (persisted record) */
    bool refused;      /* the server refused the key this boot: do not present it again */
    bool needed;       /* the server asked for authorization: present the key once */
} ml_reg_auth_t;

typedef enum {
    ML_REG_ACCEPTED,   /* registered: record it, continue */
    ML_REG_RETRY,      /* retry now with the other key choice */
    ML_REG_REFUSED,    /* nothing left to try: a new auth key or approval is needed */
} ml_reg_outcome_t;

/* Present the configured key in this RegisterRequest? */
bool ml_reg_auth_send_key(const ml_reg_auth_t *s, bool have_key);

/* Applies a RegisterResponse. error: RegisterResponse.Error was set.
 * needs_auth: AuthURL was set (the server does not authorize this node).
 * *note: a static, value-free explanation for diagnostics. */
ml_reg_outcome_t ml_reg_auth_result(ml_reg_auth_t *s, bool have_key, bool sent_key,
                                    bool error, bool needs_auth, const char **note);

/* Record of the accepted identity: node public key + keyed hash of the auth
 * key (all zero without a key). */
void ml_reg_marker(uint8_t out[ML_REG_MARKER_LEN], const uint8_t node_public_key[32], const char *auth_key);

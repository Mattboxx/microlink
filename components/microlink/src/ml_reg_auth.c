/* When a RegisterRequest carries the auth key (see ml_reg_auth.h).
 * SPDX-License-Identifier: GPL-3.0-only */
#include "ml_reg_auth.h"

#include <string.h>
#include "blake2s.h"

bool ml_reg_auth_send_key(const ml_reg_auth_t *s, bool have_key)
{
    return have_key && !s->refused && (s->needed || !s->registered);
}

ml_reg_outcome_t ml_reg_auth_result(ml_reg_auth_t *s, bool have_key, bool sent_key,
                                    bool error, bool needs_auth, const char **note)
{
    const char *why = NULL;
    ml_reg_outcome_t out;
    if (error) {
        if (sent_key) {
            /* Used, expired, revoked or mistyped. The device may still be
             * registered (the consuming registration's response was lost,
             * or a new key was entered for a registered device). */
            s->refused = true;
            s->needed = false;
            why = "auth key refused; retrying without it";
            out = ML_REG_RETRY;
        } else {
            why = "registration refused by the control server";
            out = ML_REG_REFUSED;
        }
    } else if (needs_auth) {
        if (!sent_key && have_key && !s->refused) {
            s->needed = true;
            s->registered = false;
            why = "not registered; retrying with the auth key";
            out = ML_REG_RETRY;
        } else {
            s->registered = false;
            why = have_key ? "not authorized: a new auth key is needed"
                           : "not authorized: an auth key is needed";
            out = ML_REG_REFUSED;
        }
    } else {
        s->registered = true;
        s->needed = false;
        out = ML_REG_ACCEPTED;
    }
    if (note) *note = why;
    return out;
}

void ml_reg_marker(uint8_t out[ML_REG_MARKER_LEN], const uint8_t node_public_key[32], const char *auth_key)
{
    memcpy(out, node_public_key, 32);
    memset(out + 32, 0, 32);
    if (auth_key && auth_key[0]) {
        static const char label[] = "microlink registration auth key v1";
        blake2s_ctx ctx;
        blake2s_init(&ctx, 32, node_public_key, 32);   /* keyed by the identity */
        blake2s_update(&ctx, label, sizeof label);
        blake2s_update(&ctx, auth_key, strlen(auth_key));
        blake2s_final(&ctx, out + 32);
    }
}

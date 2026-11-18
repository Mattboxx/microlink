#pragma once

/* TLS certificates that must never be trusted, even when a root in the
 * ESP-IDF certificate bundle still vouches for them.
 *
 * October 2026: the private keys of eight eMudhra intermediate CAs (P-384,
 * private scalars below 256) can be derived by anyone from the public
 * certificates, so anyone can issue a certificate for any name that chains to
 * "emSign ECC Root CA - G3" or "AAA Certificate Services", both still in the
 * bundle. Browsers, Go 1.27.3 (Tailscale TS-2026-013) and the OS stores block
 * them by public key; the ESP has no revocation checking, so it is done here
 * by the SHA-256 of each certificate's SubjectPublicKeyInfo, which also
 * covers their Sectigo cross-signs. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ML_TLS_DISTRUSTED_COUNT 8

/* True when the DER SubjectPublicKeyInfo belongs to a distrusted CA. */
bool ml_tls_spki_distrusted(const uint8_t *spki_der, size_t len);

/* Drop-in replacement for esp_crt_bundle_attach() (an mbedtls_ssl_config *
 * or NULL): attaches the bundle, then refuses any chain that contains a
 * distrusted certificate at any depth. Use it for every esp_tls,
 * esp_http_client, esp-mqtt and direct mbedTLS client that uses the bundle. */
esp_err_t ml_tls_bundle_attach(void *conf);

/* Chains refused because of a distrusted certificate since boot. */
uint32_t ml_tls_distrust_refusals(void);

/* Private trust anchors for the tailnet's own TLS connections only: a
 * Headscale login server over HTTPS and its DERP relays, with a private CA or
 * a self-signed certificate. ml_tls_tailnet_attach() is ml_tls_bundle_attach()
 * plus these anchors; it is used by the control and DERP connections and
 * nowhere else, so firmware updates, MQTT and notifications keep the public
 * bundle only. The certificate name, validity and the distrust list are still
 * checked: these anchors add trust, they never turn verification off.
 *
 * ml_tls_set_tailnet_ca(): PEM text with 1 to ML_TLS_TAILNET_CA_CERTS
 * certificates (at most ML_TLS_TAILNET_CA_MAX bytes); NULL or "" removes them.
 * Call it before the tailnet connections start (the gateway does at boot).
 * Fails (and keeps nothing) on invalid, empty, oversized or distrusted input. */
#define ML_TLS_TAILNET_CA_MAX   3999   /* one NVS string with its terminator */
#define ML_TLS_TAILNET_CA_CERTS 4
esp_err_t ml_tls_set_tailnet_ca(const char *pem);
bool ml_tls_tailnet_ca_set(void);
esp_err_t ml_tls_tailnet_attach(void *conf);
/* Checks PEM text as ml_tls_set_tailnet_ca() would, without keeping it:
 * returns the number of certificates (0 when invalid) and the SHA-256 of the
 * first one in hex (65 bytes) and its subject (subject_size bytes). */
int ml_tls_check_tailnet_ca(const char *pem, char fingerprint_hex[65], char *subject, size_t subject_size);

#ifdef __cplusplus
}
#endif

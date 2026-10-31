/* SPDX-License-Identifier: MIT
 * Test-only packet-path stage counters; see ml_perf.h. Empty unless the build
 * defines TSR_PERF_PROFILE=1. */
#include <string.h>
#include "ml_perf.h"
#if defined(TSR_PERF_PROFILE) && TSR_PERF_PROFILE
#include "freertos/FreeRTOS.h"
/* Test-only stage counters (see ml_perf.h); a spinlock because the RX manager
 * task and the TCPIP thread update them from either core. */
const char *const ml_perf_stage_names[ML_PERF_STAGES] = {
	"rx_queue_us", "rx_total", "rx_copy", "rx_alloc", "rx_memset", "rx_poly", "rx_chacha",
	"tx_total", "tx_alloc", "tx_memset", "tx_copy", "tx_chacha", "tx_poly", "tx_output",
};
static ml_perf_counter_t s_ml_perf[ML_PERF_STAGES];
static portMUX_TYPE s_ml_perf_lock = portMUX_INITIALIZER_UNLOCKED;

void ml_perf_add(ml_perf_stage_t stage, uint32_t value, uint32_t bytes, int migrated) {
	if ((unsigned)stage >= ML_PERF_STAGES) return;
	portENTER_CRITICAL_SAFE(&s_ml_perf_lock);
	ml_perf_counter_t *c = &s_ml_perf[stage];
	if (migrated) {
		c->migrated++;
	} else {
		c->total += value;
		c->bytes += bytes;
		c->count++;
		if (value > c->max) c->max = value;
	}
	portEXIT_CRITICAL_SAFE(&s_ml_perf_lock);
}

void ml_perf_snapshot(ml_perf_counter_t out[ML_PERF_STAGES], int reset) {
	portENTER_CRITICAL_SAFE(&s_ml_perf_lock);
	memcpy(out, s_ml_perf, sizeof s_ml_perf);
	if (reset) memset(s_ml_perf, 0, sizeof s_ml_perf);
	portEXIT_CRITICAL_SAFE(&s_ml_perf_lock);
}
#endif

/* SPDX-License-Identifier: MIT
 * Test-only packet-path profiling (Mattboxx performance roadmap).
 *
 * Compiled only when the build defines TSR_PERF_PROFILE=1 (the firmware
 * version then ends in "-prof"); otherwise every macro below expands to
 * nothing and no code or data is added. Stages count CPU cycles of the core
 * that ran them; a sample whose task moved to the other core in between is
 * counted as "migrated" instead of being added. Queue residence is in
 * microseconds (it spans tasks). Not for release images.
 */
#ifndef ML_PERF_H
#define ML_PERF_H

#include <stdint.h>

typedef enum {
    ML_PERF_RX_QUEUE_US,    /* wg_rx_queue residence, microseconds */
    ML_PERF_RX_TOTAL,       /* manager: one received WireGuard packet */
    ML_PERF_RX_COPY,        /* manager: pbuf_alloc + copy of the queued packet */
    ML_PERF_RX_ALLOC,       /* data message: plaintext pbuf_alloc */
    ML_PERF_RX_MEMSET,      /* data message: zeroing of the plaintext pbuf */
    ML_PERF_RX_POLY,        /* decrypt: Poly1305 key + authentication */
    ML_PERF_RX_CHACHA,      /* decrypt: ChaCha20 */
    ML_PERF_TX_TOTAL,       /* output: one transmitted WireGuard packet */
    ML_PERF_TX_ALLOC,
    ML_PERF_TX_MEMSET,
    ML_PERF_TX_COPY,        /* pbuf_copy_partial of the plaintext */
    ML_PERF_TX_CHACHA,      /* encrypt: ChaCha20 (with Poly1305 key block) */
    ML_PERF_TX_POLY,        /* encrypt: Poly1305 */
    ML_PERF_TX_OUTPUT,      /* UDP/DERP hand-off */
    ML_PERF_STAGES
} ml_perf_stage_t;

typedef struct {
    uint64_t total;         /* cycles (microseconds for ML_PERF_RX_QUEUE_US) */
    uint64_t bytes;
    uint32_t count;
    uint32_t max;
    uint32_t migrated;
} ml_perf_counter_t;

#if defined(TSR_PERF_PROFILE) && TSR_PERF_PROFILE

#include "esp_cpu.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

extern const char *const ml_perf_stage_names[ML_PERF_STAGES];
void ml_perf_add(ml_perf_stage_t stage, uint32_t value, uint32_t bytes, int migrated);
/* Copies all counters; reset clears them afterwards. */
void ml_perf_snapshot(ml_perf_counter_t out[ML_PERF_STAGES], int reset);

typedef struct { uint32_t cycles; int core; } ml_perf_mark_t;

static inline ml_perf_mark_t ml_perf_begin(void)
{
    ml_perf_mark_t m = { esp_cpu_get_cycle_count(), xPortGetCoreID() };
    return m;
}

static inline void ml_perf_end(ml_perf_stage_t stage, ml_perf_mark_t m, uint32_t bytes)
{
    uint32_t now = esp_cpu_get_cycle_count();
    int same = xPortGetCoreID() == m.core;
    ml_perf_add(stage, same ? now - m.cycles : 0, bytes, !same);
}

#define ML_PERF_BEGIN(mark)              ml_perf_mark_t mark = ml_perf_begin()
#define ML_PERF_END(stage, mark, bytes)  ml_perf_end((stage), (mark), (uint32_t)(bytes))
#define ML_PERF_US(stage, us)            ml_perf_add((stage), (uint32_t)(us), 0, 0)
#define ML_PERF_NOW_US()                 esp_timer_get_time()

#else

#define ML_PERF_BEGIN(mark)              do { } while (0)
#define ML_PERF_END(stage, mark, bytes)  do { } while (0)
#define ML_PERF_US(stage, us)            do { } while (0)

#endif
#endif

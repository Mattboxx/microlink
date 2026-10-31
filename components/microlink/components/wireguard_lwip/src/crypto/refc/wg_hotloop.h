/* SPDX-License-Identifier: MIT
 * Experimental ESP32-S3 placement of two existing arithmetic loops only.
 * This does not make the cipher cache-disabled/ISR safe: its data and callers
 * retain their existing memory/context requirements. Algorithms are unchanged.
 */
#ifndef WG_HOTLOOP_H
#define WG_HOTLOOP_H

#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#include "esp_attr.h"
#endif

/* TSR_CRYPTO_IN_FLASH=1 (test builds only) keeps the loops in flash to
 * measure what the IRAM placement is worth against its internal RAM. */
#if defined(CONFIG_IDF_TARGET_ESP32S3) && CONFIG_IDF_TARGET_ESP32S3 \
	&& !(defined(TSR_CRYPTO_IN_FLASH) && TSR_CRYPTO_IN_FLASH)
#define WG_HOT_LOOP IRAM_ATTR
#else
#define WG_HOT_LOOP
#endif

#endif

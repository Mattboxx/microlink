// Taken from https://github.com/floodyberry/poly1305-donna - public domain or MIT
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "wg_hotloop.h"

/* ESP32-S3: poly1305_blocks() runs the hand-written Xtensa block function in
 * poly1305_xtensa.S (same arithmetic, no register spills) once it has matched
 * the C code below on fixed inputs; the C code then stays in flash as the
 * fallback. Other targets and host builds use the C code only. */
#ifndef POLY1305_XTENSA_ASM /* host tests may set it to drive the dispatcher with a stub */
#if defined(__XTENSA__) && defined(CONFIG_IDF_TARGET_ESP32S3) && CONFIG_IDF_TARGET_ESP32S3
#define POLY1305_XTENSA_ASM 1
#else
#define POLY1305_XTENSA_ASM 0
#endif
#endif
#if POLY1305_XTENSA_ASM
#define POLY1305_C_LOOP __attribute__((noinline)) /* flash; must not be inlined into the IRAM dispatcher */
#include "esp_log.h"
#else
#define POLY1305_C_LOOP WG_HOT_LOOP
#endif

/* Mattboxx performance work (2026-10-31): each 16-byte block is read as four
 * little-endian words (one 32-bit load each when aligned on a little-endian
 * target, else four byte-assembled words) and split into the five 26-bit
 * limbs with shifts, instead of five overlapping byte-assembled reads. The
 * limbs and therefore the arithmetic are unchanged. */
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define POLY1305_WORD_LOAD 1
typedef uint32_t __attribute__((may_alias)) poly1305_word_t;
#else
#define POLY1305_WORD_LOAD 0
#endif
/*
	poly1305 implementation using 32 bit * 32 bit = 64 bit multiplication and 64 bit addition
*/

#if defined(_MSC_VER)
	#define POLY1305_NOINLINE __declspec(noinline)
#elif defined(__GNUC__)
	#define POLY1305_NOINLINE __attribute__((noinline))
#else
	#define POLY1305_NOINLINE
#endif

#define poly1305_block_size 16

/* 17 + sizeof(size_t) + 14*sizeof(unsigned long) */
typedef struct poly1305_state_internal_t {
	unsigned long r[5];
	unsigned long h[5];
	unsigned long pad[4];
	size_t leftover;
	unsigned char buffer[poly1305_block_size];
	unsigned char final;
} poly1305_state_internal_t;

/* interpret four 8 bit unsigned integers as a 32 bit unsigned integer in little endian */
static unsigned long
U8TO32(const unsigned char *p) {
	return
		(((unsigned long)(p[0] & 0xff)      ) |
	     ((unsigned long)(p[1] & 0xff) <<  8) |
         ((unsigned long)(p[2] & 0xff) << 16) |
         ((unsigned long)(p[3] & 0xff) << 24));
}

/* store a 32 bit unsigned integer as four 8 bit unsigned integers in little endian */
static void
U32TO8(unsigned char *p, unsigned long v) {
	p[0] = (v      ) & 0xff;
	p[1] = (v >>  8) & 0xff;
	p[2] = (v >> 16) & 0xff;
	p[3] = (v >> 24) & 0xff;
}

void
poly1305_init(poly1305_context *ctx, const unsigned char key[32]) {
	poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;

	/* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
	st->r[0] = (U8TO32(&key[ 0])     ) & 0x3ffffff;
	st->r[1] = (U8TO32(&key[ 3]) >> 2) & 0x3ffff03;
	st->r[2] = (U8TO32(&key[ 6]) >> 4) & 0x3ffc0ff;
	st->r[3] = (U8TO32(&key[ 9]) >> 6) & 0x3f03fff;
	st->r[4] = (U8TO32(&key[12]) >> 8) & 0x00fffff;

	/* h = 0 */
	st->h[0] = 0;
	st->h[1] = 0;
	st->h[2] = 0;
	st->h[3] = 0;
	st->h[4] = 0;

	/* save pad for later */
	st->pad[0] = U8TO32(&key[16]);
	st->pad[1] = U8TO32(&key[20]);
	st->pad[2] = U8TO32(&key[24]);
	st->pad[3] = U8TO32(&key[28]);

	st->leftover = 0;
	st->final = 0;
}

static void POLY1305_C_LOOP
poly1305_blocks_c(poly1305_state_internal_t *st, const unsigned char *m, size_t bytes) {
	const unsigned long hibit = (st->final) ? 0 : (1UL << 24); /* 1 << 128 */
	unsigned long r0,r1,r2,r3,r4;
	unsigned long s1,s2,s3,s4;
	unsigned long h0,h1,h2,h3,h4;
	unsigned long long d0,d1,d2,d3,d4;
	unsigned long c,g0,g1,g2,g3;

	r0 = st->r[0];
	r1 = st->r[1];
	r2 = st->r[2];
	r3 = st->r[3];
	r4 = st->r[4];

	s1 = r1 * 5;
	s2 = r2 * 5;
	s3 = r3 * 5;
	s4 = r4 * 5;

	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];
	h3 = st->h[3];
	h4 = st->h[4];

	while (bytes >= poly1305_block_size) {
		unsigned long t0, t1, t2, t3;
#if POLY1305_WORD_LOAD
		if (!((uintptr_t)m & 3)) {
			const poly1305_word_t *w = (const poly1305_word_t *)m;
			t0 = w[0]; t1 = w[1]; t2 = w[2]; t3 = w[3];
		} else
#endif
		{
			t0 = U8TO32(m + 0); t1 = U8TO32(m + 4); t2 = U8TO32(m + 8); t3 = U8TO32(m + 12);
		}

		/* h += m[i]: bits 0-25, 26-51, 52-77, 78-103 and 104-127 (+ hibit) */
		h0 += t0 & 0x3ffffff;
		h1 += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
		h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
		h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
		h4 += (t3 >> 8) | hibit;

		/* h *= r, then (partial) h %= p. Each d_i is finished and carried
		 * before the next one is formed (the same products, carries and
		 * result as computing d0..d4 first): only one 64-bit accumulator is
		 * live, so a 16-register core does not spill five of them. */
		d0 = ((unsigned long long)h0 * r0) + ((unsigned long long)h1 * s4) + ((unsigned long long)h2 * s3) + ((unsigned long long)h3 * s2) + ((unsigned long long)h4 * s1);
		c = (unsigned long)(d0 >> 26); g0 = (unsigned long)d0 & 0x3ffffff;
		d1 = ((unsigned long long)h0 * r1) + ((unsigned long long)h1 * r0) + ((unsigned long long)h2 * s4) + ((unsigned long long)h3 * s3) + ((unsigned long long)h4 * s2) + c;
		c = (unsigned long)(d1 >> 26); g1 = (unsigned long)d1 & 0x3ffffff;
		d2 = ((unsigned long long)h0 * r2) + ((unsigned long long)h1 * r1) + ((unsigned long long)h2 * r0) + ((unsigned long long)h3 * s4) + ((unsigned long long)h4 * s3) + c;
		c = (unsigned long)(d2 >> 26); g2 = (unsigned long)d2 & 0x3ffffff;
		d3 = ((unsigned long long)h0 * r3) + ((unsigned long long)h1 * r2) + ((unsigned long long)h2 * r1) + ((unsigned long long)h3 * r0) + ((unsigned long long)h4 * s4) + c;
		c = (unsigned long)(d3 >> 26); g3 = (unsigned long)d3 & 0x3ffffff;
		d4 = ((unsigned long long)h0 * r4) + ((unsigned long long)h1 * r3) + ((unsigned long long)h2 * r2) + ((unsigned long long)h3 * r1) + ((unsigned long long)h4 * r0) + c;
		c = (unsigned long)(d4 >> 26); h4 = (unsigned long)d4 & 0x3ffffff;
		h0 = g0 + c * 5;  c = (h0 >> 26); h0 = h0 & 0x3ffffff;
		h1 = g1 + c;
		h2 = g2;
		h3 = g3;

		m += poly1305_block_size;
		bytes -= poly1305_block_size;
	}

	st->h[0] = h0;
	st->h[1] = h1;
	st->h[2] = h2;
	st->h[3] = h3;
	st->h[4] = h4;
}

#if POLY1305_XTENSA_ASM
/* poly1305_xtensa.S reads r and h at fixed offsets and needs a 4-byte aligned
 * message whose length is a multiple of 16 (at least 16). */
void poly1305_blocks_xtensa(poly1305_state_internal_t *st, const unsigned char *m, size_t bytes, unsigned long hibit);
#if defined(__XTENSA__)
_Static_assert(offsetof(poly1305_state_internal_t, r) == 0 && offsetof(poly1305_state_internal_t, h) == 20 &&
               sizeof(unsigned long) == 4, "poly1305_xtensa.S state layout");
#endif

static int poly1305_asm_state; /* 0 unchecked, 1 verified, -1 rejected (C from then on) */

static uint32_t
poly1305_xorshift(uint32_t *x) {
	*x ^= *x << 13; *x ^= *x >> 17; *x ^= *x << 5;
	return *x;
}

/* Compare the assembly with poly1305_blocks_c() before its first use: all-ones
 * inputs, then pseudo-random full 32-bit and clamped/real-sized limbs, both
 * hibit values and 1-4 blocks. Both cores may run this at the same time; they
 * compute and store the same result. */
static POLY1305_NOINLINE int
poly1305_asm_check(void) {
	static const unsigned long clamp[5] = { 0x3ffffff, 0x3ffff03, 0x3ffc0ff, 0x3f03fff, 0x00fffff };
	uint32_t x = 0x9e3779b9u, msg[16];
	int ok = 1;
	for (int round = 0; round < 64 && ok; round++) {
		poly1305_state_internal_t a, b;
		memset(&a, 0, sizeof(a));
		for (int i = 0; i < 5; i++) {
			uint32_t r = poly1305_xorshift(&x), h = poly1305_xorshift(&x);
			a.r[i] = round == 0 ? 0xffffffffUL : (round & 1) ? (r & clamp[i]) : r;
			a.h[i] = round == 0 ? 0xffffffffUL : (round & 1) ? (h & 0x7ffffff) : h;
		}
		for (int i = 0; i < 16; i++)
			msg[i] = round == 0 ? 0xffffffffu : poly1305_xorshift(&x);
		a.final = (unsigned char)((round >> 1) & 1);
		b = a;
		size_t bytes = poly1305_block_size * (size_t)(1 + (round >> 2) % 4);
		poly1305_blocks_c(&a, (const unsigned char *)msg, bytes);
		poly1305_blocks_xtensa(&b, (const unsigned char *)msg, bytes, b.final ? 0 : (1UL << 24));
		ok = memcmp(a.h, b.h, sizeof(a.h)) == 0;
	}
	if (!ok)
		ESP_LOGE("poly1305", "assembly block function disagrees with C; using C");
	poly1305_asm_state = ok ? 1 : -1;
	return poly1305_asm_state;
}
#endif

static void WG_HOT_LOOP
poly1305_blocks(poly1305_state_internal_t *st, const unsigned char *m, size_t bytes) {
#if POLY1305_XTENSA_ASM
	int state = poly1305_asm_state;
	if (state == 0)
		state = poly1305_asm_check();
	if (state > 0) {
		const unsigned long hibit = (st->final) ? 0 : (1UL << 24); /* 1 << 128 */
		if (!((uintptr_t)m & 3)) {
			if (bytes >= poly1305_block_size)
				poly1305_blocks_xtensa(st, m, bytes & ~(size_t)(poly1305_block_size - 1), hibit);
		} else {
			uint32_t block[4]; /* unaligned input: one aligned copy per block */
			for (; bytes >= poly1305_block_size; m += poly1305_block_size, bytes -= poly1305_block_size) {
				memcpy(block, m, poly1305_block_size);
				poly1305_blocks_xtensa(st, (const unsigned char *)block, poly1305_block_size, hibit);
			}
		}
		return;
	}
#endif
	poly1305_blocks_c(st, m, bytes);
}

/* 1: the Xtensa assembly is in use, -1: it was rejected by its check,
 * 0: not checked yet or not built for this target. */
int
poly1305_asm_status(void) {
#if POLY1305_XTENSA_ASM
	return poly1305_asm_state;
#else
	return 0;
#endif
}

POLY1305_NOINLINE void
poly1305_finish(poly1305_context *ctx, unsigned char mac[16]) {
	poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;
	unsigned long h0,h1,h2,h3,h4,c;
	unsigned long g0,g1,g2,g3,g4;
	unsigned long long f;
	unsigned long mask;

	/* process the remaining block */
	if (st->leftover) {
		size_t i = st->leftover;
		st->buffer[i++] = 1;
		for (; i < poly1305_block_size; i++)
			st->buffer[i] = 0;
		st->final = 1;
		poly1305_blocks(st, st->buffer, poly1305_block_size);
	}

	/* fully carry h */
	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];
	h3 = st->h[3];
	h4 = st->h[4];

	             c = h1 >> 26; h1 = h1 & 0x3ffffff;
	h2 +=     c; c = h2 >> 26; h2 = h2 & 0x3ffffff;
	h3 +=     c; c = h3 >> 26; h3 = h3 & 0x3ffffff;
	h4 +=     c; c = h4 >> 26; h4 = h4 & 0x3ffffff;
	h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3ffffff;
	h1 +=     c;

	/* compute h + -p */
	g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
	g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
	g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
	g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
	g4 = h4 + c - (1UL << 26);

	/* select h if h < p, or h + -p if h >= p */
	mask = (g4 >> ((sizeof(unsigned long) * 8) - 1)) - 1;
	g0 &= mask;
	g1 &= mask;
	g2 &= mask;
	g3 &= mask;
	g4 &= mask;
	mask = ~mask;
	h0 = (h0 & mask) | g0;
	h1 = (h1 & mask) | g1;
	h2 = (h2 & mask) | g2;
	h3 = (h3 & mask) | g3;
	h4 = (h4 & mask) | g4;

	/* h = h % (2^128) */
	h0 = ((h0      ) | (h1 << 26)) & 0xffffffff;
	h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
	h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
	h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

	/* mac = (h + pad) % (2^128) */
	f = (unsigned long long)h0 + st->pad[0]            ; h0 = (unsigned long)f;
	f = (unsigned long long)h1 + st->pad[1] + (f >> 32); h1 = (unsigned long)f;
	f = (unsigned long long)h2 + st->pad[2] + (f >> 32); h2 = (unsigned long)f;
	f = (unsigned long long)h3 + st->pad[3] + (f >> 32); h3 = (unsigned long)f;

	U32TO8(mac +  0, h0);
	U32TO8(mac +  4, h1);
	U32TO8(mac +  8, h2);
	U32TO8(mac + 12, h3);

	/* zero out the state */
	st->h[0] = 0;
	st->h[1] = 0;
	st->h[2] = 0;
	st->h[3] = 0;
	st->h[4] = 0;
	st->r[0] = 0;
	st->r[1] = 0;
	st->r[2] = 0;
	st->r[3] = 0;
	st->r[4] = 0;
	st->pad[0] = 0;
	st->pad[1] = 0;
	st->pad[2] = 0;
	st->pad[3] = 0;
}


/* SPDX-License-Identifier: MIT
 * Poly1305 block function for Xtensa LX7 (ESP32-S3), Mattboxx 2026-10-31.
 *
 * Same arithmetic as poly1305_blocks() in poly1305-donna-32.h (26-bit limbs,
 * 32 x 32 -> 64-bit products, partial reduction mod 2^130 - 5), written by
 * hand because the compiler keeps five 64-bit accumulators and nine
 * coefficients alive and spills most of them on a 16-register window. Here
 * the limbs h0..h4 stay in registers, coefficients are loaded as needed and
 * one 64-bit accumulator is completed and carried at a time.
 *
 * void poly1305_blocks_xtensa(poly1305_state_internal_t *st,
 *                             const unsigned char *m, size_t bytes,
 *                             unsigned long hibit);
 *   st:    r[5] at offsets 0..16, h[5] at 20..36 (32-bit words)
 *   m:     4-byte aligned; bytes: multiple of 16, at least 16
 *   hibit: 1 << 24, or 0 for the final padded block
 * The C caller compares this routine with the C code before its first use
 * and keeps using C if they differ (poly1305_asm_check()).
 *
 * Registers: a2 st, a3 m, a4 bytes, a5 carry c, a6..a10 h0..h4,
 * a11/a12 accumulator lo/hi, a13 coefficient, a14/a15 temporaries.
 * Stack (entry a1, 80): s1..s4 = 5*r1..r4 at 0..12, g0..g3 at 16..28,
 * hibit at 32; like GCC frames, the top 32 bytes stay free for the
 * windowed-ABI register save areas.
 */
#if defined(__XTENSA__)

#if defined(TSR_CRYPTO_IN_FLASH) && TSR_CRYPTO_IN_FLASH
    .section .text.poly1305_blocks_xtensa, "ax"
#else
    .section .iram1.poly1305_xtensa, "ax"
#endif
    .literal_position
    .align  4
    .global poly1305_blocks_xtensa
    .type   poly1305_blocks_xtensa, @function

/* acc = x * coefficient */
.macro MUL0 x
    mull    a11, \x, a13
    muluh   a12, \x, a13
.endm

/* acc += x * coefficient (64-bit, carry through saltu) */
.macro MAC x
    mull    a14, \x, a13
    muluh   a15, \x, a13
    add     a11, a11, a14
    saltu   a14, a11, a14
    add     a12, a12, a15
    add     a12, a12, a14
.endm

/* acc += c (a5) */
.macro ADDC
    add     a11, a11, a5
    saltu   a14, a11, a5
    add     a12, a12, a14
.endm

/* c = (unsigned long)(acc >> 26); acc_lo &= 0x3ffffff */
.macro CARRY
    ssai    26
    src     a5, a12, a11
    slli    a11, a11, 6
    srli    a11, a11, 6
.endm

poly1305_blocks_xtensa:
    entry   a1, 80
    s32i    a5, a1, 32              /* hibit */
    l32i    a13, a2, 4
    addx4   a13, a13, a13
    s32i    a13, a1, 0              /* s1 */
    l32i    a13, a2, 8
    addx4   a13, a13, a13
    s32i    a13, a1, 4              /* s2 */
    l32i    a13, a2, 12
    addx4   a13, a13, a13
    s32i    a13, a1, 8              /* s3 */
    l32i    a13, a2, 16
    addx4   a13, a13, a13
    s32i    a13, a1, 12             /* s4 */
    l32i    a6, a2, 20              /* h0 */
    l32i    a7, a2, 24              /* h1 */
    l32i    a8, a2, 28              /* h2 */
    l32i    a9, a2, 32              /* h3 */
    l32i    a10, a2, 36             /* h4 */

.Lblock:
    /* h += m: limbs are bits 0-25, 26-51, 52-77, 78-103, 104-127 (+hibit) */
    l32i    a11, a3, 0              /* t0 */
    l32i    a12, a3, 4              /* t1 */
    l32i    a13, a3, 8              /* t2 */
    l32i    a14, a3, 12             /* t3 */
    ssai    14
    src     a15, a14, a13           /* (t3:t2) >> 14 */
    slli    a15, a15, 6
    srli    a15, a15, 6
    add     a9, a9, a15             /* h3 */
    srli    a14, a14, 8
    l32i    a15, a1, 32
    or      a14, a14, a15
    add     a10, a10, a14           /* h4 */
    ssai    20
    src     a15, a13, a12           /* (t2:t1) >> 20 */
    slli    a15, a15, 6
    srli    a15, a15, 6
    add     a8, a8, a15             /* h2 */
    ssai    26
    src     a15, a12, a11           /* (t1:t0) >> 26 */
    slli    a15, a15, 6
    srli    a15, a15, 6
    add     a7, a7, a15             /* h1 */
    slli    a11, a11, 6
    srli    a11, a11, 6
    add     a6, a6, a11             /* h0 */

    /* d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1 */
    l32i    a13, a2, 0
    MUL0    a6
    l32i    a13, a1, 12
    MAC     a7
    l32i    a13, a1, 8
    MAC     a8
    l32i    a13, a1, 4
    MAC     a9
    l32i    a13, a1, 0
    MAC     a10
    CARRY
    s32i    a11, a1, 16             /* g0 */

    /* d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2 + c */
    l32i    a13, a2, 4
    MUL0    a6
    l32i    a13, a2, 0
    MAC     a7
    l32i    a13, a1, 12
    MAC     a8
    l32i    a13, a1, 8
    MAC     a9
    l32i    a13, a1, 4
    MAC     a10
    ADDC
    CARRY
    s32i    a11, a1, 20             /* g1 */

    /* d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3 + c */
    l32i    a13, a2, 8
    MUL0    a6
    l32i    a13, a2, 4
    MAC     a7
    l32i    a13, a2, 0
    MAC     a8
    l32i    a13, a1, 12
    MAC     a9
    l32i    a13, a1, 8
    MAC     a10
    ADDC
    CARRY
    s32i    a11, a1, 24             /* g2 */

    /* d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4 + c */
    l32i    a13, a2, 12
    MUL0    a6
    l32i    a13, a2, 8
    MAC     a7
    l32i    a13, a2, 4
    MAC     a8
    l32i    a13, a2, 0
    MAC     a9
    l32i    a13, a1, 12
    MAC     a10
    ADDC
    CARRY
    s32i    a11, a1, 28             /* g3 */

    /* d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0 + c */
    l32i    a13, a2, 16
    MUL0    a6
    l32i    a13, a2, 12
    MAC     a7
    l32i    a13, a2, 8
    MAC     a8
    l32i    a13, a2, 4
    MAC     a9
    l32i    a13, a2, 0
    MAC     a10
    ADDC
    CARRY
    mov     a10, a11                /* h4 = d4 & mask */

    /* h0 = g0 + c*5; c = h0 >> 26; h0 &= mask; h1 = g1 + c; h2 = g2; h3 = g3 */
    l32i    a6, a1, 16
    addx4   a14, a5, a5
    add     a6, a6, a14
    extui   a14, a6, 26, 6          /* c = h0 >> 26 */
    slli    a6, a6, 6
    srli    a6, a6, 6
    l32i    a7, a1, 20
    add     a7, a7, a14
    l32i    a8, a1, 24
    l32i    a9, a1, 28

    addi    a3, a3, 16
    addi    a4, a4, -16
    bltui   a4, 16, .Ldone
    j       .Lblock

.Ldone:
    s32i    a6, a2, 20
    s32i    a7, a2, 24
    s32i    a8, a2, 28
    s32i    a9, a2, 32
    s32i    a10, a2, 36
    retw

    .size   poly1305_blocks_xtensa, . - poly1305_blocks_xtensa

#endif

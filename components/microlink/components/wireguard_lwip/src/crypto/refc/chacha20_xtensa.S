/* SPDX-License-Identifier: MIT
 * ChaCha20 block function for Xtensa LX7 (ESP32-S3), Mattboxx 2026-11-01.
 *
 * Same algorithm as the fused loop in chacha20.c (RFC 8439 2.3: twenty rounds,
 * feed-forward, XOR with the input, block counter in word 12), written by
 * hand because GCC keeps the sixteen state words on a 16-register window and
 * moves about 40 of them through the stack per double round. Here fifteen
 * words stay in registers (a0 is saved and used as well) and only x12/x14
 * share one: the quarter rounds run in pairs ordered so that this register
 * is exchanged twice per double round (4 memory operations instead of ~40).
 * The ten double rounds use the zero-overhead loop (LBEG/LEND/LCOUNT, which
 * the RTOS saves on a context switch, as for GCC's own LOOP instructions).
 * Xtensa has no rotate: SSAI 32-n then SRC x, x, x rotates left by n.
 *
 * void chacha20_blocks_xtensa(uint32_t state[16], uint32_t *out,
 *                             const uint32_t *in, uint32_t blocks);
 *   out/in: 4-byte aligned, 64 * blocks bytes, equal or not overlapping
 *   blocks: at least 1; state[12] is incremented once per block
 * The C caller compares this routine with the C code before its first use
 * and keeps using C if they differ (chacha20_asm_check()).
 *
 * Registers in the rounds: x0..x11 = a2..a13, x13 = a14, x15 = a15, and
 * a0 = x14 (columns 2-3, diagonals 2-3) or x12 (columns 0-1, diagonals 0-1).
 * Stack (entry a1, 80): return address 0, state 4, out 8, in 12, blocks
 * left 16, x12 20, x14 24, x11 28, x13 32, x15 36; like GCC frames, the top
 * 32 bytes stay free for the windowed-ABI register save areas.
 */
#if defined(__XTENSA__)

#if defined(TSR_CRYPTO_IN_FLASH) && TSR_CRYPTO_IN_FLASH
    .section .text.chacha20_blocks_xtensa, "ax"
#else
    .section .iram1.chacha20_xtensa, "ax"
#endif
    .literal_position
    .align  4
    .global chacha20_blocks_xtensa
    .type   chacha20_blocks_xtensa, @function

/* Two quarter rounds (RFC 8439 2.1) advanced together, step by step. */
.macro QR2 wa, wb, wc, wd, va, vb, vc, vd
    add     \wa, \wa, \wb
    add     \va, \va, \vb
    xor     \wd, \wd, \wa
    xor     \vd, \vd, \va
    ssai    16
    src     \wd, \wd, \wd
    src     \vd, \vd, \vd
    add     \wc, \wc, \wd
    add     \vc, \vc, \vd
    xor     \wb, \wb, \wc
    xor     \vb, \vb, \vc
    ssai    20
    src     \wb, \wb, \wb
    src     \vb, \vb, \vb
    add     \wa, \wa, \wb
    add     \va, \va, \vb
    xor     \wd, \wd, \wa
    xor     \vd, \vd, \va
    ssai    24
    src     \wd, \wd, \wd
    src     \vd, \vd, \vd
    add     \wc, \wc, \wd
    add     \vc, \vc, \vd
    xor     \wb, \wb, \wc
    xor     \vb, \vb, \vc
    ssai    25
    src     \wb, \wb, \wb
    src     \vb, \vb, \vb
.endm

/* x += state[i] for two register words, loads issued ahead of their use. */
.macro FEED2 x, y, off_x, off_y
    l32i    a13, a15, \off_x
    l32i    a14, a15, \off_y
    add     \x, \x, a13
    add     \y, \y, a14
.endm

/* x ^= in[i] for two register words. */
.macro MIX2 x, y, off_x, off_y
    l32i    a13, a15, \off_x
    l32i    a14, a15, \off_y
    xor     \x, \x, a13
    xor     \y, \y, a14
.endm

/* out[i] = (word waiting in the frame + state[i]) ^ in[i];
 * a2 = state, a3 = in, a15 = out. */
.macro LAST slot, off
    l32i    a4, a1, \slot
    l32i    a5, a2, \off
    l32i    a6, a3, \off
    add     a4, a4, a5
    xor     a4, a4, a6
    s32i    a4, a15, \off
.endm

chacha20_blocks_xtensa:
    entry   a1, 80
    s32i    a0, a1, 0
    s32i    a2, a1, 4
    s32i    a3, a1, 8
    s32i    a4, a1, 12
    s32i    a5, a1, 16

.Lblock:
    movi    a3, .Lround
    wsr.lbeg a3
    movi    a3, .Lround_end
    wsr.lend a3
    movi    a3, 9                   /* ten passes */
    wsr.lcount a3
    isync
    l32i    a2, a1, 4
    l32i    a0, a2, 48
    s32i    a0, a1, 20              /* x12 waits in the frame */
    l32i    a0, a2, 56              /* x14 */
    l32i    a3, a2, 4
    l32i    a4, a2, 8
    l32i    a5, a2, 12
    l32i    a6, a2, 16
    l32i    a7, a2, 20
    l32i    a8, a2, 24
    l32i    a9, a2, 28
    l32i    a10, a2, 32
    l32i    a11, a2, 36
    l32i    a12, a2, 40
    l32i    a13, a2, 44
    l32i    a14, a2, 52
    l32i    a15, a2, 60
    l32i    a2, a2, 0

.Lround:
    QR2     a4, a8, a12, a0,   a5, a9, a13, a15     /* columns 2, 3 */
    s32i    a0, a1, 24
    l32i    a0, a1, 20
    QR2     a2, a6, a10, a0,   a3, a7, a11, a14     /* columns 0, 1 */
    QR2     a2, a7, a12, a15,  a3, a8, a13, a0      /* diagonals 0, 1 */
    s32i    a0, a1, 20
    l32i    a0, a1, 24
    QR2     a4, a9, a10, a14,  a5, a6, a11, a0      /* diagonals 2, 3 */
.Lround_end:

    /* Free a13..a15: x11, x13 and x15 wait in the frame with x12. */
    s32i    a13, a1, 28
    s32i    a14, a1, 32
    s32i    a15, a1, 36
    l32i    a15, a1, 4              /* state: feed-forward */
    FEED2   a2, a3, 0, 4
    FEED2   a4, a5, 8, 12
    FEED2   a6, a7, 16, 20
    FEED2   a8, a9, 24, 28
    FEED2   a10, a11, 32, 36
    FEED2   a12, a0, 40, 56
    l32i    a15, a1, 12             /* in */
    MIX2    a2, a3, 0, 4
    MIX2    a4, a5, 8, 12
    MIX2    a6, a7, 16, 20
    MIX2    a8, a9, 24, 28
    MIX2    a10, a11, 32, 36
    MIX2    a12, a0, 40, 56
    l32i    a15, a1, 8              /* out: every input word above is read */
    s32i    a2, a15, 0
    s32i    a3, a15, 4
    s32i    a4, a15, 8
    s32i    a5, a15, 12
    s32i    a6, a15, 16
    s32i    a7, a15, 20
    s32i    a8, a15, 24
    s32i    a9, a15, 28
    s32i    a10, a15, 32
    s32i    a11, a15, 36
    s32i    a12, a15, 40
    s32i    a0, a15, 56
    l32i    a2, a1, 4
    l32i    a3, a1, 12
    LAST    28, 44                  /* x11 */
    LAST    20, 48                  /* x12 */
    LAST    32, 52                  /* x13 */
    LAST    36, 60                  /* x15 */
    l32i    a4, a2, 48              /* block counter */
    addi    a4, a4, 1
    s32i    a4, a2, 48

    addi    a3, a3, 64
    s32i    a3, a1, 12
    addi    a15, a15, 64
    s32i    a15, a1, 8
    l32i    a4, a1, 16
    addi    a4, a4, -1
    s32i    a4, a1, 16
    bnez    a4, .Lblock

    l32i    a0, a1, 0
    retw

    .size   chacha20_blocks_xtensa, . - chacha20_blocks_xtensa

#endif

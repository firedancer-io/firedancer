#include "fd_merlin.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>
#include <stdio.h>

/******** The Keccak-f[1600] permutation ********/

// void
// strobe128_dbg(fd_merlin_strobe128_t* ctx) {
//   printf("state: ");
//   for (ulong i=0; i<200; i++) { printf("%02x ", ctx->state_bytes[i]); }
//   printf("\npos: %d\n", ctx->pos);
//   printf("pos_begin: %d\n", ctx->pos_begin);
//   printf("cur_flags: %d\n", ctx->cur_flags);
// }

/*** Constants. ***/
static const uint8_t rho[24] = {1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
                                27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};
static const uint8_t pi[24] = {10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
                               15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1};
static const uint64_t RC[24] = {1ULL,
                                0x8082ULL,
                                0x800000000000808aULL,
                                0x8000000080008000ULL,
                                0x808bULL,
                                0x80000001ULL,
                                0x8000000080008081ULL,
                                0x8000000000008009ULL,
                                0x8aULL,
                                0x88ULL,
                                0x80008009ULL,
                                0x8000000aULL,
                                0x8000808bULL,
                                0x800000000000008bULL,
                                0x8000000000008089ULL,
                                0x8000000000008003ULL,
                                0x8000000000008002ULL,
                                0x8000000000000080ULL,
                                0x800aULL,
                                0x800000008000000aULL,
                                0x8000000080008081ULL,
                                0x8000000000008080ULL,
                                0x80000001ULL,
                                0x8000000080008008ULL};

/*** Helper macros to unroll the permutation. ***/
#define rol(x, s) (((x) << s) | ((x) >> (64 - s)))
#define REPEAT6(e) e e e e e e
#define REPEAT24(e) REPEAT6(e e e e)
#define REPEAT5(e) e e e e e
#define FOR5(v, s, e) \
  v = 0;              \
  REPEAT5(e; v += s;)

/*** Keccak-f[1600] ***/
static /*inline*/ void keccakf(void* state) {
  uint64_t* a = (uint64_t*)state;
  uint64_t b[5] = {0};
  uint64_t t = 0;
  uint8_t x, y;
  int i;

  for (i = 0; i < 24; i++) {
    /* Theta */
    FOR5(x, 1, b[x] = 0; FOR5(y, 5, b[x] ^= a[x + y];))
    FOR5(x, 1, FOR5(y, 5, a[y + x] ^= b[(x + 4) % 5] ^ rol(b[(x + 1) % 5], 1);))
    /* Rho and pi */
    t = a[1];
    x = 0;
    REPEAT24(b[0] = a[pi[x]]; a[pi[x]] = rol(t, rho[x]); t = b[0]; x++;)
    /* Chi */
    FOR5(y, 5,
         FOR5(x, 1, b[x] = a[y + x];)
             FOR5(x, 1, a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);))
    /* Iota */
    a[0] ^= RC[i];
  }
}

/******** A Strobe-128 context; internal functions. ********/

#define STROBE_R 166

#define FLAG_I (1)
#define FLAG_A (1 << 1)
#define FLAG_C (1 << 2)
#define FLAG_T (1 << 3)
#define FLAG_M (1 << 4)
#define FLAG_K (1 << 5)

static /*inline*/ void strobe128_run_f(fd_merlin_strobe128_t* ctx) {
  ctx->state_bytes[ctx->pos] ^= ctx->pos_begin;
  ctx->state_bytes[ctx->pos + 1] ^= 0x04;
  ctx->state_bytes[STROBE_R + 1] ^= 0x80;
  keccakf(ctx->state);
  ctx->pos = 0;
  ctx->pos_begin = 0;
}

static void strobe128_absorb(fd_merlin_strobe128_t* ctx,
                             const uint8_t* data,
                             size_t data_len) {
  size_t i;
  for (i = 0; i < data_len; ++i) {
    ctx->state_bytes[ctx->pos] ^= data[i];
    ctx->pos += 1;
    if (ctx->pos == STROBE_R) {
      strobe128_run_f(ctx);
    }
  }
}

// static void strobe128_overwrite(fd_merlin_strobe128_t* ctx,
//                                 const uint8_t* data,
//                                 size_t data_len) {
//   size_t i;
//   for (i = 0; i < data_len; ++i) {
//     ctx->state_bytes[ctx->pos] = data[i];
//     ctx->pos += 1;
//     if (ctx->pos == STROBE_R) {
//       strobe128_run_f(ctx);
//     }
//   }
// }

static void strobe128_squeeze(fd_merlin_strobe128_t* ctx, uint8_t* data, size_t data_len) {
  size_t i;
  for (i = 0; i < data_len; ++i) {
    data[i] = ctx->state_bytes[ctx->pos];
    ctx->state_bytes[ctx->pos] = 0;
    ctx->pos += 1;
    if (ctx->pos == STROBE_R) {
      strobe128_run_f(ctx);
    }
  }
}

static /*inline*/ void strobe128_begin_op(fd_merlin_strobe128_t* ctx,
                                      uint8_t flags,
                                      uint8_t more) {
  if (more) {
    /* Changing flags while continuing is illegal */
    assert(ctx->cur_flags == flags);
    return;
  }

  /* T flag is not supported */
  assert(!(flags & FLAG_T));

  uint8_t old_begin = ctx->pos_begin;
  ctx->pos_begin = ctx->pos + 1;
  ctx->cur_flags = flags;

  uint8_t data[2] = {old_begin, flags};
  strobe128_absorb(ctx, data, 2);

  /* Force running the permutation if C or K is set. */
  uint8_t force_f = 0 != (flags & (FLAG_C | FLAG_K));

  if (force_f && ctx->pos != 0) {
    strobe128_run_f(ctx);
  }
}

/******** A Strobe-128 context; external (to Strobe) functions. ********/

static void strobe128_meta_ad(fd_merlin_strobe128_t* ctx,
                              const uint8_t* data,
                              size_t data_len,
                              uint8_t more) {
  strobe128_begin_op(ctx, FLAG_M | FLAG_A, more);
  strobe128_absorb(ctx, data, data_len);
}

static void strobe128_ad(fd_merlin_strobe128_t* ctx,
                         const uint8_t* data,
                         size_t data_len,
                         uint8_t more) {
  strobe128_begin_op(ctx, FLAG_A, more);
  strobe128_absorb(ctx, data, data_len);
}

static void strobe128_prf(fd_merlin_strobe128_t* ctx,
                          uint8_t* data,
                          size_t data_len,
                          uint8_t more) {
  strobe128_begin_op(ctx, FLAG_I | FLAG_A | FLAG_C, more);
  strobe128_squeeze(ctx, data, data_len);
}

// static void strobe128_key(fd_merlin_strobe128_t* ctx,
//                           const uint8_t* data,
//                           size_t data_len,
//                           uint8_t more) {
//   strobe128_begin_op(ctx, FLAG_C | FLAG_A, more);
//   strobe128_overwrite(ctx, data, data_len);
// }

static void strobe128_init(fd_merlin_strobe128_t* ctx,
                           const uint8_t* label,
                           size_t label_len) {
  uint8_t init[18] = {1,  168, 1,  0,   1,  96, 83, 84, 82,
                      79, 66,  69, 118, 49, 46, 48, 46, 50};
  memset(ctx->state_bytes, 0, 200);
  memcpy(ctx->state_bytes, init, 18);
  keccakf(ctx->state);
  ctx->pos = 0;
  ctx->pos_begin = 0;
  ctx->cur_flags = 0;

  strobe128_meta_ad(ctx, label, label_len, 0);
}

/* Derived from https://github.com/hdevalence/libmerlin */

void
fd_merlin_transcript_init( fd_merlin_transcript_t * mctx,
                           char const * const       label,
                           ulong                    label_len ) {
  strobe128_init(&mctx->sctx, (uchar *)FD_MERLIN_LITERAL("Merlin v1.0"));
  // strobe128_dbg(&mctx->sctx);
  fd_merlin_transcript_append_message(mctx, FD_MERLIN_LITERAL("dom-sep"), (uchar *)label, label_len);
  // strobe128_dbg(&mctx->sctx);
}

void
fd_merlin_transcript_append_message( fd_merlin_transcript_t * mctx,
                                     char const * const       label,
                                     ulong                    label_len,
                                     uchar const *            message,
                                     ulong                    message_len ) {
  strobe128_meta_ad(&mctx->sctx, (uchar *)label, label_len, 0);
  strobe128_meta_ad(&mctx->sctx, (uchar *)&message_len, 4, 1);
  strobe128_ad(&mctx->sctx, message, message_len, 0);
}

void
fd_merlin_transcript_challenge_bytes( fd_merlin_transcript_t * mctx,
                                      char const * const       label,
                                      ulong                    label_len,
                                      uchar *                  buffer,
                                      ulong                    buffer_len ) {
  strobe128_meta_ad(&mctx->sctx, (uchar *)label, label_len, 0);
  strobe128_meta_ad(&mctx->sctx, (uchar *)&buffer_len, 4, 1);
  strobe128_prf(&mctx->sctx, buffer, buffer_len, 0);
}

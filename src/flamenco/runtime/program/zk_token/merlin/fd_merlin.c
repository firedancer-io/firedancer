#include "fd_merlin.h"
#include "../../../../../ballet/keccak256/fd_keccak256.h"

/* Derived from https://github.com/hdevalence/libmerlin */

/* Strobe-128 Internals */

#define STROBE_R 166
#define FLAG_I (1)
#define FLAG_A (1 << 1)
#define FLAG_C (1 << 2)
#define FLAG_T (1 << 3)
#define FLAG_M (1 << 4)
#define FLAG_K (1 << 5)

static inline void
strobe128_run_f( fd_merlin_strobe128_t * ctx ) {
  ctx->state_bytes[ctx->pos] ^= ctx->pos_begin;
  ctx->state_bytes[ctx->pos + 1] ^= 0x04;
  ctx->state_bytes[STROBE_R + 1] ^= 0x80;
  fd_keccak256_core( ctx->state );
  ctx->pos = 0;
  ctx->pos_begin = 0;
}

static void
strobe128_absorb( fd_merlin_strobe128_t * ctx,
                  uchar const *           data,
                  ulong const             data_len) {
  for ( ulong i=0; i<data_len; i++ ) {
    ctx->state_bytes[ctx->pos] ^= data[i];
    ctx->pos += 1;
    if (ctx->pos == STROBE_R) {
      strobe128_run_f(ctx);
    }
  }
}

static void
strobe128_squeeze( fd_merlin_strobe128_t * ctx,
                   uchar *                 data,
                   ulong const             data_len) {
  for ( ulong i=0; i<data_len; i++ ) {
    data[i] = ctx->state_bytes[ctx->pos];
    ctx->state_bytes[ctx->pos] = 0;
    ctx->pos += 1;
    if (ctx->pos == STROBE_R) {
      strobe128_run_f(ctx);
    }
  }
}

static void
strobe128_begin_op( fd_merlin_strobe128_t * ctx,
                    uchar                   flags ) {
  /* Note: this implementation cuts some corners, see code below.
     Our implementation of Merlin doesn't use these features. */

  /*
  if (more) {
    // Changing flags while continuing is illegal
    assert(ctx->cur_flags == flags);
    return;
  }

  // T flag is not supported
  assert(!(flags & FLAG_T));
  */

  uchar old_begin = ctx->pos_begin;
  ctx->pos_begin = ctx->pos + 1;
  ctx->cur_flags = flags;

  uchar data[2] = { old_begin, flags };
  strobe128_absorb( ctx, data, 2 );

  /* Force running the permutation if C or K is set. */
  uchar force_f = 0 != (flags & (FLAG_C | FLAG_K));

  if (force_f && ctx->pos != 0) {
    strobe128_run_f(ctx);
  }
}

/* Strobe-128 */

static inline void
strobe128_meta_ad( fd_merlin_strobe128_t * ctx,
                   uchar const *           data,
                   ulong                   data_len,
                   uchar                   more ) {
  if ( more==0 ) {
    strobe128_begin_op( ctx, FLAG_M | FLAG_A );
  }
  strobe128_absorb(   ctx, data, data_len );
}

static inline void
strobe128_ad(fd_merlin_strobe128_t * ctx,
             uchar const *           data,
             ulong const             data_len,
             uchar                   more) {
  if ( more==0 ) {
    strobe128_begin_op( ctx, FLAG_A );
  }
  strobe128_absorb(   ctx, data, data_len );
}

static inline void
strobe128_prf( fd_merlin_strobe128_t * ctx,
               uchar *                 data,
               ulong const             data_len,
               uchar                   more ) {
  if ( more==0 ) {
    strobe128_begin_op(ctx, FLAG_I | FLAG_A | FLAG_C );
  }
  strobe128_squeeze(ctx, data, data_len);
}

static inline void
strobe128_init( fd_merlin_strobe128_t * ctx,
                uchar const *           label,
                ulong const             label_len ) {
  uchar init[18] = {
    1,  168, 1,  0,   1,  96, 83, 84, 82,
    79, 66,  69, 118, 49, 46, 48, 46, 50,
  };
  fd_memset( ctx->state_bytes, 0, 200 );
  fd_memcpy( ctx->state_bytes, init, 18 );
  fd_keccak256_core( ctx->state );
  ctx->pos = 0;
  ctx->pos_begin = 0;
  ctx->cur_flags = 0;

  strobe128_meta_ad( ctx, label, label_len, 0 );
}

/* Merlin */

void
fd_merlin_transcript_init( fd_merlin_transcript_t * mctx,
                           char const * const       label,
                           uint const               label_len ) {
  strobe128_init(&mctx->sctx, (uchar *)FD_MERLIN_LITERAL("Merlin v1.0"));
  fd_merlin_transcript_append_message(mctx, FD_MERLIN_LITERAL("dom-sep"), (uchar *)label, label_len);
}

void
fd_merlin_transcript_append_message( fd_merlin_transcript_t * mctx,
                                     char const * const       label,
                                     uint const               label_len,
                                     uchar const *            message,
                                     uint const               message_len ) {
  strobe128_meta_ad(&mctx->sctx, (uchar *)label, label_len, 0);
  strobe128_meta_ad(&mctx->sctx, (uchar *)&message_len, 4, 1);
  strobe128_ad(&mctx->sctx, message, message_len, 0);
}

void
fd_merlin_transcript_challenge_bytes( fd_merlin_transcript_t * mctx,
                                      char const * const       label,
                                      uint const               label_len,
                                      uchar *                  buffer,
                                      uint const               buffer_len ) {
  strobe128_meta_ad(&mctx->sctx, (uchar *)label, label_len, 0);
  strobe128_meta_ad(&mctx->sctx, (uchar *)&buffer_len, 4, 1);
  strobe128_prf(&mctx->sctx, buffer, buffer_len, 0);
}

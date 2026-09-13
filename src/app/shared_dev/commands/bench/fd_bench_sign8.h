#ifndef HEADER_fd_src_app_shared_dev_commands_bench_fd_bench_sign8_h
#define HEADER_fd_src_app_shared_dev_commands_bench_fd_bench_sign8_h

/* Eight Ed25519 signatures at a time for the load generator.

   WARNING: variable time.  The fixed base table is indexed by digits
   of the secret nonce, which leaks the private key through timing and
   cache.  The benchmark's keys are derived from small integers and
   fund nothing; nothing else may sign with this. */

#include "../../../../util/fd_util_base.h"

#define FD_BENCH_SIGN8_MSG_MAX (1232UL)
#define FD_BENCH_SIGN8_N_MAX   (8UL)

struct fd_bench_sign8;
typedef struct fd_bench_sign8 fd_bench_sign8_t;

FD_PROTOTYPES_BEGIN

ulong fd_bench_sign8_align    ( void );
ulong fd_bench_sign8_footprint( void );

/* Builds the fixed base table; about 15 ms. */
fd_bench_sign8_t *
fd_bench_sign8_new( void * mem );

/* out[j] = encoding of [r[j]]B for eight scalars r[j] < L.  Test hook
   for the table and digit recoding. */
void
fd_bench_sign8_mul_base( fd_bench_sign8_t const * s8,
                         uchar                    out[ 8 ][ 32 ],
                         uchar const              r[ 8 ][ 32 ] );

/* sigs[j] gets the RFC 8032 signature of msgs[j] (msg_szs[j] bytes, at
   most FD_BENCH_SIGN8_MSG_MAX) under (pubs[j], privs[j]), identical to
   fd_ed25519_sign.  Every array has 8*n entries, n in [1,
   FD_BENCH_SIGN8_N_MAX].  The n batches share one field inversion, so
   larger n is cheaper per signature. */
void
fd_bench_sign8_n( fd_bench_sign8_t const * s8,
                  ulong                    n,
                  uchar * const *          sigs,
                  uchar const * const *    msgs,
                  ulong const *            msg_szs,
                  uchar const * const *    pubs,
                  uchar const * const *    privs );

static inline void
fd_bench_sign8( fd_bench_sign8_t const * s8,
                uchar * const            sigs[ 8 ],
                uchar const * const      msgs[ 8 ],
                ulong const              msg_szs[ 8 ],
                uchar const * const      pubs[ 8 ],
                uchar const * const      privs[ 8 ] ) {
  fd_bench_sign8_n( s8, 1UL, sigs, msgs, msg_szs, pubs, privs );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_dev_commands_bench_fd_bench_sign8_h */

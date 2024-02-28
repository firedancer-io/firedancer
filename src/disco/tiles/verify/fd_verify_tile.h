#ifndef HEADER_fd_src_disco_tiles_verify_fd_verify_tile_h
#define HEADER_fd_src_disco_tiles_verify_fd_verify_tile_h

/* The verify tile is a wrapper around the mux tile, that also verifies
   incoming transaction signatures match the data being signed.
   Non-matching transactions are filtered out of the frag stream. */

#include "../../fd_disco_base.h"
#include "../../mux/fd_mux.h"
#include "../../quic/fd_tpu.h"

#define FD_VERIFY_TILE_ALIGN (128UL)

#define FD_VERIFY_TILE_TCACHE_DEPTH   16UL
#define FD_VERIFY_TILE_TCACHE_MAP_CNT 64UL

struct fd_verify_tile_topo {
  fd_wksp_t *      quic_in_wksp;
  fd_tpu_reasm_t * quic_in_reasm;
  ulong            quic_in_depth;
  ulong            quic_in_burst;

  fd_wksp_t *      dedup_out_wksp;
  void *           dedup_out_dcache;
  ulong            dedup_out_mtu;
};

typedef struct fd_verify_tile_topo fd_verify_tile_topo_t;

struct __attribute__((aligned(FD_VERIFY_TILE_ALIGN))) fd_verify_tile_private {
  /* TODO switch to fd_sha512_batch_t? */
  fd_sha512_t * sha[ FD_TXN_ACTUAL_SIG_MAX ];

  ulong   tcache_depth;
  ulong   tcache_map_cnt;
  ulong * tcache_sync;
  ulong * tcache_ring;
  ulong * tcache_map;

  fd_wksp_t * in_mem;
  ulong       in_chunk0;
  ulong       in_wmark;

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
};

typedef struct fd_verify_tile_private fd_verify_tile_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_verify_tile_align( void );

FD_FN_PURE ulong
fd_verify_tile_footprint( void const * args );

ulong
fd_verify_tile_seccomp_policy( void *               shverify,
                               struct sock_filter * out,
                               ulong                out_cnt );

ulong
fd_verify_tile_allowed_fds( void * shverify,
                            int *  out,
                            ulong  out_cnt );

fd_verify_tile_t *
fd_verify_tile_join( void *                        shverify,
                     void const *                  args,
                     fd_verify_tile_topo_t const * topo );

#define FD_TXN_VERIFY_SUCCESS  0
#define FD_TXN_VERIFY_FAILED  -1
#define FD_TXN_VERIFY_DEDUP   -2

int
fd_verify_tile_txn_verify( fd_verify_tile_t * ctx,
                           uchar const *      udp_payload,
                           ushort const       payload_sz,
                           fd_txn_t const *   txn,
                           ulong *            opt_sig );

void
fd_verify_tile_run( fd_verify_tile_t *      verify,
                    fd_cnc_t *              cnc,
                    ulong                   in_cnt,
                    fd_frag_meta_t const ** in_mcache,
                    ulong **                in_fseq,
                    fd_frag_meta_t *        mcache,
                    ulong                   out_cnt,
                    ulong **                out_fseq );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_fd_disco_tiles_verify_fd_verify_tile_h */

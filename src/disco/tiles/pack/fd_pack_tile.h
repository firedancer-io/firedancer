#ifndef HEADER_fd_src_disco_tiles_pack_fd_pack_tile_h
#define HEADER_fd_src_disco_tiles_pack_fd_pack_tile_h

/* fd_pack is responsible for taking verified transactions, and
   arranging them into "microblocks" (groups) of transactions to be
   executed serially.  It can try to do clever things so that multiple
   microblocks can execute in parallel, if they don't write to the same
   accounts. */

#include "../../fd_disco_base.h"
#include "../../mux/fd_mux.h"

/* TODO: fd_stake_ci probably belongs elsewhere */
#include "../../shred/fd_stake_ci.h"
#include "../../shred/fd_shredder.h"

#include "../../../ballet/pack/fd_pack.h"

#define FD_PACK_TILE_ALIGN (4096UL)

/* About 1.5 kB on the stack */
#define FD_PACK_TILE_PACK_MAX_OUT (16UL)

struct fd_pack_tile_args {
  ulong        max_pending_transactions;
  ulong        bank_tile_count;
  char const * identity_key_path;
};

typedef struct fd_pack_tile_args fd_pack_tile_args_t;

struct fd_pack_tile_topo {
  ulong       in_cnt;
  fd_wksp_t * in_wksp[ 32 ];
  void *      in_dcache[ 32 ];
  ulong       in_mtu[ 32 ];

  ulong       stake_info_in_idx;
  ulong       poh_in_idx;

  ulong       bank_tile_cnt;

  fd_wksp_t * out_wksp;
  void *      out_dcache;
  ulong       out_mtu;

  ulong *     out_busy[ FD_PACK_TILE_PACK_MAX_OUT ];
};

typedef struct fd_pack_tile_topo fd_pack_tile_topo_t;

struct fd_pack_tile_in {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
};

typedef struct fd_pack_tile_in fd_pack_tile_in_t;

struct __attribute__((aligned(FD_PACK_TILE_ALIGN))) fd_pack_tile_private {
  fd_pack_t *  pack;
  fd_txn_p_t * cur_spot;

  fd_pubkey_t identity_pubkey __attribute__((aligned(32UL)));

  ulong poh_in_idx;
  ulong stake_info_in_idx;

  fd_rng_t rng[ 1 ];

  /* The leader slot we are currently packing for, or ULONG_MAX if we
     are not the leader. */
  ulong  leader_slot;

  /* The end wallclock time of the leader slot we are currently packing
     for, if we are currently packing for a slot.

     _slot_end_ns is used as a temporary between during_frag and
     after_frag in case the tile gets overrun. */
  long _slot_end_ns;
  long slot_end_ns;

  fd_pack_tile_in_t in[ 32 ];

  ulong    out_cnt;
  ulong *  out_current[ FD_PACK_TILE_PACK_MAX_OUT ];
  ulong    out_expect[ FD_PACK_TILE_PACK_MAX_OUT  ];
  long     out_ready_at[ FD_PACK_TILE_PACK_MAX_OUT  ];

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;

  ulong      insert_result[ FD_PACK_INSERT_RETVAL_CNT ];
  fd_histf_t schedule_duration[ 1 ];
  fd_histf_t insert_duration  [ 1 ];

  fd_stake_ci_t stake_ci[ 1 ];
} fd_pack_ctx_t;

typedef struct fd_pack_tile_private fd_pack_tile_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_pack_tile_align( void );

FD_FN_PURE ulong
fd_pack_tile_footprint( fd_pack_tile_args_t const * args );

FD_FN_CONST long
fd_pack_tile_lazy( fd_pack_tile_args_t const * args );

ulong
fd_pack_tile_seccomp_policy( void *               shpack,
                             struct sock_filter * out,
                             ulong                out_cnt );

ulong
fd_pack_tile_allowed_fds( void * shpack,
                          int *  out,
                          ulong  out_cnt );

void
fd_pack_tile_join_privileged( void *                      shpack,
                              fd_pack_tile_args_t const * args );

fd_pack_tile_t *
fd_pack_tile_join( void *                      shpack,
                   fd_pack_tile_args_t const * args,
                   fd_pack_tile_topo_t const * topo );

void
fd_pack_tile_run( fd_pack_tile_t *        ctx,
                  fd_cnc_t *              cnc,
                  ulong                   in_cnt,
                  fd_frag_meta_t const ** in_mcache,
                  ulong **                in_fseq,
                  fd_frag_meta_t *        mcache,
                  ulong                   out_cnt,
                  ulong **                out_fseq );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_fd_disco_tiles_pack_fd_pack_tile_h */

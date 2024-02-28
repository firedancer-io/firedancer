#ifndef HEADER_fd_src_disco_tiles_bank_fd_bank_tile_h
#define HEADER_fd_src_disco_tiles_bank_fd_bank_tile_h

#include "../../fd_disco_base.h"
#include "../../mux/fd_mux.h"

#define FD_BANK_TILE_ALIGN (128UL)

struct fd_bank_tile_topo {
  ulong tidx;

  ulong * bank_busy;

  ulong poh_in_idx;
  ulong pack_in_idx;

  fd_wksp_t * pack_in_wksp;
  void *      pack_in_dcache;
  ulong       pack_in_mtu;

  fd_wksp_t * poh_in_wksp;
  void *      poh_in_dcache;
  ulong       poh_in_mtu;

  fd_wksp_t * out_wksp;
  void *      out_dcache;
  ulong       out_mtu;
};

typedef struct fd_bank_tile_topo fd_bank_tile_topo_t;

struct __attribute__((aligned(FD_BANK_TILE_ALIGN))) fd_bank_tile_private {
  ulong tidx;

  fd_blake3_t * blake3;

  fd_became_leader_t leader_frag;
  ulong              leader_bank_slot;
  void const *       leader_bank;

  uchar * txn_abi_mem;
  uchar * txn_sidecar_mem;

  ulong * bank_busy;

  ulong poh_in_idx;
  ulong pack_in_idx;

  fd_wksp_t * pack_in_mem;
  ulong       pack_in_chunk0;
  ulong       pack_in_wmark;

  fd_wksp_t * poh_in_mem;
  ulong       poh_in_chunk0;
  ulong       poh_in_wmark;

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;

  struct {
    ulong slot_acquire[ 3 ];

    ulong txn_load_address_lookup_tables[ 6 ];
    ulong txn_load[ 38 ];
    ulong txn_executing[ 38 ];
    ulong txn_executed[ 38 ];
  } metrics;
};

typedef struct fd_bank_tile_private fd_bank_tile_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_bank_tile_align( void );

FD_FN_PURE ulong
fd_bank_tile_footprint( void const * args );

fd_bank_tile_t *
fd_bank_tile_join( void *                     shbank,
                  void const *                args,
                  fd_bank_tile_topo_t const * topo );

void
fd_bank_tile_run( fd_bank_tile_t *        bank,
                  fd_cnc_t *              cnc,
                  ulong                   in_cnt,
                  fd_frag_meta_t const ** in_mcache,
                  ulong **                in_fseq,
                  fd_frag_meta_t *        mcache,
                  ulong                   out_cnt,
                  ulong **                out_fseq );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_fd_disco_tiles_bank_fd_bank_tile_h */

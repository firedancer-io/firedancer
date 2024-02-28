#ifndef HEADER_fd_src_disco_tiles_store_fd_store_tile_h
#define HEADER_fd_src_disco_tiles_store_fd_store_tile_h

#include "../../fd_disco_base.h"
#include "../../mux/fd_mux.h"

#define FD_STORE_TILE_ALIGN (128UL)

struct fd_store_tile_topo {
  fd_wksp_t * in_wksp;
  void *      in_dcache;
  ulong       in_mtu;
};

typedef struct fd_store_tile_topo fd_store_tile_topo_t;

struct __attribute__((aligned(FD_STORE_TILE_ALIGN))) fd_store_tile_private {
  uchar __attribute__((aligned(32UL))) mem[ FD_SHRED_STORE_MTU ];

  fd_wksp_t * in_mem;
  ulong       in_chunk0;
  ulong       in_wmark;
};

typedef struct fd_store_tile_private fd_store_tile_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_store_tile_align( void );

FD_FN_PURE ulong
fd_store_tile_footprint( void const * args );

fd_store_tile_t *
fd_store_tile_join( void *                       shstore,
                    void const *                 args,
                    fd_store_tile_topo_t const * topo );

void
fd_store_tile_run( fd_store_tile_t *       store,
                   fd_cnc_t *              cnc,
                   ulong                   in_cnt,
                   fd_frag_meta_t const ** in_mcache,
                   ulong **                in_fseq,
                   fd_frag_meta_t *        mcache,
                   ulong                   out_cnt,
                   ulong **                out_fseq );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_fd_disco_tiles_store_fd_store_tile_h */

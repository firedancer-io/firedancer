#ifndef HEADER_fd_src_discof_restore_utils_fd_restore_test_base
#define HEADER_fd_src_discof_restore_utils_fd_restore_test_base

#include "../../../util/fd_util_base.h"
#include "../../../disco/topo/fd_topo.h"

#define FD_RESTORE_MAX_OUT_LINKS 16UL

struct fd_restore_link_in {
  ulong                  topo_idx;
  char                   name[ 13UL ];
  fd_wksp_t *            mem;
  fd_frag_meta_t const * mcache;
  fd_frag_meta_t const * mline;
  ulong                  seq;
  ulong                  depth;
  int                    ready;

  struct {
    ulong chunk;
    ulong sig;
    ulong sz;
    ulong ctl;
    ulong tsorig;
    ulong tspub;
  } result;
};

typedef struct fd_restore_link_in  fd_restore_link_in_t;

struct fd_restore_link_out {
  ulong            topo_idx;
  fd_wksp_t *      mem;
  ulong            chunk0;
  ulong            chunk;
  ulong            depth;
  ulong            mtu;
  void *           dcache;
  fd_frag_meta_t * mcache; /* only used if the link has no consumers */
};

typedef struct fd_restore_link_out fd_restore_link_out_t;

static char const snapshots_path[] = "src/discof/restore/test/env";

struct fd_restore_stem_mock {
  fd_frag_meta_t * out_mcache[ FD_RESTORE_MAX_OUT_LINKS ];
  ulong            out_depth [ FD_RESTORE_MAX_OUT_LINKS ];
  ulong            seqs      [ FD_RESTORE_MAX_OUT_LINKS ];
  ulong            cr_avail  [ FD_RESTORE_MAX_OUT_LINKS ];
  ulong            min_cr_avail;
};

typedef struct fd_restore_stem_mock fd_restore_stem_mock_t;

static inline void
fd_restore_link_in_init( fd_restore_link_in_t * in,
                         fd_topo_t *            topo,
                         fd_topo_link_t *       link ) {
  in->topo_idx = link->id;
  memcpy( in->name, link->name, sizeof(link->name) );
  in->mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
  in->mcache = topo->links[ link->id ].mcache;
  in->depth  = link->depth;
  in->seq    = 0UL;
  in->mline  = in->mcache + fd_mcache_line_idx( in->seq, in->depth );
  in->ready  = 0;
}

static inline void
fd_restore_link_out_init( fd_restore_link_out_t * out,
                          fd_topo_t *             topo,
                          fd_topo_link_t *        link ) {
  out->topo_idx = link->id;
  out->mem      = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
  out->chunk0   = fd_dcache_compact_chunk0( out->mem, link->dcache );
  out->depth    = link->depth;
  out->mtu      = link->mtu;
  out->chunk    = out->chunk0;
  out->dcache   = link->dcache;
}

static inline int
fd_restore_poll_link_in( fd_restore_link_in_t * in ) {
  ulong seq_found = FD_VOLATILE_CONST( in->mline->seq );
  long  diff      = fd_seq_diff( in->seq, seq_found );

  if( FD_UNLIKELY( diff ) ) {
    if( FD_UNLIKELY( diff<0L ) ) {
      FD_LOG_ERR(( "overrun detected on restore input link %s: expected seq %lu found %lu",
                   in->name, in->seq, seq_found ));
    }
    in->ready = 0;
    return 0;
  }

  in->result.chunk  = in->mline->chunk;
  in->result.sig    = in->mline->sig;
  in->result.sz     = in->mline->sz;
  in->result.ctl    = in->mline->ctl;
  in->result.tsorig = in->mline->tsorig;
  in->result.tspub  = in->mline->tspub;

  in->seq   = fd_seq_inc( in->seq, 1UL );
  in->mline = in->mcache + fd_mcache_line_idx( in->seq, in->depth );
  in->ready = 1;
  return 1;
}

static inline void
fd_restore_init_stem( fd_restore_stem_mock_t * stem,
                      fd_topo_t *              topo,
                      fd_topo_tile_t *         tile ) {
  for( ulong i=0; i<tile->out_cnt; i++ ) {
    stem->out_mcache[ i ] = topo->links[ tile->out_link_id[ i ] ].mcache;
    stem->out_depth [ i ] = topo->links[ tile->out_link_id[ i ] ].depth;
    stem->seqs      [ i ] = 0UL;
    stem->cr_avail  [ i ] = 8UL;
  }
  stem->min_cr_avail = 8UL;
}

#endif /* HEADER_fd_src_discof_restore_utils_fd_restore_test_base */

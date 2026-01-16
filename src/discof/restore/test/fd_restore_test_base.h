#ifndef HEADER_fd_src_discof_restore_utils_fd_restore_test_base
#define HEADER_fd_src_discof_restore_utils_fd_restore_test_base

#include "../../../util/fd_util_base.h"
#include "../../../disco/topo/fd_topo.h"
#include "../../../disco/topo/fd_topob.h"

#define FD_RESTORE_MAX_OUT_LINKS (16UL)
#define WKSP_TAG                 (1UL)
#define LINK_DEPTH               (8UL)

/* fd_restore_test_base.h contains common link definitions and helper
   functions to create mcache/dcache links and poll them in a non-stem
   testing context. */

struct fd_restore_link_in {
  ulong                  topo_idx;     /* index of link in topology object */
  char                   name[ 13UL ];
  fd_wksp_t *            mem;
  fd_frag_meta_t const * mcache;
  fd_frag_meta_t const * mline;        /* points to next entry in mcache */
  ulong                  seq;
  ulong                  depth;
  int                    valid;        /* indicates whether result is valid */

  /* contains result of poll, if any */
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
};

typedef struct fd_restore_link_out fd_restore_link_out_t;

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
  in->valid  = 0;
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

/* fd_restore_poll_link_in polls the in link and returns whether a new
   message was successfully polled from the in link. */
static inline int
fd_restore_poll_link_in( fd_restore_link_in_t * in ) {
  ulong seq_found = FD_VOLATILE_CONST( in->mline->seq );
  long  diff      = fd_seq_diff( in->seq, seq_found );

  if( FD_UNLIKELY( diff ) ) {
    if( FD_UNLIKELY( diff<0L ) ) {
      FD_LOG_ERR(( "overrun detected on restore input link %s: expected seq %lu found %lu",
                   in->name, in->seq, seq_found ));
    }
    in->valid = 0;
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
  in->valid = 1;
  return 1;
}

/* fd_restore_init_stem inits a mock fd_restore_stem_mock_t object
   with necessary fields to create a mock stem instance.
   See fd_snapct_test_topo_after_credit for how the mock stem instance
   is used. */
static inline void
fd_restore_init_stem( fd_restore_stem_mock_t * stem,
                      fd_topo_t *              topo,
                      fd_topo_tile_t *         tile ) {
  for( ulong i=0; i<tile->out_cnt; i++ ) {
    stem->out_mcache[ i ] = topo->links[ tile->out_link_id[ i ] ].mcache;
    stem->out_depth [ i ] = topo->links[ tile->out_link_id[ i ] ].depth;
    stem->seqs      [ i ] = 0UL;
    stem->cr_avail  [ i ] = LINK_DEPTH;
  }
  stem->min_cr_avail = LINK_DEPTH;
}

/* fd_restore_create_link creates a link in the given topology object
   with the given link parameters.

   wksp points to a wksp. topo points to a topology object.  link_name
   is the name of the link. wksp_name is the name of the wksp.  depth is
   the link depth.  mtu is the link mtu entry size.  permit_no_consumers
   should be 1 if the link does not have consumers.  permit_no_producer
   should be 1 if the link has no producer. */
static inline void
fd_restore_create_link( fd_wksp_t *  wksp,
                        fd_topo_t *  topo,
                        char const * link_name,
                        char const * wksp_name,
                        ulong        depth,
                        ulong        mtu,
                        int          permit_no_consumers,
                        int          permit_no_producer ) {
  fd_topo_link_t * link   = fd_topob_link( topo, link_name, wksp_name, depth, mtu, 1UL );
  void *           mcache = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( depth, 0UL ), WKSP_TAG );
  FD_TEST( fd_mcache_new( mcache, depth, 0UL, 0UL ) );
  topo->objs[ link->mcache_obj_id ].offset = fd_wksp_gaddr_fast( wksp, mcache );

  ulong const in_data_sz = fd_dcache_req_data_sz( mtu, depth, 1UL, 1 );
  void *       dcache    = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( in_data_sz, 0UL ), WKSP_TAG );
  FD_TEST( fd_dcache_new( dcache, in_data_sz, 0UL ) );
  topo->objs[ link->dcache_obj_id ].offset = fd_wksp_gaddr_fast( wksp, dcache );

  link->mcache = fd_mcache_join( mcache );
  link->dcache = fd_dcache_join( dcache );
  link->permit_no_consumers = !!permit_no_consumers;
  link->permit_no_producers = !!permit_no_producer;
}

#endif /* HEADER_fd_src_discof_restore_utils_fd_restore_test_base */

#include "../../disco/topo/fd_topo.h"
#include "../../util/wksp/fd_wksp_private.h" /* why does this depend on private APIs? */

#define SHAM_LINK_(n) FD_EXPAND_THEN_CONCAT3(SHAM_LINK_NAME,_,n)

struct SHAM_LINK_NAME {
  fd_frag_meta_t * mcache;
  fd_wksp_t *      wksp;
  ulong            depth;
  ulong            seq_expect;
};

typedef struct SHAM_LINK_NAME SHAM_LINK_(t);

static inline ulong SHAM_LINK_(align)(void)     { return alignof(SHAM_LINK_(t)); }
static inline ulong SHAM_LINK_(footprint)(void) { return sizeof(SHAM_LINK_(t)); }

static inline SHAM_LINK_(t) *
SHAM_LINK_(new)( void * mem, const char * wksp_name ) {
  SHAM_LINK_(t) * self = (SHAM_LINK_(t) *)mem;
  memset( self, 0, sizeof(SHAM_LINK_(t)) );
  FD_LOG_NOTICE(( "attaching to workspace \"%s\"", wksp_name ));
  self->wksp = fd_wksp_attach( wksp_name );
  if( FD_UNLIKELY( !self->wksp ) )
    FD_LOG_ERR(( "unable to attach to \"%s\"\n\tprobably does not exist or bad permissions", wksp_name ));
  ulong offset = fd_ulong_align_up( fd_wksp_private_data_off( self->wksp->part_max ), fd_topo_workspace_align() );
  self->mcache = fd_mcache_join( (void *)((ulong)self->wksp + offset) );
  if( self->mcache == NULL ) {
    FD_LOG_ERR(( "failed to join a mcache" ));
  }
  return self;
}

static inline void
SHAM_LINK_(start)( SHAM_LINK_(t) * self ) {
  fd_frag_meta_t * mcache = self->mcache;
  self->depth  = fd_mcache_depth( mcache );
  self->seq_expect = fd_mcache_seq0( mcache );
}

static void
SHAM_LINK_(during_frag)( SHAM_LINK_CONTEXT * ctx, SHAM_LINK_STATE * state, void const * msg, int sz );

static void
SHAM_LINK_(after_frag)( SHAM_LINK_CONTEXT * ctx, SHAM_LINK_STATE * state );

static inline void
SHAM_LINK_(poll)( SHAM_LINK_(t) * self, SHAM_LINK_CONTEXT * ctx, SHAM_LINK_STATE * state ) {
  while (1) {
    fd_frag_meta_t const * mline = self->mcache + fd_mcache_line_idx( self->seq_expect, self->depth );

    ulong seq_found = fd_frag_meta_seq_query( mline );
    long  diff      = fd_seq_diff( seq_found, self->seq_expect );
    if( FD_UNLIKELY( diff ) ) { /* caught up or overrun, optimize for expected sequence number ready */
      if( FD_UNLIKELY( diff>0L ) ) {
        FD_LOG_NOTICE(( "overrun: seq=%lu seq_found=%lu diff=%ld", self->seq_expect, seq_found, diff ));
        self->seq_expect = seq_found;
      } else {
        /* caught up */
        break;
      }
      continue;
    }

    ulong chunk = mline->chunk;
    /* TODO: sanity check chunk,sz */
    SHAM_LINK_(during_frag)( ctx, state, fd_chunk_to_laddr( self->wksp, chunk ), mline->sz );

    seq_found = fd_frag_meta_seq_query( mline );
    diff      = fd_seq_diff( seq_found, self->seq_expect );
    if( FD_UNLIKELY( diff ) ) { /* overrun, optimize for expected sequence number ready */
      FD_LOG_NOTICE(( "overrun: seq=%lu seq_found=%lu diff=%ld", self->seq_expect, seq_found, diff ));
      self->seq_expect = seq_found;
      continue;
    }

    SHAM_LINK_(after_frag)( ctx, state );

    self->seq_expect++;
  }
}

#undef SHAM_LINK_CONTEXT
#undef SHAM_LINK_STATE
#undef SHAM_LINK_NAME
#undef SHAM_LINK_

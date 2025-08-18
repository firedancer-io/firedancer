#include "../../../../disco/stem/fd_stem.h"
#include <sched.h>

struct fd_echo_tile { uchar dummy; };
typedef struct fd_echo_tile fd_echo_tile_t;

static void
after_frag( void *              _ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               _tspub,
            fd_stem_context_t * stem ) {
  (void)_ctx; (void)in_idx; (void)seq; (void)sz; (void)_tspub;
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, 0UL, sig, 0UL, 0UL, 0UL, tsorig, tspub );
}

static void
during_housekeeping( fd_echo_tile_t * ctx ) {
  (void)ctx;
  sched_yield();
}

#define STEM_BURST                  (1UL)
#define STEM_CALLBACK_CONTEXT_TYPE  fd_echo_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_echo_tile_t)
#define STEM_CALLBACK_AFTER_FRAG    after_frag
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#include "../../../../disco/stem/fd_stem.c"

static ulong scratch_align( void ) { return alignof(fd_echo_tile_t); }
static ulong scratch_footprint( fd_topo_tile_t const * tile ) { (void)tile; return sizeof(fd_echo_tile_t); }

fd_topo_run_tile_t fd_tile_echo = {
  .name              = "echo",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .run               = stem_run
};

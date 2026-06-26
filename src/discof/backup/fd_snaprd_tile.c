#include "../../disco/topo/fd_topo.h"
#include "../../flamenco/accdb/fd_accdb.h"

#define STEM_BURST 64UL /* 64 * 64KiB -> 4MiB */

struct fd_snaprd {
  fd_accdb_shmem_t const * accdb;

  struct {
    uchar * base;
    ulong   chunk0;
    ulong   wmark;
    ulong   chunk;
  } out;
};

typedef struct fd_snaprd fd_snaprd_t;

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo; (void)tile;
  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = FD_ACCDB_FD_RO; /* accounts db readonly fd */
  return out_cnt;
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof(fd_snaprd_t);
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  return sizeof(fd_snaprd_t);
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  fd_snaprd_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_CHECK_ERR( tile->out_cnt==1UL, "topology mismatch" );
  fd_topo_link_t const * out_link = &topo->links[ tile->out_link_id[ 0 ] ];
  FD_CHECK_ERR( !strcmp( out_link->name, "snaprd_out" ), "topology mismatch" );
}

static void
after_credit( fd_snaprd_t *       ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {

}

static void
metrics_write( fd_snaprd_t * ctx ) {

}

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snaprd_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snaprd_t)
#define STEM_CALLBACK_AFTER_CREDIT  after_credit
#define STEM_CALLBACK_METRICS_WRITE metrics_write
#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snaprd = {
  .name                 = "snaprd",
  .populate_allowed_fds = populate_allowed_fds,
  .scratch_align        = scratch_align,
  .scratch_footprint    = scratch_footprint,
  .unprivileged_init    = unprivileged_init,
  .run                  = stem_run,
  .allow_renameat       = 1
};

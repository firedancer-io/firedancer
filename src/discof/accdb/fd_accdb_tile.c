#include "../../disco/tiles.h"

#include "generated/fd_accdb_tile_seccomp.h"

#include "../../disco/metrics/fd_metrics.h"

#include "fd_accdb.h"

#include <fcntl.h>
#include <errno.h>

struct fd_accdb_tile_ctx {
  int fd;

  fd_accdb_t * accdb;

  ulong seed;
};

typedef struct fd_accdb_tile_ctx fd_accdb_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof( fd_accdb_tile_ctx_t );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_accdb_tile_ctx_t ), sizeof( fd_accdb_tile_ctx_t )                        );
  l = FD_LAYOUT_APPEND( l, fd_accdb_shmem_align(),         fd_accdb_shmem_footprint( tile->accdb.max_accounts,
                                                                                     tile->accdb.max_unrooted_slots,
                                                                                     tile->accdb.max_txn_per_slot,
                                                                                     tile->accdb.partition_cnt,
                                                                                     tile->accdb.cache_footprint,
                                                                                     tile->accdb.joiner_cnt )   );
  l = FD_LAYOUT_APPEND( l, fd_accdb_align(),               fd_accdb_footprint( tile->accdb.max_unrooted_slots ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
metrics_write( fd_accdb_tile_ctx_t * ctx ) {
  fd_accdb_shmem_metrics_t const * metrics = fd_accdb_metrics( ctx->accdb );

  FD_MGAUGE_SET( ACCDB, ACCOUNTS_TOTAL,         metrics->accounts_total );
  FD_MGAUGE_SET( ACCDB, ACCOUNTS_CAPACITY,      metrics->accounts_capacity );
  FD_MCNT_SET( ACCDB, BYTES_READ,               metrics->bytes_read );
  FD_MCNT_SET( ACCDB, BYTES_WRITTEN,            metrics->bytes_written );
  FD_MCNT_SET( ACCDB, ACCOUNTS_READ,            metrics->accounts_read );
  FD_MCNT_SET( ACCDB, ACCOUNTS_WRITTEN,         metrics->accounts_written );
  FD_MCNT_SET( ACCDB, ACCOUNTS_RELOCATED,       metrics->accounts_relocated );
  FD_MGAUGE_SET( ACCDB, DISK_ALLOCATED_BYTES,   metrics->disk_allocated_bytes );
  FD_MGAUGE_SET( ACCDB, DISK_USED_BYTES,        metrics->disk_used_bytes );
  FD_MGAUGE_SET( ACCDB, IN_COMPACTION,          (ulong)metrics->in_compaction );
  FD_MCNT_SET( ACCDB, COMPACTIONS_REQUESTED,    metrics->compactions_requested );
  FD_MCNT_SET( ACCDB, COMPACTIONS_COMPLETED,    metrics->compactions_completed );
  FD_MCNT_SET( ACCDB, ACCOUNTS_RELOCATED_BYTES, metrics->accounts_relocated_bytes );
}

static inline void
before_credit( fd_accdb_tile_ctx_t * ctx,
               fd_stem_context_t *   stem FD_FN_UNUSED,
               int *                 charge_busy ) {
  fd_accdb_background( ctx->accdb, charge_busy );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_accdb_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_accdb_tile_ctx_t ), sizeof( fd_accdb_tile_ctx_t ) );
  FD_TEST( fd_rng_secure( &ctx->seed, 8U ) );

  ctx->fd = open( tile->accdb.path, O_RDWR|O_TRUNC|O_CREAT|O_CLOEXEC, 0644 );
  if( FD_UNLIKELY( ctx->fd<0 ) ) {
    FD_LOG_ERR(( "failed to open accounts database file %s (%d-%s)", tile->accdb.path, errno, fd_io_strerror( errno ) ));
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_accdb_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_accdb_tile_ctx_t ), sizeof( fd_accdb_tile_ctx_t ) );

  fd_accdb_shmem_t * shmem = fd_accdb_shmem_join(
      fd_accdb_shmem_new(
          FD_SCRATCH_ALLOC_APPEND( l, fd_accdb_shmem_align(),
                                      fd_accdb_shmem_footprint( tile->accdb.max_accounts,
                                                                tile->accdb.max_unrooted_slots,
                                                                tile->accdb.max_txn_per_slot,
                                                                tile->accdb.partition_cnt,
                                                                tile->accdb.cache_footprint,
                                                                tile->accdb.joiner_cnt ) ),
          tile->accdb.max_accounts,
          tile->accdb.max_unrooted_slots,
          tile->accdb.max_txn_per_slot,
          tile->accdb.partition_cnt,
          tile->accdb.partition_sz,
          tile->accdb.cache_footprint,
          ctx->seed,
          tile->accdb.joiner_cnt ) );
  FD_TEST( shmem );

  void * accdb_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_accdb_align(),
                                                  fd_accdb_footprint( tile->accdb.max_unrooted_slots ) );
  ctx->accdb = fd_accdb_join( fd_accdb_new( accdb_mem, shmem, ctx->fd ) );
  FD_TEST( ctx->accdb );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_accdb_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_accdb_tile_ctx_t ), sizeof( fd_accdb_tile_ctx_t ) );

  populate_sock_filter_policy_fd_accdb_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->fd );
  return sock_filter_policy_fd_accdb_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_accdb_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_accdb_tile_ctx_t ), sizeof( fd_accdb_tile_ctx_t ) );

  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = ctx->fd; /* accounts db fd */
  return out_cnt;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_accdb_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_accdb_tile_ctx_t)

#define STEM_CALLBACK_METRICS_WRITE metrics_write
#define STEM_CALLBACK_BEFORE_CREDIT before_credit

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_accdb = {
  .name                     = "accdb",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};

/* The strmk tile writes instant boot streams.

   A boot stream is an archive that starts at a slot and grows by one
   appendvec per block, so that a peer can start executing before its
   snapshot has finished loading.  The replay tile feeds this tile the
   accounts each block touches, the tile reads their values at the
   stream's start slot through a read-only accounts join, and the
   snapsv tile serves the files over HTTP.

   This tile owns a fixed pool of files in a directory below the
   snapshots directory: one file per open stream, the index, and the
   scratch file that the index is renamed from.  The files are opened
   before the sandbox starts, because the sandbox bans opening
   files. */

#define _GNU_SOURCE
#include <linux/futex.h>
#include <string.h>

#include "fd_strmk_tile.h"
#include "fd_snapmk_tile.h"
#include "../../disco/stem/fd_stem.h"
#include "../../disco/topo/fd_topo.h"
#include "../../flamenco/accdb/fd_accdb.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../tango/fseq/fd_fseq.h"

#include "generated/fd_strmk_tile_seccomp.h"

struct fd_strmk {
  /* the boot file directory, kept open for the index rename */
  int  dir_fd;
  uint stream_max;

  fd_banks_t *    banks;
  fd_txncache_t * txncache;
  fd_accdb_t *    accdb;
};

typedef struct fd_strmk fd_strmk_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( fd_ulong_max( alignof(fd_strmk_t), fd_txncache_align() ), fd_accdb_align() );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong max_live_slots = tile->strmk.max_live_slots;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_strmk_t),  sizeof(fd_strmk_t)                      );
  l = FD_LAYOUT_APPEND( l, fd_txncache_align(),  fd_txncache_footprint( max_live_slots )  );
  l = FD_LAYOUT_APPEND( l, fd_accdb_align(),     fd_accdb_footprint( max_live_slots, 0 )  );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_strmk_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_strmk_t), sizeof(fd_strmk_t) );
  memset( ctx, 0, sizeof(fd_strmk_t) );

  FD_CHECK_ERR( tile->strmk.max_open_streams &&
                tile->strmk.max_open_streams<=FD_STRMK_STREAM_MAX,
                "[snapshots.instant_boot.serve.max_open_streams] is out of range" );
  ctx->stream_max = (uint)tile->strmk.max_open_streams;

  char dir_path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( dir_path, PATH_MAX, NULL, "%s/%s", tile->strmk.snapshots_path, FD_STRMK_DIR ) );
  ctx->dir_fd = fd_strmk_dir_open( dir_path );

  char name[ FD_SNAP_NAME_MAX ];
  for( uint i=0U; i<ctx->stream_max; i++ ) {
    fd_strmk_file_open( ctx->dir_fd, dir_path, fd_strmk_stream_name( name, i ), O_RDWR, FD_STRMK_FD( i ) );
  }
  fd_strmk_file_open( ctx->dir_fd, dir_path, FD_STRMK_INDEX,     O_RDWR, FD_STRMK_FD( ctx->stream_max    ) );
  fd_strmk_file_open( ctx->dir_fd, dir_path, FD_STRMK_INDEX_TMP, O_RDWR, FD_STRMK_FD( ctx->stream_max+1U ) );

  /* Nothing from a previous run is served: a stream cannot be resumed,
     and the index would name streams that are gone. */
  for( uint i=0U; i<ctx->stream_max+2U; i++ ) {
    if( FD_UNLIKELY( -1==ftruncate( FD_STRMK_FD( i ), 0L ) ) ) {
      FD_LOG_ERR(( "ftruncate() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
  }
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_strmk_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_UNLIKELY( out_fds_cnt<6UL+(ulong)ctx->stream_max ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = ctx->dir_fd;
  out_fds[ out_cnt++ ] = FD_ACCDB_FD_RO;
  for( uint i=0U; i<ctx->stream_max+2U; i++ )
    out_fds[ out_cnt++ ] = FD_STRMK_FD( i ); /* streams, index, index scratch */
  return out_cnt;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  fd_strmk_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  populate_sock_filter_policy_fd_strmk_tile(
      out_cnt, out,
      (uint)fd_log_private_logfile_fd(),
      (uint)ctx->dir_fd,
      (uint)FD_STRMK_FD( 0 ), (uint)FD_STRMK_FD( ctx->stream_max+1U ),
      (uint)FD_ACCDB_FD_RO );
  return sock_filter_policy_fd_strmk_tile_instr_cnt;
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch        = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  ulong  max_live_slots = tile->strmk.max_live_slots;

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_strmk_t * ctx       = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_strmk_t),  sizeof(fd_strmk_t) );
  void *       _txncache = FD_SCRATCH_ALLOC_APPEND( l, fd_txncache_align(),  fd_txncache_footprint( max_live_slots ) );
  void *       _accdb    = FD_SCRATCH_ALLOC_APPEND( l, fd_accdb_align(),     fd_accdb_footprint( max_live_slots, 0 ) );
  ulong end = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  FD_CHECK_CRIT( end==(ulong)scratch + scratch_footprint( tile ), "bug when calculating tile memory layout" );

  ctx->banks = fd_banks_join( fd_topo_obj_laddr( topo, tile->strmk.banks_obj_id ) );
  FD_TEST( ctx->banks );

  fd_txncache_shmem_t * txncache_shmem = fd_txncache_shmem_join( fd_topo_obj_laddr( topo, tile->strmk.txncache_obj_id ) );
  FD_TEST( txncache_shmem );
  ctx->txncache = fd_txncache_join( fd_txncache_new( _txncache, txncache_shmem ) );
  FD_TEST( ctx->txncache );

  /* Read-only join to accdb.  The accounts workspace is mapped
     PROT_READ in this tile; the epoch fseq is the only writable
     mapping, and tells the accdb tile which epoch this tile reads so
     that compaction does not reclaim partitions mid-read. */
  fd_accdb_shmem_t * accdb_shmem = fd_accdb_shmem_join( fd_topo_obj_laddr( topo, tile->strmk.accdb_obj_id ) );
  FD_TEST( accdb_shmem );
  ulong * epoch_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, tile->strmk.accdb_epoch_obj_id ) );
  FD_TEST( epoch_fseq );
  ctx->accdb = fd_accdb_join_readonly( _accdb, accdb_shmem, epoch_fseq, FD_ACCDB_FD_RO );
  FD_TEST( ctx->accdb );

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if( FD_UNLIKELY( strcmp( link->name, "replay_strmk" ) ) ) {
      FD_LOG_ERR(( "unexpected input link \"%s\"", link->name ));
    }
  }

  /* The tile asks replay for banks on strmk_replay and tells the file
     server about stream files on strmk_out. */
  FD_CHECK_ERR( fd_topo_find_tile_out_link( topo, tile, "strmk_replay", 0UL )!=ULONG_MAX, "missing strmk_replay link" );
  ulong out_idx = fd_topo_find_tile_out_link( topo, tile, "strmk_out", 0UL );
  FD_CHECK_ERR( out_idx!=ULONG_MAX, "missing strmk_out link" );
  FD_CHECK_ERR( topo->links[ tile->out_link_id[ out_idx ] ].mtu>=sizeof(fd_snapmk_msg_t), "strmk_out link MTU too small" );
}

static void
after_credit( fd_strmk_t *        ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)ctx; (void)stem; (void)opt_poll_in; (void)charge_busy;
}

#define STEM_BURST 1UL

#define STEM_CALLBACK_CONTEXT_TYPE  fd_strmk_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_strmk_t)
#define STEM_CALLBACK_AFTER_CREDIT  after_credit

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_strmk = {
  .name                     = "strmk",
  .populate_allowed_fds     = populate_allowed_fds,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
  .allow_renameat           = 1
};

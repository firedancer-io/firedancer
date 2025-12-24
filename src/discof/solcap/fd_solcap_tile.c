/* The solcap tile collects solcap events emitted by various tiles in
   the system, and writes them out to a pcapng file. */

#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/solcap/fd_pkt_w_pcapng.h"
#include "../../util/net/fd_pcapng.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

#include "generated/fd_solcap_tile_seccomp.h"

/* Tile state */

#define MAX_IN_LINKS 256

struct fd_solcap_link_in {
  void * base;
  ulong  chunk0;
  ulong  wmark;
  ulong  mtu;
};
typedef struct fd_solcap_link_in fd_solcap_link_in_t;

struct fd_solcap_tile_ctx {
  fd_capture_ctx_t * capture_ctx;

  FILE * file;
  long   file_off;       /* committed write offset */
  long   file_off_spec;  /* speculative write offset */

  ulong in_cnt;
  fd_solcap_link_in_t in[ MAX_IN_LINKS ];
};

typedef struct fd_solcap_tile_ctx fd_solcap_tile_ctx_t;

static ulong
scratch_align( void ) {
  return alignof(fd_solcap_tile_ctx_t);
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  return sizeof(fd_solcap_tile_ctx_t);
}

/* Sandbox */

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  fd_solcap_tile_ctx_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  int solcap_fd = fileno( ctx->file );
  populate_sock_filter_policy_fd_solcap_tile(
      out_cnt, out,
      (uint)fd_log_private_logfile_fd(),
      (uint)solcap_fd );
  return sock_filter_policy_fd_solcap_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_solcap_tile_ctx_t const * ctx = (fd_solcap_tile_ctx_t const *)scratch;
  FD_TEST( out_fds_cnt>=3UL );
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd();
  out_fds[ out_cnt++ ] = fileno( ctx->file );
  return out_cnt;
}

/* Startup routine */

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  fd_solcap_tile_ctx_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( ctx, 0, sizeof(fd_solcap_tile_ctx_t) );

  int solcap_fd = open( tile->solcap.out_path, O_CREAT|O_WRONLY|O_EXCL, S_IRUSR|S_IWUSR );
  if( FD_UNLIKELY( solcap_fd<0 ) ) {
    FD_LOG_ERR(( "failed to create solcap file: open(%s) failed (%i-%s)", tile->solcap.out_path, errno, fd_io_strerror( errno ) ));
  }

  ctx->file = fdopen( solcap_fd, "wb" );
  if( FD_UNLIKELY( !ctx->file ) ) {
    FD_LOG_ERR(( "failed to create solcap file: fdopen(fd=%d) failed (%i-%s)", solcap_fd, errno, fd_io_strerror( errno ) ));
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  fd_solcap_tile_ctx_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  /* Hook up to input links */

  FD_TEST( tile->in_cnt <= 32UL );
  ctx->in_cnt = tile->in_cnt;
  for( ulong i=0UL; i < tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    void * base = fd_wksp_containing( link->dcache );
    ctx->in[ i ].base   = base;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( base, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( base, link->dcache, link->mtu );
    ctx->in[ i ].mtu    = link->mtu;
  }

  /* Write header */

  fd_pcapng_shb_opts_t shb_opts;
  fd_pcapng_shb_defaults( &shb_opts );
  if( FD_UNLIKELY( !fd_pcapng_fwrite_shb( &shb_opts, ctx->file ) ) ) {
    FD_LOG_ERR(( "failed to create solcap file: write to %s failed (%i-%s)", tile->solcap.out_path, errno, fd_io_strerror( errno ) ));
  }
  fd_pcapng_idb_opts_t idb_opts = {
    .name = "eth0"
  };
  if( FD_UNLIKELY( !fd_pcapng_fwrite_idb( FD_PCAPNG_LINKTYPE_NULL, &idb_opts, ctx->file ) ) ) {
    FD_LOG_ERR(( "failed to create solcap file: write to %s failed (%i-%s)", tile->solcap.out_path, errno, fd_io_strerror( errno ) ));
  }

  ctx->file_off = ftell( ctx->file );
  if( FD_UNLIKELY( ctx->file_off<0L ) ) FD_LOG_ERR(( "ftell failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  FD_LOG_INFO(( "writing solcap events to %s", tile->solcap.out_path ));
}

static void
metrics_write( fd_solcap_tile_ctx_t * ctx ) {
  FD_MCNT_SET( SOLCAP, BYTES_WRITTEN, (ulong)ctx->file_off );
}

/* Frag handling */

static inline void
during_frag( fd_solcap_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  meta_seq,
             ulong                  meta_sig,
             ulong                  meta_chunk,
             ulong                  meta_sz,
             ulong                  meta_ctl ) {
  (void)meta_sz; (void)meta_ctl;

  /* bounds check frag */

  ulong chunk = meta_chunk;
  ulong sz    = (meta_sig>>8) & ((1UL<<24)-1UL);
  fd_solcap_link_in_t const * link = &ctx->in[ in_idx ];
  if( FD_UNLIKELY( chunk < link->chunk0 ||
                   chunk > link->wmark  ||
                   sz    > link->mtu ) ) {
    FD_LOG_CRIT(( "frag (in_idx=%lu seq=%lu) is corrupt: chunk=%#lx sz=%lu mtu=%lu chunk0=%#lx wmark=%#lx",
                  in_idx, meta_seq, chunk, sz, link->mtu, link->chunk0, link->wmark ));
  }

  uchar const * event = fd_chunk_to_laddr( link->base, chunk );

  /* write frag */

  if( FD_UNLIKELY( ctx->file_off_spec != ctx->file_off ) ) {
    /* a previous speculative write failed, seek back */
    if( FD_UNLIKELY( 0!=fseek( ctx->file, ctx->file_off, SEEK_SET ) ) ) {
      FD_LOG_ERR(( "fseek failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    ctx->file_off_spec = ctx->file_off;
  }

  int err = fd_pkt_w_pcapng_write( ctx->file, event, sz, fd_log_wallclock() );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "failed to write solcap event (%i-%s)", err, fd_io_strerror( err ) ));
  }
  ctx->file_off_spec = ftell( ctx->file );
  if( FD_UNLIKELY( ctx->file_off_spec<0L ) ) FD_LOG_ERR(( "ftell failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static inline void
after_frag( fd_solcap_tile_ctx_t * ctx,
            ulong                  in_idx,
            ulong                  seq,
            ulong                  sig,
            ulong                  sz,
            ulong                  tsorig,
            ulong                  tspub,
            fd_stem_context_t *    stem ) {
  (void)in_idx; (void)seq; (void)sig; (void)sz; (void)tsorig; (void)tspub; (void)stem;
  ctx->file_off = ctx->file_off_spec;
}

#define STEM_BURST                  1UL
#define STEM_CALLBACK_CONTEXT_TYPE  fd_solcap_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_solcap_tile_ctx_t)
#define STEM_CALLBACK_METRICS_WRITE metrics_write
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_solcap = {
  .name                     = "solcap",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run
};

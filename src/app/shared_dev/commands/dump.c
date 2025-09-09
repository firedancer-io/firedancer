#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../util/net/fd_pcap.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

struct dump_ctx {
  fd_io_buffered_ostream_t ostream;
  ulong                    pending_sz;

  struct link {
    fd_topo_link_t const * topo;
    void const *           dcache_base;
    uint                   link_hash;
  }                        links[ FD_TOPO_MAX_LINKS ];
  ulong                    link_cnt;

  ulong *                  metrics_base;
  long                     next_stat_log;
  ulong                    last_frags;
  ulong                    last_bytes;
  ulong                    last_overrun_frags;
};
typedef struct dump_ctx dump_ctx_t;

void
dump_cmd_args( int      * argc,
               char * * * argv,
               args_t   * args ) {
  char const * out_file = fd_env_strip_cmdline_cstr( argc, argv, "--out-file", NULL, "dump.pcap" );
  char const * link     = fd_env_strip_cmdline_cstr( argc, argv, "--link",     NULL, ""          );
  args->dump.once       = fd_env_strip_cmdline_int(  argc, argv, "--once",     NULL, 1           );
  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( args->dump.pcap_path ), out_file, sizeof(args->dump.pcap_path)-1UL ) );
  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( args->dump.link_name ), link,     sizeof(args->dump.link_name)-1UL ) );
}

static void
dump_link_once( dump_ctx_t *        ctx,
                struct link const * link ) {
  fd_frag_meta_t const * mcache = link->topo->mcache;
  ulong seq0 = fd_mcache_seq0( mcache );
  ulong seq_init = fd_mcache_seq_query( fd_mcache_seq_laddr_const( mcache ) );
  ulong depth = fd_mcache_depth( mcache );

  ulong frags = 0UL;
  ulong bytes = 0UL;

  /* For links that are published reliably, we can trust the value of
     seq_init.  For unreliable links, we'll just publish one whole
     depth. */

  /* We know at this point [seq0, seq_init) were published, but they may
     be long overwritten, and there may be more published than that. */

  ulong min_seq_seen = seq_init; /* What we actually dumped is [min_seq_seen, seq_init) */
  for( ulong seq=fd_seq_dec( seq_init, 1UL ); fd_seq_ge( seq, seq0 ); seq=fd_seq_dec( seq, 1UL ) ) {
    /* It's not necessary for this to be atomic, since this is a
       post-mortem tool. */
    fd_frag_meta_t const * line = mcache+fd_mcache_line_idx( seq, depth );
    ulong read_seq = fd_frag_meta_seq_query( line );
    if( FD_UNLIKELY( read_seq!=seq ) ) break;

    min_seq_seen = seq;

    if( FD_LIKELY( link->dcache_base ) ) {
      ulong chunk = line->chunk;
      ulong sz    = line->sz;
      void const * buffer = fd_chunk_to_laddr_const( link->dcache_base, chunk );
      fd_pcap_ostream_pkt( &ctx->ostream, (long)seq, line, sizeof(fd_frag_meta_t), buffer, sz, link->link_hash );
      bytes += sz;
    } else {
      fd_pcap_ostream_pkt( &ctx->ostream, (long)seq, line, sizeof(fd_frag_meta_t), NULL, 0, link->link_hash );
    }
    frags++;
  }

  /* Now check everything after seq_init.  This could potentially loop
     forever if the producer is still going, so we cap it at one depth. */
  for( ulong off=0UL; off<depth; off++ ) {
    ulong seq = fd_seq_inc( seq_init, off );

    fd_frag_meta_t const * line = mcache+fd_mcache_line_idx( seq, depth );
    ulong read_seq = fd_frag_meta_seq_query( line );

    /* Skip anything we processed in the first loop, also skipping any
       with the err control bit set.  When an mcache is initialized, all
       the frags have err set to true, so this will skip those in
       particular as well. */
    if( FD_UNLIKELY( (fd_seq_le( min_seq_seen, read_seq ) & fd_seq_lt( read_seq, seq_init )) | (line->ctl & (1<<2)) ) ) continue;

    if( FD_LIKELY( link->dcache_base ) ) {
      ulong chunk = line->chunk;
      ulong sz    = line->sz;
      void const * buffer = fd_chunk_to_laddr_const( link->dcache_base, chunk );
      fd_pcap_ostream_pkt( &ctx->ostream, (long)seq, line, sizeof(fd_frag_meta_t), buffer, sz, link->link_hash );
      bytes += sz;
    } else {
      fd_pcap_ostream_pkt( &ctx->ostream, (long)seq, line, sizeof(fd_frag_meta_t), NULL, 0, link->link_hash );
    }
    frags++;
  }
  FD_LOG_NOTICE(( "dumped %lu frags, %lu bytes in total from %s:%lu. Link hash: 0x%x",
                  frags, bytes, link->topo->name, link->topo->kind_id, link->link_hash ));
}

static int running = 1;

static void
exit_signal( int sig FD_PARAM_UNUSED ) {
  running = 0;
}

static int
should_shutdown( dump_ctx_t * ctx FD_PARAM_UNUSED ) {
  return !running;
}

static void
during_frag( dump_ctx_t * ctx,
             ulong        in_idx,
             ulong        seq,
             ulong        sig FD_PARAM_UNUSED ,
             ulong        chunk,
             ulong        sz,
             ulong        ctl FD_PARAM_UNUSED ) {
  /* We have a new candidate fragment to copy into the dump file.
     Because we attach read-only and do not backpressure any producers,
     this fragment could be overrun at any point during this function.
     So we copy the relevant data into local memory (in the buffered
     ostream peek space) and only commit it to the file later in
     after_frag.  after_frag is only called if the fragment was not
     overrun while we were processing it. */

  ctx->pending_sz = 0UL;

  long pcap_sz = fd_pcap_pkt_sz( sizeof(fd_frag_meta_t), sz );
  if( FD_UNLIKELY( pcap_sz < 0L ) ) return;

  if( (ulong)pcap_sz > fd_io_buffered_ostream_peek_sz( &ctx->ostream ) ) {
    fd_io_buffered_ostream_flush( &ctx->ostream );
    if( FD_UNLIKELY( (ulong)pcap_sz > fd_io_buffered_ostream_peek_sz( &ctx->ostream ) ) ) {
      FD_LOG_ERR(( "packet size %ld too large for pcap, increase write buffer size (%lu)",
                   pcap_sz, fd_io_buffered_ostream_peek_sz( &ctx->ostream ) ));
    }
  }

  FD_TEST( (sz==0UL) || (ctx->links[ in_idx ].dcache_base!=NULL) );

  fd_topo_link_t const * link      = ctx->links[ in_idx ].topo;
  fd_frag_meta_t const * mline     = link->mcache + fd_mcache_line_idx( seq, fd_mcache_depth( link->mcache ) );
  void const *           frag_data = fd_chunk_to_laddr_const( ctx->links[ in_idx ].dcache_base, chunk );

  fd_pcap_pkt( fd_io_buffered_ostream_peek( &ctx->ostream ),
               (long)seq,
               mline,
               sizeof(fd_frag_meta_t),
               frag_data,
               sz,
               ctx->links[ in_idx ].link_hash );
  ctx->pending_sz = (ulong)pcap_sz;
}

static void
after_frag( dump_ctx_t *        ctx,
            ulong               in_idx FD_PARAM_UNUSED,
            ulong               seq FD_PARAM_UNUSED,
            ulong               sig FD_PARAM_UNUSED,
            ulong               sz,
            ulong               tsorig FD_PARAM_UNUSED,
            ulong               tspub FD_PARAM_UNUSED,
            fd_stem_context_t * stem FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( !ctx->pending_sz ) ) return;
  long pcap_sz = fd_pcap_pkt_sz( sizeof(fd_frag_meta_t), sz );
  FD_TEST( (ulong)pcap_sz == ctx->pending_sz );
  fd_io_buffered_ostream_seek( &ctx->ostream, ctx->pending_sz );
  ctx->pending_sz = 0UL;
}

static void
log_metrics( dump_ctx_t * ctx ) {
  ulong frags = 0UL;
  ulong bytes = 0UL;
  ulong overrun_frags = 0UL;
  for( ulong i=0UL; i<ctx->link_cnt; i++) {
    volatile ulong const * link_metrics = fd_metrics_link_in( ctx->metrics_base, i );
    frags         += link_metrics[ FD_METRICS_COUNTER_LINK_CONSUMED_COUNT_OFF ];
    bytes         += link_metrics[ FD_METRICS_COUNTER_LINK_CONSUMED_SIZE_BYTES_OFF ];
    overrun_frags += link_metrics[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_FRAG_COUNT_OFF ];
    overrun_frags += link_metrics[ FD_METRICS_COUNTER_LINK_OVERRUN_READING_FRAG_COUNT_OFF ];
  }

  long frags_diff = fd_seq_diff( frags, ctx->last_frags );
  long bytes_diff = fd_seq_diff( bytes, ctx->last_bytes );
  FD_LOG_NOTICE(( "dumped %ld frags, %ld bytes", frags_diff, bytes_diff ));

  if( FD_UNLIKELY( overrun_frags != ctx->last_overrun_frags ) ) {
    /* Note: We expect overruns at startup because we have no way to
       know the current seq to start polling from, so we start at 0
       which has often been overrun. */
    if( FD_LIKELY( ctx->last_overrun_frags != 0 ) ) {
      long overrun_diff = fd_seq_diff( overrun_frags, ctx->last_overrun_frags );
      FD_LOG_WARNING(( "overrun detected, %ld frags dropped", overrun_diff ));
    }
    ctx->last_overrun_frags = overrun_frags;
  }
}

static void
during_housekeeping( dump_ctx_t * ctx ) {
  long now = fd_log_wallclock();
  if( FD_UNLIKELY( now > ctx->next_stat_log ) ) {
    ctx->next_stat_log = now + (long)1e9;
    log_metrics( ctx );
  }
}

#define STEM_BURST                        (0UL)
#define STEM_CALLBACK_CONTEXT_TYPE        dump_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN       alignof(dump_ctx_t)
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag
#define STEM_CALLBACK_SHOULD_SHUTDOWN     should_shutdown
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#include "../../../disco/stem/fd_stem.c"

void
dump_cmd_fn( args_t      * args,
             fd_config_t * config ) {
  char * tokens[ 16 ];
  ulong token_count = fd_cstr_tokenize( tokens, 16UL, args->dump.link_name, ',' );

  dump_ctx_t ctx = { 0 };

  uchar write_buf[ 131072 ];
  int fd = open( args->dump.pcap_path, O_WRONLY | O_CREAT | O_TRUNC,
                 S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH );
  if( FD_UNLIKELY( fd < 0 ) )
    FD_LOG_ERR(( "open() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( &ctx.ostream != fd_io_buffered_ostream_init( &ctx.ostream, fd, write_buf, sizeof(write_buf) ) ) )
    FD_LOG_ERR(( "fd_io_buffered_ostream_init() failed" ));

  FD_TEST( 0==fd_pcap_ostream_hdr( &ctx.ostream, FD_PCAP_LINK_LAYER_USER0 ) );

  fd_topo_t * topo = &config->topo;
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_ONLY );
  fd_topo_fill( topo );

  for( ulong i=0UL; i<topo->link_cnt; i++) {
    fd_topo_link_t * link = &topo->links[ i ];
    int found = (token_count==0UL);
    for( ulong j=0UL; (!found)&(j<token_count); j++ ) found |= !strcmp( tokens[ j ], topo->links[ i ].name );
    if( found ) {
      if( FD_UNLIKELY( NULL==link->mcache ) )
        FD_LOG_ERR(( "link %s:%lu mcache is null", link->name, link->kind_id ));
      ctx.links[ ctx.link_cnt ].topo        = link;
      ctx.links[ ctx.link_cnt ].dcache_base = link->mtu ? fd_topo_obj_wksp_base( topo, link->dcache_obj_id ) : NULL;
      ctx.links[ ctx.link_cnt ].link_hash   = (uint)((fd_hash( 17UL, link->name, strlen( link->name ) ) << 8) | link->kind_id);
      ctx.link_cnt++;
    }
  }

  if( args->dump.once ) {
    for( ulong i=0UL; i<ctx.link_cnt; i++ ) {
      dump_link_once( &ctx, &ctx.links[ i ] );
    }
  } else {
    struct sigaction sa = {
      .sa_handler = exit_signal,
      .sa_flags   = 0,
    };
    if( FD_UNLIKELY( sigaction( SIGTERM, &sa, NULL ) ) )
      FD_LOG_ERR(( "sigaction(SIGTERM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( sigaction( SIGINT, &sa, NULL ) ) )
      FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    fd_frag_meta_t const * mcaches[ FD_TOPO_MAX_LINKS ];
    for( ulong i=0UL; i<ctx.link_cnt; i++ ) {
      mcaches[ i ] = ctx.links[ i ].topo->mcache;
    }

    uchar fseq_mem[ FD_TOPO_MAX_LINKS ][ FD_FSEQ_FOOTPRINT ] __attribute__((aligned((FD_FSEQ_ALIGN))));
    ulong * fseqs[ FD_TOPO_MAX_LINKS ];
    for( ulong i=0UL; i<ctx.link_cnt; i++ ) {
      fseqs[ i ] = fd_fseq_join( fd_fseq_new( fseq_mem[ i ], 0UL ) );
    }

    fd_rng_t _rng[1];
    fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)fd_tickcount(), 0UL ) );

    uchar * scratch = fd_alloca( FD_STEM_SCRATCH_ALIGN, stem_scratch_footprint( ctx.link_cnt, 0UL, 0UL ) );

    ctx.metrics_base = fd_metrics_join( fd_metrics_new( fd_alloca( FD_METRICS_ALIGN, FD_METRICS_FOOTPRINT( ctx.link_cnt, 0UL ) ), ctx.link_cnt, 0UL ) );
    fd_metrics_register( ctx.metrics_base );

    ctx.next_stat_log = fd_log_wallclock() + (long)1e9;
    stem_run1( ctx.link_cnt, /* in_cnt */
               mcaches,      /* in_mcache */
               fseqs,        /* in_fseq */
               0UL,          /* out_cnt */
               NULL,         /* out_mcache */
               0UL,          /* cons_cnt */
               NULL,         /* _cons_out */
               NULL,         /* _cons_fseq */
               0UL,          /* burst */
               0UL,          /* lazy */
               rng,          /* rng */
               scratch,      /* scratch */
               &ctx );       /* ctx */

    for( ulong i=0UL; i<ctx.link_cnt; i++ ) {
      struct link const * link = &ctx.links[ i ];
      volatile ulong const * link_metrics = fd_metrics_link_in( ctx.metrics_base, i );
      ulong frags = link_metrics[ FD_METRICS_COUNTER_LINK_CONSUMED_COUNT_OFF ];
      ulong bytes = link_metrics[ FD_METRICS_COUNTER_LINK_CONSUMED_SIZE_BYTES_OFF ];
      FD_LOG_NOTICE(( "dumped %lu frags, %lu bytes in total from %s:%lu. Link hash: 0x%x",
                      frags, bytes, link->topo->name, link->topo->kind_id, link->link_hash ));
    }

    fd_metrics_delete( fd_metrics_leave( ctx.metrics_base ) );
    ctx.metrics_base = NULL;

    fd_rng_delete( fd_rng_leave( rng ) );

    for( ulong i=0UL; i<ctx.link_cnt; i++ ) {
      fd_fseq_delete( fd_fseq_leave( fseqs[ i ] ) );
    }
  }

  fd_topo_leave_workspaces( topo );

  fd_io_buffered_ostream_flush( &ctx.ostream );
  fd_io_buffered_ostream_fini( &ctx.ostream );
  close( fd );
}

action_t fd_action_dump = {
  .name          = "dump",
  .args          = dump_cmd_args,
  .fn            = dump_cmd_fn,
  .perm          = NULL,
  .description   = "Dump tango links to a packet capture file",
  .is_diagnostic = 1
};

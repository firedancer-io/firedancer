/* fd_shrgen_tile is a synthetic turbine source.  It shreds a fixed
   entry batch into FEC sets with fd_shredder, signs each set's Merkle
   root with a leader keypair, and sends the shreds as UDP datagrams to
   a shred tile's turbine port.  The receiving shred tile treats them
   like any other turbine traffic, so the keypair must be the leader
   for the slots generated (in a single node dev cluster that is the
   validator's own identity key), and the shred version must match.

   The tile has no links.  Each after_credit call emits at most one
   FEC set (64 shreds in one sendmmsg call), paced so that
   fec_sets_per_slot sets are spread evenly over slot_duration_ns.  A
   zero slot duration removes the pacing and the tile sends as fast as
   it can shred.

   Target slot: with a fixed start_slot the tile free-runs upward from
   it.  With start_slot==0 it auto-tracks the target validator's root:
   it scrapes replay_root_slot from the validator's Prometheus /metrics
   endpoint once at startup and periodically, and pins the target to
   root_slot+slot_ahead.  NOTE: when the node is catching up its root
   can lag the live tip by many slots, so root+slot_ahead can land in
   the already-in-progress (root, tip] window; injecting shreds there
   has been observed to SIGSEGV the shred tile.  This is intentional per
   request (targeting root+100). */

#define _GNU_SOURCE /* sendmmsg */

#include "../../../../disco/topo/fd_topo.h"
#include "../../../../disco/shred/fd_shredder.h"
#include "../../../../disco/keyguard/fd_keyload.h"
#include "../../../../ballet/ed25519/fd_ed25519.h"
#include "../../../../ballet/sha512/fd_sha512.h"
#include "../../../../ballet/shred/fd_shred.h"
#include "../../../../util/net/fd_ip4.h"

#include <errno.h>
#include <stdlib.h>     /* exit, strtoul */
#include <string.h>     /* memmem */
#include <unistd.h>     /* read, write, close */
#include <sys/socket.h>
#include <sys/time.h>   /* struct timeval */
#include <netinet/in.h>

/* One entry batch per FEC set.  The batch is a sequence of empty tick
   entries (ulong entry_cnt, then per entry: ulong hashcnt_delta,
   uchar hash[32], ulong txn_cnt=0) so that the payload parses as
   entries.  The sizes are the largest whole number of entries that
   fits in exactly one chained (or resigned, for the last set of a
   slot) FEC set; the shredder zero pads the remainder. */

#define SHRGEN_ENTRY_SZ         (48UL)
#define SHRGEN_CHAINED_ENTRIES  ((FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ -8UL)/SHRGEN_ENTRY_SZ)
#define SHRGEN_RESIGNED_ENTRIES ((FD_SHREDDER_RESIGNED_FEC_SET_PAYLOAD_SZ-8UL)/SHRGEN_ENTRY_SZ)
#define SHRGEN_CHAINED_BATCH_SZ (8UL+SHRGEN_CHAINED_ENTRIES *SHRGEN_ENTRY_SZ)
#define SHRGEN_RESIGNED_BATCH_SZ (8UL+SHRGEN_RESIGNED_ENTRIES*SHRGEN_ENTRY_SZ)

FD_STATIC_ASSERT( SHRGEN_CHAINED_BATCH_SZ <=FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ,  batch_sz );
FD_STATIC_ASSERT( SHRGEN_RESIGNED_BATCH_SZ<=FD_SHREDDER_RESIGNED_FEC_SET_PAYLOAD_SZ, batch_sz );

#define SHRGEN_PKT_CNT (2UL*FD_FEC_SHRED_CNT)

#define SHRGEN_REPORT_NS  (1000L*1000L*1000L)
#define SHRGEN_RESYNC_NS  (1000L*1000L*1000L) /* re-scrape the live tip every 1s */
#define SHRGEN_HTTP_BUF_SZ (1UL<<20)          /* /metrics dump fits comfortably */

struct __attribute__((aligned(128UL))) fd_shrgen_tile_ctx {
  fd_shredder_t * shredder;
  fd_sha512_t     sha512[ 1 ];
  uchar const *   private_key; /* 32 bytes, followed by the 32 byte public key */
  uchar const *   public_key;

  int                sock;
  struct sockaddr_in dest;

  ulong slot;
  ulong end_slot;          /* exclusive, ULONG_MAX runs forever */
  ulong slot_fec_idx;      /* FEC sets sent so far in slot */
  ulong fec_sets_per_slot;
  long  slot_duration_ns;  /* 0 disables pacing */
  long  slot_start_ns;

  /* Auto-track the target validator's live tip via Prometheus. */
  int                auto_track;
  struct sockaddr_in metrics_addr;
  ulong              slot_ahead;
  long               resync_ns;      /* next wallclock time to re-scrape */
  int                resync_warned;

  uchar        chained_merkle_root[ 32 ];
  fd_fec_set_t fec_set[ 1 ];
  uchar        entry_batch[ SHRGEN_CHAINED_BATCH_SZ ];

  struct mmsghdr msgs[ SHRGEN_PKT_CNT ];
  struct iovec   iovs[ SHRGEN_PKT_CNT ];

  ulong fec_cnt;
  ulong shred_cnt;
  ulong byte_cnt;
  ulong send_err_cnt;
  int   send_err_logged;

  long  report_ns;
  ulong report_fec_cnt;
  ulong report_shred_cnt;
  ulong report_byte_cnt;

  char http_buf[ SHRGEN_HTTP_BUF_SZ ];
};

typedef struct fd_shrgen_tile_ctx fd_shrgen_tile_ctx_t;

/* fetch_root_slot does a blocking HTTP GET of the target validator's
   Prometheus /metrics and returns the value of the replay_root_slot
   gauge, or 0 on any failure.  Timeouts are short so a slow or absent
   target only briefly stalls generation. */

static ulong
fetch_root_slot( fd_shrgen_tile_ctx_t * ctx ) {
  int fd = socket( AF_INET, SOCK_STREAM, 0 );
  if( FD_UNLIKELY( -1==fd ) ) return 0UL;

  struct timeval tv = { .tv_sec = 0, .tv_usec = 250000 }; /* 250ms */
  (void)setsockopt( fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv) );
  (void)setsockopt( fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv) );

  ulong root = 0UL;
  do {
    if( FD_UNLIKELY( -1==connect( fd, fd_type_pun_const( &ctx->metrics_addr ), sizeof(ctx->metrics_addr) ) ) ) break;

    char const * req     = "GET /metrics HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    ulong        req_len = strlen( req );
    ulong        off     = 0UL;
    int          ok      = 1;
    while( off<req_len ) {
      long n = write( fd, req+off, req_len-off );
      if( n<0 ) { if( errno==EINTR ) continue; ok = 0; break; }
      off += (ulong)n;
    }
    if( FD_UNLIKELY( !ok ) ) break;

    ulong len = 0UL;
    while( len+1UL<SHRGEN_HTTP_BUF_SZ ) {
      long n = read( fd, ctx->http_buf+len, SHRGEN_HTTP_BUF_SZ-1UL-len );
      if( n<0 ) { if( errno==EINTR ) continue; break; }
      if( n==0 ) break; /* EOF */
      len += (ulong)n;
    }

    /* Match the sample line "\nreplay_root_slot{...} <value>", not the
       "# HELP/# TYPE replay_root_slot" comment lines (no leading
       newline+name and no '{'). */
    char const * key = "\nreplay_root_slot{";
    char *       p   = memmem( ctx->http_buf, len, key, strlen( key ) );
    if( FD_UNLIKELY( !p ) ) break;
    char * brace = memchr( p, '}', (ulong)( ctx->http_buf+len-p ) );
    if( FD_UNLIKELY( !brace ) ) break;
    p = brace+1UL;
    while( p<ctx->http_buf+len && *p==' ' ) p++;
    root = strtoul( p, NULL, 10 );
  } while( 0 );

  close( fd );
  return root;
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_shrgen_tile_ctx_t), fd_shredder_align() );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_shrgen_tile_ctx_t), sizeof(fd_shrgen_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_shredder_align(),           fd_shredder_footprint()      );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_shrgen_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_shrgen_tile_ctx_t), sizeof(fd_shrgen_tile_ctx_t) );
  fd_memset( ctx, 0, sizeof(fd_shrgen_tile_ctx_t) );

  if( FD_UNLIKELY( !strcmp( tile->shrgen.key_path, "" ) ) ) FD_LOG_ERR(( "key_path not set" ));
  ctx->private_key = fd_keyload_load( tile->shrgen.key_path, /* public_key_only */ 0 );
  ctx->public_key  = ctx->private_key+32UL;

  ctx->sock = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( -1==ctx->sock ) ) FD_LOG_ERR(( "socket() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  int sndbuf = 8<<20;
  if( FD_UNLIKELY( -1==setsockopt( ctx->sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf) ) ) )
    FD_LOG_ERR(( "setsockopt(SO_SNDBUF) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  ctx->dest = (struct sockaddr_in){
    .sin_family      = AF_INET,
    .sin_port        = fd_ushort_bswap( tile->shrgen.dest_port ),
    .sin_addr.s_addr = tile->shrgen.dest_ip_addr,
  };
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_shrgen_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_shrgen_tile_ctx_t), sizeof(fd_shrgen_tile_ctx_t) );
  void * _shredder           = FD_SCRATCH_ALLOC_APPEND( l, fd_shredder_align(),           fd_shredder_footprint()      );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top>(ulong)scratch+scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top-(ulong)scratch-scratch_footprint( tile ), scratch_top, (ulong)scratch+scratch_footprint( tile ) ));

  if( FD_UNLIKELY( !fd_sha512_join( fd_sha512_new( ctx->sha512 ) ) ) ) FD_LOG_ERR(( "fd_sha512_join failed" ));

  ctx->shredder = fd_shredder_join( fd_shredder_new( _shredder ) );
  if( FD_UNLIKELY( !ctx->shredder ) ) FD_LOG_ERR(( "fd_shredder_join failed" ));
  if( FD_UNLIKELY( !tile->shrgen.shred_version ) ) FD_LOG_ERR(( "shred_version not set" ));
  fd_shredder_set_shred_version( ctx->shredder, tile->shrgen.shred_version );

  if( FD_UNLIKELY( !tile->shrgen.fec_sets_per_slot ) ) FD_LOG_ERR(( "fec_sets_per_slot must be non-zero" ));
  if( FD_UNLIKELY( tile->shrgen.fec_sets_per_slot>FD_FEC_BLK_MAX ) )
    FD_LOG_ERR(( "fec_sets_per_slot %lu exceeds the %lu FEC sets a slot can hold", tile->shrgen.fec_sets_per_slot, (ulong)FD_FEC_BLK_MAX ));

  ctx->slot_fec_idx      = 0UL;
  ctx->fec_sets_per_slot = tile->shrgen.fec_sets_per_slot;
  ctx->slot_duration_ns  = (long)tile->shrgen.slot_duration_ns;
  ctx->slot_start_ns     = fd_log_wallclock();
  ctx->report_ns         = ctx->slot_start_ns;

  ctx->auto_track   = !tile->shrgen.start_slot;
  ctx->slot_ahead   = tile->shrgen.slot_ahead;
  ctx->metrics_addr = (struct sockaddr_in){
    .sin_family      = AF_INET,
    .sin_port        = fd_ushort_bswap( tile->shrgen.metrics_port ),
    .sin_addr.s_addr = tile->shrgen.metrics_ip,
  };

  if( FD_UNLIKELY( ctx->auto_track ) ) {
    /* Seed from the target's live tip.  The endpoint may not answer on
       the first try right after the target boots, so retry briefly. */
    ulong root = 0UL;
    for( int attempt=0; attempt<50 && !root; attempt++ ) root = fetch_root_slot( ctx );
    if( FD_UNLIKELY( !root ) )
      FD_LOG_ERR(( "auto-track: could not read replay_root_slot from " FD_IP4_ADDR_FMT ":%hu.  Is the target validator up with a metrics tile? "
                   "Pass --slot to target a fixed slot instead.",
                   FD_IP4_ADDR_FMT_ARGS( tile->shrgen.metrics_ip ), tile->shrgen.metrics_port ));
    ctx->slot      = root + ctx->slot_ahead;
    ctx->end_slot  = ULONG_MAX; /* auto-track runs until Ctrl+C */
    ctx->resync_ns = fd_log_wallclock() + SHRGEN_RESYNC_NS;
    FD_LOG_NOTICE(( "auto-track: root_slot=%lu -> target slot=%lu (root+%lu)", root, ctx->slot, ctx->slot_ahead ));
  } else {
    ctx->slot     = tile->shrgen.start_slot;
    ctx->end_slot = fd_ulong_if( !!tile->shrgen.slot_cnt, tile->shrgen.start_slot+tile->shrgen.slot_cnt, ULONG_MAX );
  }

  /* Empty tick entries, see the comment at the top of the file.  The
     entry count is the larger (chained) one; a resigned batch is a
     prefix of the same bytes and claims fewer entries. */
  fd_rng_t _rng[ 1 ]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)tile->kind_id, 0UL ) );
  uchar * batch = ctx->entry_batch;
  FD_STORE( ulong, batch, SHRGEN_CHAINED_ENTRIES );
  for( ulong i=0UL; i<SHRGEN_CHAINED_ENTRIES; i++ ) {
    uchar * entry = batch+8UL+i*SHRGEN_ENTRY_SZ;
    FD_STORE( ulong, entry, 12500UL ); /* hashcnt_delta */
    for( ulong j=0UL; j<32UL; j++ ) entry[ 8UL+j ] = fd_rng_uchar( rng );
    FD_STORE( ulong, entry+40UL, 0UL ); /* txn_cnt */
  }
  fd_rng_delete( fd_rng_leave( rng ) );

  for( ulong j=0UL; j<32UL; j++ ) ctx->chained_merkle_root[ j ] = (uchar)j;

  /* The shred buffers never move, so the scatter/gather arrays are
     set up once.  Data shreds are FD_SHRED_MIN_SZ and parity shreds
     FD_SHRED_MAX_SZ, as fd_shred_sz reports for the chained types. */
  for( ulong i=0UL; i<FD_FEC_SHRED_CNT; i++ ) {
    ctx->iovs[ i                  ] = (struct iovec){ .iov_base = ctx->fec_set->data_shreds  [ i ].b, .iov_len = FD_SHRED_MIN_SZ };
    ctx->iovs[ i+FD_FEC_SHRED_CNT ] = (struct iovec){ .iov_base = ctx->fec_set->parity_shreds[ i ].b, .iov_len = FD_SHRED_MAX_SZ };
  }
  for( ulong i=0UL; i<SHRGEN_PKT_CNT; i++ ) {
    ctx->msgs[ i ] = (struct mmsghdr){
      .msg_hdr = {
        .msg_name    = &ctx->dest,
        .msg_namelen = sizeof(ctx->dest),
        .msg_iov     = &ctx->iovs[ i ],
        .msg_iovlen  = 1,
      },
    };
  }

  FD_LOG_NOTICE(( "shrgen sending to " FD_IP4_ADDR_FMT ":%hu shred_version=%hu slot=%lu (%s) fec_sets_per_slot=%lu slot_duration_ns=%ld",
                  FD_IP4_ADDR_FMT_ARGS( tile->shrgen.dest_ip_addr ), tile->shrgen.dest_port, tile->shrgen.shred_version,
                  ctx->slot, ctx->auto_track ? "auto-track" : "fixed", tile->shrgen.fec_sets_per_slot, ctx->slot_duration_ns ));
}

/* make_fec_set shreds and signs the next FEC set of the current slot
   into ctx->fec_set. */

static void
make_fec_set( fd_shrgen_tile_ctx_t * ctx ) {
  int last = ctx->slot_fec_idx+1UL==ctx->fec_sets_per_slot;

  fd_entry_batch_meta_t meta[ 1 ];
  fd_memset( meta, 0, sizeof(fd_entry_batch_meta_t) );
  meta->parent_offset  = 1UL;
  meta->reference_tick = fd_ulong_min( (ctx->slot_fec_idx*64UL)/ctx->fec_sets_per_slot, 63UL );
  meta->block_complete = last;

  ulong batch_sz = fd_ulong_if( last, SHRGEN_RESIGNED_BATCH_SZ, SHRGEN_CHAINED_BATCH_SZ );
  FD_STORE( ulong, ctx->entry_batch, fd_ulong_if( last, SHRGEN_RESIGNED_ENTRIES, SHRGEN_CHAINED_ENTRIES ) );

  FD_TEST( fd_shredder_init_batch( ctx->shredder, ctx->entry_batch, batch_sz, ctx->slot, meta ) );
  FD_TEST( fd_shredder_next_fec_set( ctx->shredder, ctx->fec_set, ctx->chained_merkle_root ) );
  FD_TEST( !fd_shredder_next_fec_set( ctx->shredder, ctx->fec_set, ctx->chained_merkle_root ) ); /* batch is sized for exactly one set */
  fd_shredder_fini_batch( ctx->shredder );

  /* chained_merkle_root now holds this set's root, which is what the
     leader signs. */
  uchar sig[ 64 ];
  fd_ed25519_sign( sig, ctx->chained_merkle_root, 32UL, ctx->public_key, ctx->private_key, ctx->sha512 );
  for( ulong i=0UL; i<FD_FEC_SHRED_CNT; i++ ) fd_memcpy( ctx->fec_set->data_shreds  [ i ].s->signature, sig, 64UL );
  for( ulong i=0UL; i<FD_FEC_SHRED_CNT; i++ ) fd_memcpy( ctx->fec_set->parity_shreds[ i ].s->signature, sig, 64UL );
}

static void
send_fec_set( fd_shrgen_tile_ctx_t * ctx ) {
  ulong sent = 0UL;
  while( sent<SHRGEN_PKT_CNT ) {
    int rc = sendmmsg( ctx->sock, ctx->msgs+sent, (uint)(SHRGEN_PKT_CNT-sent), 0 );
    if( FD_UNLIKELY( rc<0 ) ) {
      if( FD_LIKELY( errno==EINTR ) ) continue;
      ctx->send_err_cnt++;
      if( FD_UNLIKELY( !ctx->send_err_logged ) ) {
        FD_LOG_WARNING(( "sendmmsg() failed (%i-%s), further failures are counted silently", errno, fd_io_strerror( errno ) ));
        ctx->send_err_logged = 1;
      }
      return;
    }
    for( ulong i=0UL; i<(ulong)rc; i++ ) ctx->byte_cnt += ctx->msgs[ sent+i ].msg_len;
    sent += (ulong)rc;
  }
  ctx->shred_cnt += SHRGEN_PKT_CNT;
  ctx->fec_cnt++;
}

static void
report( fd_shrgen_tile_ctx_t * ctx,
        long                   now ) {
  double dt = (double)(now-ctx->report_ns)/1e9;
  if( FD_UNLIKELY( dt<=0.0 ) ) return;
  FD_LOG_NOTICE(( "slot=%lu fec_sets=%lu (%.0f/s) shreds=%lu (%.0f/s) %.1f Mbps send_err=%lu",
                  ctx->slot,
                  ctx->fec_cnt,   (double)(ctx->fec_cnt  -ctx->report_fec_cnt  )/dt,
                  ctx->shred_cnt, (double)(ctx->shred_cnt-ctx->report_shred_cnt)/dt,
                  8.0*(double)(ctx->byte_cnt-ctx->report_byte_cnt)/dt/1e6,
                  ctx->send_err_cnt ));
  ctx->report_ns        = now;
  ctx->report_fec_cnt   = ctx->fec_cnt;
  ctx->report_shred_cnt = ctx->shred_cnt;
  ctx->report_byte_cnt  = ctx->byte_cnt;
}

static void
after_credit( fd_shrgen_tile_ctx_t * ctx,
              fd_stem_context_t *    stem FD_PARAM_UNUSED,
              int *                  opt_poll_in,
              int *                  charge_busy ) {
  *opt_poll_in = 0;

  long now = fd_log_wallclock();
  if( FD_LIKELY( ctx->slot_duration_ns ) ) {
    long due = ctx->slot_start_ns + (long)( ((ulong)ctx->slot_duration_ns*ctx->slot_fec_idx)/ctx->fec_sets_per_slot );
    if( FD_LIKELY( now<due ) ) return;
  }

  *charge_busy = 1;

  make_fec_set( ctx );
  send_fec_set( ctx );

  if( FD_UNLIKELY( ++ctx->slot_fec_idx==ctx->fec_sets_per_slot ) ) {
    ctx->slot_fec_idx = 0UL;
    ctx->slot++;
    /* Keep the nominal schedule, but never fall more than one slot
       behind it: a stall should lower the rate, not produce a burst
       of catch-up slots. */
    long next = ctx->slot_start_ns+ctx->slot_duration_ns;
    ctx->slot_start_ns = fd_long_if( next<now-ctx->slot_duration_ns, now, next );

    if( FD_UNLIKELY( ctx->slot>=ctx->end_slot ) ) {
      report( ctx, fd_log_wallclock() );
      FD_LOG_NOTICE(( "reached slot %lu, exiting", ctx->slot ));
      exit( 0 );
    }
  }
}

static void
during_housekeeping( fd_shrgen_tile_ctx_t * ctx ) {
  long now = fd_log_wallclock();

  /* Re-pin the target to the validator's live tip. */
  if( FD_UNLIKELY( ctx->auto_track && now>=ctx->resync_ns ) ) {
    ctx->resync_ns = now + SHRGEN_RESYNC_NS;
    ulong root = fetch_root_slot( ctx );
    if( FD_LIKELY( root ) ) {
      ctx->slot          = root + ctx->slot_ahead;
      ctx->slot_fec_idx  = 0UL;
      ctx->slot_start_ns = now;
      ctx->resync_warned = 0;
    } else if( FD_UNLIKELY( !ctx->resync_warned ) ) {
      FD_LOG_WARNING(( "auto-track: replay_root_slot scrape failed; holding target slot %lu (further failures silent)", ctx->slot ));
      ctx->resync_warned = 1;
    }
  }

  if( FD_UNLIKELY( now-ctx->report_ns>=SHRGEN_REPORT_NS ) ) report( ctx, now );
}

#define STEM_BURST (1UL)
#define STEM_LAZY  ((long)1e6) /* 1ms, the tile has no links so this only paces housekeeping */

#define STEM_CALLBACK_CONTEXT_TYPE  fd_shrgen_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_shrgen_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_shrgen = {
  .name              = "shrgen",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .privileged_init   = privileged_init,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run,
};

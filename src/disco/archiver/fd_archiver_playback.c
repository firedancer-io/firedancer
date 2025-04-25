#define _GNU_SOURCE  /* Enable GNU and POSIX extensions */

#include "../tiles.h"

#include "fd_archiver.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <sys/socket.h>
#include <linux/if_xdp.h>
#include "generated/archiver_playback_seccomp.h"
#include "../../disco/topo/fd_pod_format.h"
#include "../../flamenco/runtime/fd_rocksdb.h"
#include "../../discof/geyser/fd_replay_notif.h"
/* The archiver playback tile consumes from the archive file, adds artificial delay
to reproduce exactly the timing from the capture, and forwards these fragments to the
receiver tiles (shred/quic/gossip/repair).

There should be a single archiver playback tile, and it should replace the input links to the
receiver tiles.
*/

#define NET_SHRED_OUT_IDX  (0UL)
#define NET_REPAIR_OUT_IDX (1UL)

#define FD_ARCHIVER_PLAYBACK_ALLOC_TAG   (3UL)

#define FD_ARCHIVER_STARTUP_DELAY_SECONDS (1)
#define FD_ARCHIVE_PLAYBACK_BUFFER_SZ      (FD_SHMEM_GIGANTIC_PAGE_SZ)

struct fd_archiver_playback_stats {
  ulong net_shred_out_cnt;
  ulong net_quic_out_cnt;
  ulong net_gossip_out_cnt;
  ulong net_repair_out_cnt;

};
typedef struct fd_archiver_playback_stats fd_archiver_playback_stats_t;

typedef struct {
  fd_wksp_t * mem;
  ulong       mtu;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
} fd_archiver_playback_out_ctx_t;

struct fd_archiver_playback_tile_ctx {
  fd_io_buffered_istream_t istream;
  uchar *                  istream_buf;

  ulong                  use_rocksdb;
  fd_rocksdb_t           rocksdb;
  fd_rocksdb_root_iter_t rocksdb_root_iter;
  fd_slot_meta_t         rocksdb_slot_meta;
  ulong                  rocksdb_curr_idx;
  ulong                  rocksdb_end_idx;
  ulong                  rocksdb_end_slot;
  uchar *                rocksdb_bank_hash;
  ulong                  replay_end_slot;

  fd_archiver_playback_stats_t stats;

  double tick_per_ns;

  ulong prev_publish_time;
  ulong now;
  ulong need_notify;
  ulong notified;

  // Replay tile input
  fd_wksp_t * replay_in_mem;
  ulong       replay_in_chunk0;
  ulong       replay_in_wmark;

  fd_archiver_playback_out_ctx_t out[ 32 ];

  fd_alloc_t * alloc;
  fd_valloc_t  valloc;

  ulong playback_done;
  ulong done_time;
  ulong playback_started;
  ulong playback_cnt[FD_ARCHIVER_TILE_CNT];

  ulong * published_wmark; /* same as the one in replay tile */
};
typedef struct fd_archiver_playback_tile_ctx fd_archiver_playback_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 1UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;

  populate_sock_filter_policy_archiver_playback( out_cnt,
                                                 out,
                                                 (uint)fd_log_private_logfile_fd(),
                                                 (uint)tile->archiver.archive_fd );
  return sock_filter_policy_archiver_playback_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo        FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt FD_PARAM_UNUSED,
                      int *                  out_fds ) {
  ulong out_cnt = 0UL;

  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  if( FD_LIKELY( -1!=tile->archiver.archive_fd ) )
    out_fds[ out_cnt++ ] = tile->archiver.archive_fd; /* archive file */

  return out_cnt;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_archiver_playback_tile_ctx_t), sizeof(fd_archiver_playback_tile_ctx_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
    void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

    FD_SCRATCH_ALLOC_INIT( l, scratch );
    fd_archiver_playback_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_archiver_playback_tile_ctx_t), sizeof(fd_archiver_playback_tile_ctx_t) );
    memset( ctx, 0, sizeof(fd_archiver_playback_tile_ctx_t) );
    FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
    FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

    if( strncmp( tile->archiver.archiver_path, "rocksdb:", 8 )==0 ) {
      tile->archiver.archive_fd = -1;
    } else {
      tile->archiver.archive_fd = open( tile->archiver.archiver_path, O_RDONLY | O_DIRECT, 0666 );
      if ( FD_UNLIKELY( tile->archiver.archive_fd<0 ) ) {
        FD_LOG_ERR(( "failed to open archive file %s %d %d %s", tile->archiver.archiver_path, tile->archiver.archive_fd, errno, strerror(errno) ));
      }
    }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_archiver_playback_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_archiver_playback_tile_ctx_t), sizeof(fd_archiver_playback_tile_ctx_t) );
  void * alloc_shmem                    = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  ctx->tick_per_ns = fd_tempo_tick_per_ns( NULL );

  /* Allocator */
  ctx->alloc = fd_alloc_join( fd_alloc_new( alloc_shmem, FD_ARCHIVER_PLAYBACK_ALLOC_TAG ), fd_tile_idx() );
  if( FD_UNLIKELY( !ctx->alloc ) ) {
    FD_LOG_ERR( ( "fd_alloc_join failed" ) );
  }
  ctx->valloc = fd_alloc_virtual( ctx->alloc );

  if( strncmp( tile->archiver.archiver_path, "rocksdb:", 8 )==0 ) {
    ctx->use_rocksdb      = 1;
    ctx->rocksdb_curr_idx = 0;
    ctx->rocksdb_end_idx  = 0;
    fd_memset( &ctx->rocksdb, 0, sizeof(fd_rocksdb_t) );
    fd_memset( &ctx->rocksdb_slot_meta, 0, sizeof(fd_slot_meta_t) );
    fd_memset( &ctx->rocksdb_root_iter, 0, sizeof(fd_rocksdb_root_iter_t) );
    fd_rocksdb_init( &ctx->rocksdb, tile->archiver.archiver_path+8 );

    /* setup input link from replay tile for bank hash comparison */
    fd_topo_link_t * replay_in_link = &topo->links[ tile->in_link_id[ 1 ] ];
    ctx->replay_in_mem              = topo->workspaces[ topo->objs[ replay_in_link->dcache_obj_id ].wksp_id ].wksp;
    ctx->replay_in_chunk0           = fd_dcache_compact_chunk0( ctx->replay_in_mem, replay_in_link->dcache );
    ctx->replay_in_wmark            = fd_dcache_compact_wmark( ctx->replay_in_mem, replay_in_link->dcache, replay_in_link->mtu );

    ctx->rocksdb_bank_hash = fd_valloc_malloc( ctx->valloc, fd_frozen_hash_versioned_align(), fd_frozen_hash_versioned_footprint() );
    if( FD_UNLIKELY( NULL==ctx->rocksdb_bank_hash ) ) {
      FD_LOG_ERR(( "Failed at allocating memory for rocksdb bank hash" ));
    }

    FD_LOG_WARNING(( "Playback reads from rocksdb" ));
  } else {
    ctx->use_rocksdb = 0;
    /* Allocate output buffer */
    ctx->istream_buf = fd_valloc_malloc( ctx->valloc, 4096, FD_ARCHIVE_PLAYBACK_BUFFER_SZ );
    if( FD_UNLIKELY( !ctx->istream_buf ) ) {
      FD_LOG_ERR(( "failed to allocate input buffer" ));
    }

    /* initialize the file reader */
    fd_io_buffered_istream_init( &ctx->istream, tile->archiver.archive_fd, ctx->istream_buf, FD_ARCHIVE_PLAYBACK_BUFFER_SZ );

    /* perform the initial read */
    if( FD_UNLIKELY(( !fd_io_buffered_istream_fetch( &ctx->istream ) )) ) {
      FD_LOG_WARNING(( "failed initial read" ));
    }
  }

  /* Setup output links */
  for( ulong i=0; i<tile->out_cnt; i++ ) {
    fd_topo_link_t * link      = &topo->links[ tile->out_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->out[ i ].mtu    = link->mtu;
    ctx->out[ i ].mem    = link_wksp->wksp;
    ctx->out[ i ].chunk0 = fd_dcache_compact_chunk0( link_wksp->wksp, link->dcache );
    ctx->out[ i ].wmark  = fd_dcache_compact_wmark( link_wksp->wksp, link->dcache, link->mtu );
    ctx->out[ i ].chunk  = ctx->out[ i ].chunk0;
  }

  ctx->playback_done                            = 0;
  ctx->playback_started                         = 0;
  ctx->now                                      = 0;
  ctx->prev_publish_time                        = 0;
  /* for now, we require a notification before playback another frag */
  ctx->need_notify                              = 1;
  ctx->notified                                 = 1;
  ctx->playback_cnt[FD_ARCHIVER_TILE_ID_SHRED]  = 0;
  ctx->playback_cnt[FD_ARCHIVER_TILE_ID_REPAIR] = 0;

  ctx->replay_end_slot = tile->archiver.replay_end_slot ? tile->archiver.replay_end_slot : ULONG_MAX;

  ulong root_slot_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "root_slot" );
  FD_TEST( root_slot_obj_id!=ULONG_MAX );
  ctx->published_wmark = fd_fseq_join( fd_topo_obj_laddr( topo, root_slot_obj_id ) );
  if( FD_UNLIKELY( !ctx->published_wmark ) ) FD_LOG_ERR(( "replay tile has no root_slot fseq" ));
  FD_TEST( ULONG_MAX==fd_fseq_query( ctx->published_wmark ) );

  FD_LOG_WARNING(( "Playback tile finishes initialization" ));
}

static void
during_housekeeping( fd_archiver_playback_tile_ctx_t * ctx ) {
  ctx->now =(ulong)((double)(fd_tickcount()) / ctx->tick_per_ns);
}

static inline void
during_frag( fd_archiver_playback_tile_ctx_t * ctx,
             ulong                             in_idx,
             ulong                             seq FD_PARAM_UNUSED,
             ulong                             sig FD_PARAM_UNUSED,
             ulong                             chunk,
             ulong                             sz,
             ulong                             ctl FD_PARAM_UNUSED ) {
  if( FD_LIKELY( in_idx==0 ) ) {
    ctx->notified = 1;
    return;
  }
  if( FD_LIKELY( in_idx==1 && ctx->use_rocksdb ) ) {
    if( FD_UNLIKELY( sz!=sizeof(fd_replay_notif_msg_t) ) ) FD_LOG_ERR(( "replay_notif link seems corrupted" ));

    fd_replay_notif_msg_t * msg = fd_chunk_to_laddr( ctx->replay_in_mem, chunk );
    if( msg->type==FD_REPLAY_SLOT_TYPE ) {
      ulong slot            = msg->slot_exec.slot;
      ulong slot_be         = fd_ulong_bswap(slot);
      fd_hash_t * bank_hash = &msg->slot_exec.bank_hash;

      /* Compare bank_hash with the record in rocksdb */
      size_t vallen = 0;
      char * err = NULL;
      char * res = rocksdb_get_cf(
        ctx->rocksdb.db,
        ctx->rocksdb.ro,
        ctx->rocksdb.cf_handles[ FD_ROCKSDB_CFIDX_BANK_HASHES ],
        (char const *)&slot_be, sizeof(ulong),
        &vallen,
        &err );
      if( FD_UNLIKELY( err || vallen==0 ) ) {
        FD_LOG_ERR(( "Failed at reading bank hash for slot%lu from rocksdb", slot ));
      }
      fd_bincode_decode_ctx_t decode = {
        .data    = res,
        .dataend = res + vallen
      };
      ulong total_sz = 0UL;
      int decode_err = fd_frozen_hash_versioned_decode_footprint( &decode, &total_sz );

      fd_frozen_hash_versioned_t * versioned = fd_frozen_hash_versioned_decode( ctx->rocksdb_bank_hash, &decode );
      if( FD_UNLIKELY( decode_err!=FD_BINCODE_SUCCESS ) ||
          FD_UNLIKELY( decode.data!=decode.dataend    ) ||
          FD_UNLIKELY( versioned->discriminant!=fd_frozen_hash_versioned_enum_current ) ) {
        FD_LOG_ERR(( "Failed at decoding bank hash from rocksdb" ));
      }

      if( FD_UNLIKELY( slot>ctx->rocksdb_end_slot) ) {
        FD_LOG_ERR(( "Finish Replaying rocksdb to Slot %lu", slot ));
      }
      if( FD_UNLIKELY( slot>ctx->replay_end_slot ) ) {
        FD_LOG_ERR(( "Finish Replaying rocksdb to End Slot %lu", ctx->replay_end_slot ));
      }

      if( !memcmp( bank_hash, &versioned->inner.current.frozen_hash, sizeof(fd_hash_t) ) ) {
        FD_LOG_WARNING(( "Bank hash matches! slot=%lu, hash=%s", slot, FD_BASE58_ENC_32_ALLOCA( bank_hash->hash ) ));
      } else {
        FD_LOG_ERR(( "Bank hash mismatch! slot=%lu expected=%s, got=%s",
                     slot,
                     FD_BASE58_ENC_32_ALLOCA( bank_hash->hash ),
                     FD_BASE58_ENC_32_ALLOCA( versioned->inner.current.frozen_hash.hash ) ));
      }

      if( FD_UNLIKELY( slot>=ctx->rocksdb_end_slot) ) {
        FD_LOG_ERR(( "Finish Replaying rocksdb to Slot %lu", slot ));
      }
      if( FD_UNLIKELY( slot>=ctx->replay_end_slot ) ) {
        FD_LOG_ERR(( "Finish Replaying rocksdb to End Slot %lu", ctx->replay_end_slot ));
      }

    }
  }
}

static void
rocksdb_inspect( fd_archiver_playback_tile_ctx_t * ctx ) {
  ulong start_slot = 0;
  ulong end_slot   = 0;
  ulong shred_cnt  = 0;
  do {
    if( FD_UNLIKELY( fd_rocksdb_root_iter_next( &ctx->rocksdb_root_iter, &ctx->rocksdb_slot_meta, ctx->valloc ) ) ) break;
    if( FD_UNLIKELY( fd_rocksdb_get_meta( &ctx->rocksdb, ctx->rocksdb_slot_meta.slot, &ctx->rocksdb_slot_meta, ctx->valloc ) ) ) break;
    ulong slot = ctx->rocksdb_slot_meta.slot;
    ulong start_idx = 0;
    ulong end_idx = ctx->rocksdb_slot_meta.received;

    rocksdb_iterator_t * iter = rocksdb_create_iterator_cf(ctx->rocksdb.db, ctx->rocksdb.ro, ctx->rocksdb.cf_handles[FD_ROCKSDB_CFIDX_DATA_SHRED]);

    char k[16];
    *((ulong *) &k[0]) = fd_ulong_bswap(slot);
    *((ulong *) &k[8]) = fd_ulong_bswap(start_idx);

    rocksdb_iter_seek(iter, (const char *) k, sizeof(k));

    for (ulong i = start_idx; i < end_idx; i++) {
      ulong cur_slot, index;
      uchar valid = rocksdb_iter_valid(iter);

      if (valid) {
        size_t klen = 0;
        const char* key = rocksdb_iter_key(iter, &klen); // There is no need to free key
            if (klen != 16)  // invalid key
              FD_LOG_ERR(( "rocksdb has invalid key length" ));
            cur_slot = fd_ulong_bswap(*((ulong *) &key[0]));
            index = fd_ulong_bswap(*((ulong *) &key[8]));
      }

      if (!valid || cur_slot != slot)
        FD_LOG_ERR(("missing shreds for slot %lu, valid=%u", slot, valid));

      if (index != i)
        FD_LOG_ERR(("missing shred %lu at index %lu for slot %lu", i, index, slot));

      size_t dlen = 0;
      // Data was first copied from disk into memory to make it available to this API
      const unsigned char *data = (const unsigned char *) rocksdb_iter_value(iter, &dlen);
      if (data == NULL)
        FD_LOG_ERR(("failed to read shred %lu/%lu", slot, i));

      // This just correctly selects from inside the data pointer to the
      // actual data without a memory copy
      fd_shred_t const * shred = fd_shred_parse( data, (ulong) dlen );
      if( start_slot==0 ) start_slot = shred->slot;
      end_slot = shred->slot;
      shred_cnt++;

      rocksdb_iter_next(iter);
    }
  } while(1);

  ctx->rocksdb_end_slot=end_slot;
  FD_LOG_WARNING(( "rocksdb contains %lu shreds from slot %lu to %lu", shred_cnt, start_slot, end_slot ));
  FD_TEST( shred_cnt>0 );
}

static fd_shred_t const *
rocksdb_get_shred( fd_archiver_playback_tile_ctx_t * ctx,
                   ulong                           * out_sz ) {
  if( ctx->rocksdb_curr_idx==ctx->rocksdb_end_idx ) {
    if( FD_UNLIKELY( fd_rocksdb_root_iter_next( &ctx->rocksdb_root_iter, &ctx->rocksdb_slot_meta, ctx->valloc ) ) ) return NULL;
    if( FD_UNLIKELY( fd_rocksdb_get_meta( &ctx->rocksdb, ctx->rocksdb_slot_meta.slot, &ctx->rocksdb_slot_meta, ctx->valloc ) ) ) return NULL;
    ctx->rocksdb_curr_idx = 0;
    ctx->rocksdb_end_idx  = ctx->rocksdb_slot_meta.received;
  }
  ulong slot                = ctx->rocksdb_slot_meta.slot;
  rocksdb_iterator_t * iter = rocksdb_create_iterator_cf(ctx->rocksdb.db, ctx->rocksdb.ro, ctx->rocksdb.cf_handles[FD_ROCKSDB_CFIDX_DATA_SHRED]);

  char k[16];
  *((ulong *) &k[0]) = fd_ulong_bswap(slot);
  *((ulong *) &k[8]) = fd_ulong_bswap(ctx->rocksdb_curr_idx);
  rocksdb_iter_seek(iter, (const char *) k, sizeof(k));

  ulong cur_slot, index;
  uchar valid = rocksdb_iter_valid(iter);

  if (valid) {
    size_t klen = 0;
    const char* key = rocksdb_iter_key(iter, &klen); // There is no need to free key
    if (klen != 16)  // invalid key
      FD_LOG_ERR(( "rocksdb has invalid key length" ));
    cur_slot = fd_ulong_bswap(*((ulong *) &key[0]));
    index = fd_ulong_bswap(*((ulong *) &key[8]));
  }

  if (!valid || cur_slot != slot)
    FD_LOG_ERR(("missing shreds for slot %lu, valid=%u", slot, valid));

  if (index != ctx->rocksdb_curr_idx)
    FD_LOG_ERR(("missing shred %lu at index %lu for slot %lu", ctx->rocksdb_curr_idx, index, slot));

  size_t dlen = 0;
  // Data was first copied from disk into memory to make it available to this API
  const unsigned char *data = (const unsigned char *) rocksdb_iter_value(iter, &dlen);
  if (data == NULL)
    FD_LOG_ERR(("failed to read shred %lu/%lu", slot, ctx->rocksdb_curr_idx));

  // This just correctly selects from inside the data pointer to the
  // actual data without a memory copy
  fd_shred_t const * shred = fd_shred_parse( data, (ulong) dlen );
  ctx->rocksdb_curr_idx++;

  *out_sz = dlen;
  return shred;
}

static inline void
after_credit( fd_archiver_playback_tile_ctx_t *     ctx,
              fd_stem_context_t *                   stem,
              int *                                 opt_poll_in FD_PARAM_UNUSED,
              int *                                 charge_busy FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( ctx->playback_done ) ) {
    if( ctx->use_rocksdb ) return;
    if( ctx->now>ctx->done_time+1000000000UL*5UL ) {
      FD_LOG_ERR(( "Playback is done with %lu shred frags and %lu repair frags.",
                   ctx->playback_cnt[FD_ARCHIVER_TILE_ID_SHRED],
                   ctx->playback_cnt[FD_ARCHIVER_TILE_ID_REPAIR] ));
    }
    return;
  }

  if( FD_UNLIKELY( !ctx->playback_started ) ) {
    ulong wmark = fd_fseq_query( ctx->published_wmark );
    if( wmark==ULONG_MAX ) return;

    /* Replay tile has updated root_slot (aka. published_wmark), meaning
     * (1) snapshot has been loaded; (2) blockstore has been initialized */
    ctx->playback_started = 1;
    FD_LOG_WARNING(( "playback starts with wmark=%lu", wmark ));
    if( ctx->use_rocksdb ) {
      fd_rocksdb_root_iter_new( &ctx->rocksdb_root_iter );
      if( FD_UNLIKELY( fd_rocksdb_root_iter_seek( &ctx->rocksdb_root_iter, &ctx->rocksdb, wmark, &ctx->rocksdb_slot_meta, ctx->valloc ) ) )
        FD_LOG_ERR(( "Failed at seeking rocksdb root iter for slot=%lu", wmark ));
      rocksdb_inspect( ctx );

      fd_rocksdb_root_iter_new( &ctx->rocksdb_root_iter );
      if( FD_UNLIKELY( fd_rocksdb_root_iter_seek( &ctx->rocksdb_root_iter, &ctx->rocksdb, wmark, &ctx->rocksdb_slot_meta, ctx->valloc ) ) )
        FD_LOG_ERR(( "Failed at seeking rocksdb root iter for slot=%lu", wmark ));
    }
  }

  /* Check if reading from rocksdb instead of an archiver file from the writer tile */
  if( FD_LIKELY( ctx->use_rocksdb ) ) {
    if( FD_LIKELY( ctx->need_notify && !ctx->notified ) ) return;

    /* Ready to send the next shred */
    ulong sz                 = 0;
    ulong out_link_idx       = NET_REPAIR_OUT_IDX;
    fd_shred_t const * shred = rocksdb_get_shred( ctx, &sz );
    if( FD_UNLIKELY( shred==NULL ) ) {
      FD_LOG_WARNING(( "Playback finishes reading rocksdb" ));
      ctx->playback_done = 1;
      ctx->done_time     = ctx->now;
      return;
    }
    ctx->notified=0;
    uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out[ out_link_idx ].mem, ctx->out[ out_link_idx ].chunk );
    fd_memcpy( dst, shred, sz );
    fd_stem_publish( stem, out_link_idx, 0UL, ctx->out[ out_link_idx ].chunk, sz, 0UL, 0UL, 0UL);
    ctx->out[ out_link_idx ].chunk = fd_dcache_compact_next( ctx->out[ out_link_idx ].chunk,
                                                             sz,
                                                             ctx->out[ out_link_idx ].chunk0,
                                                             ctx->out[ out_link_idx ].wmark );
    return;
  }

  /* Peek the header without consuming anything, to see if we need to wait */
  char const * peek = fd_io_buffered_istream_peek( &ctx->istream );
  if( FD_UNLIKELY(( !peek )) ) {
    FD_LOG_ERR(( "failed to peek" ));
  }

  /* Consume the header */
  fd_archiver_frag_header_t * header = fd_type_pun( (char *)peek );
  if( FD_UNLIKELY( header->magic != FD_ARCHIVER_HEADER_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic in archive header: %lu", header->magic ));
    ctx->playback_done = 1;
    ctx->done_time     = ctx->now;
    return;
  }

  /* Determine if we should wait before publishing this
     need to delay if now > (when we should publish it)  */
  if( ctx->prev_publish_time != 0UL &&
    ( ctx->now < ( ctx->prev_publish_time + header->ns_since_prev_fragment ) )) {
    return;
  }

  /* Determine if playback receives the notification for
     the previous frag from storei tile. */
  if( FD_LIKELY( ctx->need_notify && !ctx->notified ) ) return;

  /* Consume the header from the stream */
  fd_archiver_frag_header_t header_tmp;
  if( FD_UNLIKELY( fd_io_buffered_istream_read( &ctx->istream, &header_tmp, FD_ARCHIVER_FRAG_HEADER_FOOTPRINT ) )) {
    FD_LOG_WARNING(( "failed to consume header" ));
    ctx->playback_done = 1;
    ctx->done_time     = ctx->now;
    return;
  }

  /* Determine the output link on which to send the frag */
  ulong out_link_idx = 0UL;
  switch ( header_tmp.tile_id ) {
    case FD_ARCHIVER_TILE_ID_SHRED:
    out_link_idx = NET_SHRED_OUT_IDX;
    ctx->playback_cnt[FD_ARCHIVER_TILE_ID_SHRED]++;
    break;
    case FD_ARCHIVER_TILE_ID_REPAIR:
    out_link_idx = NET_REPAIR_OUT_IDX;
    ctx->playback_cnt[FD_ARCHIVER_TILE_ID_REPAIR]++;
    break;
    default:
    FD_LOG_ERR(( "unsupported tile id" ));
  }

  /* Consume the fragment from the stream */
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out[ out_link_idx ].mem, ctx->out[ out_link_idx ].chunk );
  if( FD_UNLIKELY( fd_io_buffered_istream_read( &ctx->istream, dst, header_tmp.sz ) ) ) {
    FD_LOG_WARNING(( "failed to consume frag" ));
    ctx->playback_done = 1;
    ctx->done_time     = ctx->now;
    return;
  }

  if( FD_LIKELY( ctx->need_notify ) ) ctx->notified=0;
  if( FD_UNLIKELY(( ctx->out[ out_link_idx ].mtu<header_tmp.sz )) ) {
    FD_LOG_ERR(( "Try to playback frag with sz=%lu, exceeding mtu=%lu for link%lu",
                 header_tmp.sz, ctx->out[ out_link_idx ].mtu, out_link_idx ));
  }
  fd_stem_publish( stem, out_link_idx, header_tmp.sig, ctx->out[ out_link_idx ].chunk, header_tmp.sz, 0UL, 0UL, 0UL);
  ctx->out[ out_link_idx ].chunk = fd_dcache_compact_next( ctx->out[ out_link_idx ].chunk,
                                                           header_tmp.sz,
                                                           ctx->out[ out_link_idx ].chunk0,
                                                           ctx->out[ out_link_idx ].wmark );
  ctx->prev_publish_time = ctx->now;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  (50UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_archiver_playback_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_archiver_playback_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping

#include "../stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_archiver_playback = {
  .name                     = "arch_p",
  .loose_footprint          = loose_footprint,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};

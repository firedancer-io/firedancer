/* The strmk tile writes fast boot streams.

   A fast boot stream is a snapshot archive that never finishes: it
   opens with the manifest of an incremental snapshot's slot and later
   grows by one appendvec per block, so that a peer can start
   executing before its own snapshot has loaded.  Replay tells this
   tile about every snapshot it starts, the same message the snapshot
   maker gets, and holds the snapshot's bank until both have said they
   are done with it.  At every incremental snapshot the tile ends the
   stream it is writing and starts the next one.  The snapsv tile
   serves the files over HTTP.

   The files are a small pool opened by run.c before the tiles start,
   like the snapshot pool.  A peer still downloading a file that is
   ended is cut off, like a peer downloading a snapshot that is
   recycled. */

#define _GNU_SOURCE
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "fd_strmk_tile.h"
#include "fd_strmk_keys.h"
#include "fd_backup_wake.h"
#include "fd_snapmk_tile.h"
#include "fd_ssmanifest_writer.h"
#include "../replay/fd_replay_tile.h"
#include "../../disco/stem/fd_stem.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/accdb/fd_accdb.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../tango/fseq/fd_fseq.h"

#include "generated/fd_strmk_tile_seccomp.h"

/* The manifest is serialized into the raw buffer, which is as big as
   the manifest writer needs.  The compressor reads it a bufferful at
   a time. */

#define STRMK_COMP_BUF_SZ (1UL<<20)

/* One fast boot stream: a growing archive file. */

struct strmk_stream {
  int   open;
  int   announced;  /* OPEN sent to the file server? */
  ulong start_slot; /* the slot the stream starts at */
  uchar hash[ 32 ];
  int   fd;
  ulong file_sz;
};

typedef struct strmk_stream strmk_stream_t;

#define STRMK_WINDOW  (64UL)    /* slots of blocks whose keys are kept */
#define STRMK_KEY_MAX (1UL<<19) /* map key capacity */

struct strmk_key_id {
  ulong       bank_seq;
  fd_pubkey_t key;
};

typedef struct strmk_key_id strmk_key_id_t;

struct strmk_key {
  strmk_key_id_t id;
  uint           next;
  uint           block_next;
};

typedef struct strmk_key strmk_key_t;

#define POOL_NAME  strmk_key_pool
#define POOL_T     strmk_key_t
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               strmk_key_map
#define MAP_ELE_T              strmk_key_t
#define MAP_KEY_T              strmk_key_id_t
#define MAP_KEY                id
#define MAP_IDX_T              uint
#define MAP_KEY_EQ(k0,k1)      ( ((k0)->bank_seq==(k1)->bank_seq) & !memcmp( (k0)->key.uc, (k1)->key.uc, 32UL ) )
#define MAP_KEY_HASH(k,s)      fd_hash32( (k)->key.uc, (s)+(k)->bank_seq )
#include "../../util/tmpl/fd_map_chain.c"

/* One block in the window, in the table slot of its bank. */

struct strmk_block {
  ulong bank_seq; /* ULONG_MAX while unused */
  ulong slot;
  uint  key_head_idx; /* head of the block's account keys, UINT_MAX if none */
};

typedef struct strmk_block strmk_block_t;

#define IN_KIND_SNAP_START (0) /* replay_snapmk */
#define IN_KIND_SNAPMK     (1) /* snapmk_out */
#define IN_KIND_KEYS       (2) /* execrp_strmk, execle_strmk */

struct fd_strmk {
  uint  cur;       /* the stream being written, UINT_MAX if none */
  ulong incr_slot; /* slot of the newest incremental snapshot on disk */

  strmk_stream_t stream[ FD_STRMK_POOL ];

  /* in links, and the frag the stem callbacks hand to each other */
  uchar       in_kind  [ FD_TOPO_MAX_TILE_IN_LINKS ];
  fd_wksp_t * in_mem   [ FD_TOPO_MAX_TILE_IN_LINKS ];
  ulong       in_chunk0[ FD_TOPO_MAX_TILE_IN_LINKS ];
  ulong       in_wmark [ FD_TOPO_MAX_TILE_IN_LINKS ];
  ulong       in_mtu   [ FD_TOPO_MAX_TILE_IN_LINKS ];
  union {
    fd_replay_snap_start_t start;
    fd_snapmk_msg_t        snapmk;
    fd_strmk_keys_msg_t    keys;
  } frag;

  /* keys of the blocks in the window */
  ulong             key_seed;
  strmk_key_map_t * key_map;
  strmk_key_t *     key_pool;
  strmk_block_t *   block;
  ulong             block_max;
  ulong             block_cnt;
  ulong             current_slot;

  struct {
    ulong key_cnt;
    ulong key_stored_cnt;
    ulong key_dropped_cnt;
  } metrics;

  uchar *        raw;
  uchar          comp[ STRMK_COMP_BUF_SZ ];
  ZSTD_CStream * zstd;

  fd_banks_t * banks;
  fd_accdb_t * accdb;

  fd_ssmanifest_writer_t manifest_writer[1];

  struct {
    ulong   out_idx;
    void *  mem;
    ulong   chunk;
    ulong   chunk0;
    ulong   wmark;
    ulong * seq_prod;
  } out;

  ulong replay_out_idx;
};

typedef struct fd_strmk fd_strmk_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( fd_ulong_max( alignof(fd_strmk_t), fd_accdb_align() ), 4096UL );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_strmk_t), sizeof(fd_strmk_t)                                  );
  l = FD_LAYOUT_APPEND( l, fd_accdb_align(),    fd_accdb_footprint( tile->strmk.max_live_slots, 0 )    );
  l = FD_LAYOUT_APPEND( l, 4096UL,              FD_SSMANIFEST_BUF_MIN                               );
  l = FD_LAYOUT_APPEND( l, 64UL,                ZSTD_estimateCStreamSize( FD_BACKUP_ZSTD_LEVEL )    );
  l = FD_LAYOUT_APPEND( l, strmk_key_map_align(),  strmk_key_map_footprint( strmk_key_map_chain_cnt_est( STRMK_KEY_MAX ) ) );
  l = FD_LAYOUT_APPEND( l, strmk_key_pool_align(), strmk_key_pool_footprint( STRMK_KEY_MAX )                             );
  l = FD_LAYOUT_APPEND( l, alignof(strmk_block_t), tile->strmk.max_live_slots*sizeof(strmk_block_t)                      );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

/**********************************************************************/
/* Archive writing                                                    */
/**********************************************************************/

/* zip_push compresses sz bytes into the stream file.  Every tar entry
   is one Zstandard frame, so the last call for an entry ends it. */

static void
zip_push( fd_strmk_t *      ctx,
          strmk_stream_t *  stream,
          void const *      data,
          ulong             sz,
          ZSTD_EndDirective directive ) {
  ZSTD_inBuffer  in  = { .src = data,      .size = sz,                .pos = 0UL };
  ZSTD_outBuffer out = { .dst = ctx->comp, .size = STRMK_COMP_BUF_SZ, .pos = 0UL };
  for(;;) {
    out.pos = 0UL;
    ulong ret = ZSTD_compressStream2( ctx->zstd, &out, &in, directive );
    if( FD_UNLIKELY( ZSTD_isError( ret ) ) ) {
      FD_LOG_ERR(( "ZSTD_compressStream2 failed: %s", ZSTD_getErrorName( ret ) ));
    }
    ulong wrote;
    int   err = fd_io_write( stream->fd, ctx->comp, out.pos, out.pos, &wrote );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_io_write failed (%i-%s)", err, fd_io_strerror( err ) ));
    stream->file_sz += wrote;
    if( FD_LIKELY( directive==ZSTD_e_end ) ) {
      if( FD_LIKELY( !ret ) ) break;
    } else if( FD_LIKELY( in.pos==in.size ) ) {
      break;
    }
  }
}

/* zip_pad ends an entry whose content was pushed in pieces, padding it
   out to a tar block. */

static void
zip_pad( fd_strmk_t *     ctx,
         strmk_stream_t * stream,
         ulong            content_sz ) {
  static uchar const zero[ FD_TAR_BLOCK_SZ ] = {0};
  zip_push( ctx, stream, zero, fd_ulong_align_up( content_sz, FD_TAR_BLOCK_SZ )-content_sz, ZSTD_e_end );
}

/* strmk_preamble writes the version file and the two directory
   entries, which carry no content of their own. */

static void
strmk_preamble( fd_strmk_t *     ctx,
                strmk_stream_t * stream ) {
  ulong sz = fd_backup_tar_preamble( ctx->raw, FD_SSMANIFEST_BUF_MIN, stream->start_slot );
  zip_push( ctx, stream, ctx->raw, sz, ZSTD_e_end );
}

/* strmk_manifest writes the snapshot manifest of the stream's start
   slot, which an initialized writer has already measured, a bufferful
   at a time.

   This is the one long call in the tile.  Block keys from replay
   queue up behind it, and a block's accounts can only be read until
   the root passes its parent, about 30 slots, so this must stay well
   under that; today it takes tens of milliseconds. */

static void
strmk_manifest( fd_strmk_t *     ctx,
                strmk_stream_t * stream ) {
  ulong manifest_sz = ctx->manifest_writer->serialized_sz;
  char  name[ FD_TAR_NAME_SZ ];
  fd_backup_manifest_name( name, stream->start_slot );

  fd_tar_meta_t meta;
  zip_push( ctx, stream, fd_backup_tar_named_hdr( &meta, name, manifest_sz ), sizeof(fd_tar_meta_t), ZSTD_e_continue );

  ulong wrote = 0UL;
  for(;;) {
    ulong chunk_sz = fd_snap_manifest_serialize( ctx->manifest_writer, ctx->raw, FD_SSMANIFEST_BUF_MIN );
    if( FD_UNLIKELY( !chunk_sz ) ) break;
    zip_push( ctx, stream, ctx->raw, chunk_sz, ZSTD_e_continue );
    wrote += chunk_sz;
  }
  FD_CHECK_CRIT( wrote==manifest_sz, "fast boot stream manifest does not match the size the writer measured" );
  zip_pad( ctx, stream, manifest_sz );
}

/**********************************************************************/
/* Stream pool                                                        */
/**********************************************************************/

/* strmk_announce tells the file server a stream file is ready to serve
   (FD_STRMK_MSG_OPEN) or is no longer served (FD_STRMK_MSG_CLOSE), the
   way the snapshot maker announces its files. */

static void
strmk_announce( fd_strmk_t *        ctx,
                fd_stem_context_t * stem,
                uint                idx,
                ulong               msg_type ) {
  strmk_stream_t * stream = &ctx->stream[ idx ];
  fd_strmk_msg_t * msg    = fd_chunk_to_laddr( ctx->out.mem, ctx->out.chunk );
  msg->slot = stream->start_slot;
  msg->idx  = idx;
  memcpy( msg->hash, stream->hash, 32UL );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->out.out_idx, msg_type, ctx->out.chunk, sizeof(fd_strmk_msg_t), 0UL, 0UL, tspub );
  ctx->out.chunk     = fd_dcache_compact_next( ctx->out.chunk, sizeof(fd_strmk_msg_t), ctx->out.chunk0, ctx->out.wmark );
  fd_backup_out_wake( ctx->out.seq_prod, stem->seqs[ ctx->out.out_idx ] );
}

/* strmk_done tells replay the tile is finished reading the bank of
   the snapshot at slot. */

static void
strmk_done( fd_strmk_t *        ctx,
            fd_stem_context_t * stem,
            ulong               slot ) {
  fd_stem_publish( stem, ctx->replay_out_idx, slot, 0UL, 0UL, 0UL, 0UL, 0UL );
}

/* strmk_stream_close ends the stream being written.  A peer still
   downloading it is cut off when the file server sees the close. */

static void
strmk_stream_close( fd_strmk_t *        ctx,
                    fd_stem_context_t * stem ) {
  if( FD_LIKELY( ctx->cur==UINT_MAX ) ) return;
  strmk_stream_t * stream = &ctx->stream[ ctx->cur ];
  FD_LOG_INFO(( "closing the fast boot stream at slot %lu (%lu bytes)", stream->start_slot, stream->file_sz ));

  if( FD_LIKELY( stream->announced ) ) strmk_announce( ctx, stem, ctx->cur, FD_STRMK_MSG_CLOSE );
  stream->open      = 0;
  stream->announced = 0;
  ctx->cur          = UINT_MAX;
}

/* strmk_announce_open announces a stream once a peer can use it.  A
   peer needs the incremental snapshot the stream starts at as well,
   so the OPEN waits until that snapshot is on disk, whichever of the
   two lands second. */

static void
strmk_announce_open( fd_strmk_t *        ctx,
                     fd_stem_context_t * stem ) {
  for( uint i=0U; i<FD_STRMK_POOL; i++ ) {
    strmk_stream_t * stream = &ctx->stream[ i ];
    if( FD_LIKELY( !stream->open || stream->announced || stream->start_slot!=ctx->incr_slot ) ) continue;
    stream->announced = 1;
    strmk_announce( ctx, stem, i, FD_STRMK_MSG_OPEN );
    FD_LOG_NOTICE(( "serving the fast boot stream at slot %lu", stream->start_slot ));
  }
}

/**********************************************************************/
/* Block account keys                                                 */
/**********************************************************************/

/* strmk_block_free releases all keys for a given block. */

static void
strmk_block_free( fd_strmk_t *    ctx,
                  strmk_block_t * block ) {
  uint idx = block->key_head_idx;
  while( idx!=UINT_MAX ) {
    strmk_key_t * key = strmk_key_pool_ele( ctx->key_pool, idx );
    idx = key->block_next;
    strmk_key_map_ele_remove( ctx->key_map, &key->id, NULL, ctx->key_pool );
    strmk_key_pool_ele_release( ctx->key_pool, key );
  }
  block->bank_seq = ULONG_MAX;
  ctx->block_cnt--;
}

/* strmk_window_slide frees the blocks that fell out of the window
   once slot is the newest. */

static void
strmk_window_slide( fd_strmk_t * ctx,
                    ulong        slot ) {
  ctx->current_slot = fd_ulong_max( ctx->current_slot, slot );
  for( ulong i=0UL; i<ctx->block_max; i++ ) {
    strmk_block_t * block = &ctx->block[ i ];
    if( block->bank_seq==ULONG_MAX ) continue;
    if( block->slot+STRMK_WINDOW<=ctx->current_slot ) strmk_block_free( ctx, block );
  }
}

/* strmk_store_keys records the keys of one transaction, the first
   time its block touches them.  Bank sequence numbers only grow: a
   bigger one in a bank's slot means the bank was reused and the block
   that was there is gone, a smaller one is a late message from such a
   block and is dropped. */

static void
strmk_store_keys( fd_strmk_t *                ctx,
                  fd_strmk_keys_msg_t const * msg ) {
  ctx->metrics.key_cnt += msg->key_cnt;

  FD_CHECK_CRIT( msg->bank_idx<ctx->block_max, "bank index out of range" );
  strmk_block_t * block    = &ctx->block[ msg->bank_idx ];
  int             occupied = block->bank_seq!=ULONG_MAX;

  /* Received a late message from a block that is gone.  Practically
     unreachable. */
  if( FD_UNLIKELY( occupied && msg->bank_seq<block->bank_seq ) ) return;

  /* Start a new block */
  if( FD_UNLIKELY( block->bank_seq!=msg->bank_seq ) ) {
    if( occupied ) strmk_block_free( ctx, block );

    block->bank_seq     = msg->bank_seq;
    block->slot         = msg->slot;
    block->key_head_idx = UINT_MAX;
    ctx->block_cnt++;
    strmk_window_slide( ctx, msg->slot );
  }

  /* Store unique keys seen within the block */
  for( ulong i=0UL; i<msg->key_cnt; i++ ) {
    strmk_key_id_t id = { .bank_seq = msg->bank_seq, .key = msg->keys[ i ] };
    if( FD_LIKELY( strmk_key_map_ele_query( ctx->key_map, &id, NULL, ctx->key_pool ) ) ) continue;

    if( FD_UNLIKELY( !strmk_key_pool_free( ctx->key_pool ) ) ) {
      ctx->metrics.key_dropped_cnt++;
      continue;
    }
    
    strmk_key_t * key = strmk_key_pool_ele_acquire( ctx->key_pool );
    key->id         = id;
    key->block_next = block->key_head_idx;
    strmk_key_map_ele_insert( ctx->key_map, key, ctx->key_pool );
    block->key_head_idx = (uint)strmk_key_pool_idx( ctx->key_pool, key );
    ctx->metrics.key_stored_cnt++;
  }
}

/**********************************************************************/
/* Message handling                                                   */
/**********************************************************************/

/* strmk_stream_start starts the next stream.  It runs on replay's
   snapshot start message: an incremental snapshot ends the stream
   being written and starts the next one in the other pool file, with
   the version entry and the manifest from the bank replay is holding,
   then gives the bank back.  A full snapshot starts no stream; replay
   only waits for this tile on incrementals. */

static void
strmk_stream_start( fd_strmk_t *                   ctx,
                    fd_stem_context_t *            stem,
                    fd_replay_snap_start_t const * msg ) {
  if( FD_UNLIKELY( msg->slot==msg->base_slot ) ) return;

  uint prev = ctx->cur;
  strmk_stream_close( ctx, stem );

  /* the other file: the file server stopped serving it an incremental
     ago, when it saw that stream close */
  uint idx = prev==UINT_MAX ? 0U : ( prev+1U )%FD_STRMK_POOL;

  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, msg->bank_idx );
  FD_CHECK_CRIT( bank && bank->f.slot==msg->slot, "snapshot bank is not the one replay named" );

  long now = fd_log_wallclock();
  strmk_stream_t * stream = &ctx->stream[ idx ];
  stream->open       = 1;
  stream->announced  = 0;
  stream->start_slot = msg->slot;
  stream->file_sz    = 0UL;
  fd_blake3_hash( bank->f.lthash.bytes, FD_LTHASH_LEN_BYTES, stream->hash );

  if( FD_UNLIKELY( -1==ftruncate( stream->fd, 0L ) ) ) {
    FD_LOG_ERR(( "ftruncate(fast boot stream) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( -1==lseek( stream->fd, 0L, SEEK_SET ) ) ) {
    FD_LOG_ERR(( "lseek(fast boot stream) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  ulong zst_err = ZSTD_CCtx_reset( ctx->zstd, ZSTD_reset_session_only );
  if( FD_UNLIKELY( ZSTD_isError( zst_err ) ) ) {
    FD_LOG_ERR(( "ZSTD_CCtx_reset failed: %s", ZSTD_getErrorName( zst_err ) ));
  }

  fd_ssmanifest_writer_init( ctx->manifest_writer, bank, &msg->leader, ctx->accdb, bank->accdb_fork_id, ctx->raw );
  strmk_preamble( ctx, stream );
  strmk_manifest( ctx, stream );
  ctx->cur = idx;
  strmk_done( ctx, stem, msg->slot );

  FD_LOG_NOTICE(( "fast boot stream at slot %lu opened in %ld millis (%lu bytes)",
                  stream->start_slot, ( fd_log_wallclock()-now )/(1000L*1000L), stream->file_sz ));

  strmk_announce_open( ctx, stem );
}

/* strmk_snapshot_created notes that an incremental snapshot landed on
   disk. */

static void
strmk_snapshot_created( fd_strmk_t *                    ctx,
              fd_stem_context_t *             stem,
              fd_snapmk_msg_created_t const * msg ) {
  if( FD_LIKELY( msg->base_slot==ULONG_MAX ) ) return;
  ctx->incr_slot = msg->slot;
  strmk_announce_open( ctx, stem );
}

static void
during_frag( fd_strmk_t * ctx,
             ulong        in_idx,
             ulong        seq,
             ulong        sig,
             ulong        chunk,
             ulong        sz,
             ulong        ctl ) {
  (void)seq; (void)sig; (void)ctl;
  FD_CHECK_CRIT( chunk>=ctx->in_chunk0[ in_idx ] &&
                 chunk<=ctx->in_wmark [ in_idx ] &&
                 sz   <=ctx->in_mtu   [ in_idx ], "input frag is out-of-bounds" );
  fd_memcpy( &ctx->frag, fd_chunk_to_laddr_const( ctx->in_mem[ in_idx ], chunk ), sz );
}

static void
after_frag( fd_strmk_t *        ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)seq; (void)tsorig; (void)tspub;

  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_SNAP_START:
    if( FD_LIKELY( sig==REPLAY_SIG_SNAP_START ) ) strmk_stream_start( ctx, stem, &ctx->frag.start );
    break;
  case IN_KIND_SNAPMK:
    if( FD_LIKELY( sig==FD_SNAPMK_MSG_CREATED ) ) strmk_snapshot_created( ctx, stem, &ctx->frag.snapmk.created );
    break;
  case IN_KIND_KEYS:
    FD_CHECK_CRIT( ctx->frag.keys.key_cnt<=FD_STRMK_READ_KEYS_MAX && sz==sizeof(fd_strmk_keys_msg_t), "bad key message" );
    strmk_store_keys( ctx, &ctx->frag.keys );
    break;
  }
}

static void
metrics_write( fd_strmk_t * ctx ) {
  FD_MCNT_SET  ( STRMK, KEY_RECEIVED, ctx->metrics.key_cnt         );
  FD_MCNT_SET  ( STRMK, KEY_STORED,   ctx->metrics.key_stored_cnt  );
  FD_MCNT_SET  ( STRMK, KEY_DROPPED,  ctx->metrics.key_dropped_cnt );
  FD_MGAUGE_SET( STRMK, BLOCK_COUNT,  ctx->block_cnt );
  FD_MGAUGE_SET( STRMK, KEY_COUNT,    strmk_key_pool_used( ctx->key_pool ) );
}

/**********************************************************************/
/* Tile setup                                                         */
/**********************************************************************/

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo; (void)tile;
  if( FD_UNLIKELY( out_fds_cnt<4UL+FD_STRMK_POOL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = FD_ACCDB_FD_RO;
  out_fds[ out_cnt++ ] = FD_VOTE_STAKES_FD; /* vote stakes disk spill */
  for( ulong i=0UL; i<FD_STRMK_POOL; i++ ) out_fds[ out_cnt++ ] = FD_STRMK_FD( i );
  return out_cnt;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo; (void)tile;
  populate_sock_filter_policy_fd_strmk_tile(
      out_cnt, out,
      (uint)fd_log_private_logfile_fd(),
      (uint)FD_STRMK_FD( 0 ), (uint)FD_STRMK_FD( FD_STRMK_POOL-1UL ),
      (uint)FD_ACCDB_FD_RO,
      (uint)FD_VOTE_STAKES_FD );
  return sock_filter_policy_fd_strmk_tile_instr_cnt;
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_strmk_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_strmk_t), sizeof(fd_strmk_t) );
  memset( ctx, 0, sizeof(fd_strmk_t) );
  FD_TEST( fd_rng_secure( &ctx->key_seed, sizeof(ulong) ) );
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  ulong  zst_sz  = ZSTD_estimateCStreamSize( FD_BACKUP_ZSTD_LEVEL );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_strmk_t * ctx    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_strmk_t), sizeof(fd_strmk_t) );
  void *       _accdb = FD_SCRATCH_ALLOC_APPEND( l, fd_accdb_align(),    fd_accdb_footprint( tile->strmk.max_live_slots, 0 ) );
  void *       _raw   = FD_SCRATCH_ALLOC_APPEND( l, 4096UL,              FD_SSMANIFEST_BUF_MIN );
  void *       _zst   = FD_SCRATCH_ALLOC_APPEND( l, 64UL,                zst_sz );
  void *       _map   = FD_SCRATCH_ALLOC_APPEND( l, strmk_key_map_align(),  strmk_key_map_footprint( strmk_key_map_chain_cnt_est( STRMK_KEY_MAX ) ) );
  void *       _pool  = FD_SCRATCH_ALLOC_APPEND( l, strmk_key_pool_align(), strmk_key_pool_footprint( STRMK_KEY_MAX ) );
  void *       _block = FD_SCRATCH_ALLOC_APPEND( l, alignof(strmk_block_t), tile->strmk.max_live_slots*sizeof(strmk_block_t) );
  ulong end = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  FD_CHECK_CRIT( end==(ulong)scratch + scratch_footprint( tile ), "bug when calculating tile memory layout" );

  ctx->cur       = UINT_MAX;
  ctx->incr_slot = ULONG_MAX;
  ctx->raw       = _raw;

  ctx->zstd = ZSTD_initStaticCStream( _zst, zst_sz );
  FD_TEST( ctx->zstd );
  ulong zst_err = ZSTD_CCtx_setParameter( ctx->zstd, ZSTD_c_compressionLevel, FD_BACKUP_ZSTD_LEVEL );
  if( FD_UNLIKELY( ZSTD_isError( zst_err ) ) ) {
    FD_LOG_ERR(( "ZSTD_CCtx_setParameter failed: %s", ZSTD_getErrorName( zst_err ) ));
  }

  for( uint i=0U; i<FD_STRMK_POOL; i++ ) ctx->stream[ i ].fd = FD_STRMK_FD( i );

  ctx->key_map  = strmk_key_map_join( strmk_key_map_new( _map, strmk_key_map_chain_cnt_est( STRMK_KEY_MAX ), ctx->key_seed ) );
  ctx->key_pool = strmk_key_pool_join( strmk_key_pool_new( _pool, STRMK_KEY_MAX ) );
  FD_TEST( ctx->key_map && ctx->key_pool );
  ctx->block        = _block;
  ctx->block_max    = tile->strmk.max_live_slots;
  ctx->block_cnt    = 0UL;
  ctx->current_slot = 0UL;
  for( ulong i=0UL; i<ctx->block_max; i++ ) ctx->block[ i ].bank_seq = ULONG_MAX;

  ctx->banks = fd_banks_join( fd_topo_obj_laddr( topo, tile->strmk.banks_obj_id ) );
  FD_TEST( ctx->banks );

  /* Read-only join to accdb.  The epoch fseq tells the accdb tile
     which epoch this tile reads so that compaction does not reclaim
     partitions mid-read. */
  fd_accdb_shmem_t * accdb_shmem = fd_accdb_shmem_join( fd_topo_obj_laddr( topo, tile->strmk.accdb_obj_id ) );
  FD_TEST( accdb_shmem );
  ulong * epoch_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, tile->strmk.accdb_epoch_obj_id ) );
  FD_TEST( epoch_fseq );
  ctx->accdb = fd_accdb_join_readonly( _accdb, accdb_shmem, epoch_fseq, FD_ACCDB_FD_RO );
  FD_TEST( ctx->accdb );

  FD_CHECK_ERR( fd_topo_find_tile_in_link( topo, tile, "replay_snapmk", 0UL )!=ULONG_MAX, "missing replay_snapmk link" );
  FD_CHECK_ERR( fd_topo_find_tile_in_link( topo, tile, "snapmk_out",    0UL )!=ULONG_MAX, "missing snapmk_out link"    );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if(      !strcmp( link->name, "replay_snapmk" ) ) ctx->in_kind[ i ] = IN_KIND_SNAP_START;
    else if( !strcmp( link->name, "snapmk_out"    ) ) ctx->in_kind[ i ] = IN_KIND_SNAPMK;
    else if( !strcmp( link->name, "execrp_strmk"  ) ) ctx->in_kind[ i ] = IN_KIND_KEYS;
    else if( !strcmp( link->name, "execle_strmk"  ) ) ctx->in_kind[ i ] = IN_KIND_KEYS;
    else FD_LOG_ERR(( "unexpected input link \"%s\"", link->name ));
    FD_TEST( link->dcache );
    ctx->in_mem   [ i ] = fd_wksp_containing( link->dcache );
    FD_TEST( ctx->in_mem[ i ] );
    ctx->in_chunk0[ i ] = fd_dcache_compact_chunk0( ctx->in_mem[ i ], link->dcache );
    ctx->in_wmark [ i ] = fd_dcache_compact_wmark ( ctx->in_mem[ i ], link->dcache, link->mtu );
    ctx->in_mtu   [ i ] = link->mtu;
    FD_CHECK_ERR( link->mtu<=sizeof(ctx->frag), "input link MTU too large" );
  }

  /* The tile gives banks back to replay on strmk_replay and tells the
     file server about stream files on strmk_out. */
  ctx->replay_out_idx = fd_topo_find_tile_out_link( topo, tile, "strmk_replay", 0UL );
  FD_CHECK_ERR( ctx->replay_out_idx!=ULONG_MAX, "missing strmk_replay link" );
  ulong out_idx = fd_topo_find_tile_out_link( topo, tile, "strmk_out", 0UL );
  FD_CHECK_ERR( out_idx!=ULONG_MAX, "missing strmk_out link" );
  fd_topo_link_t const * out_link = &topo->links[ tile->out_link_id[ out_idx ] ];
  FD_CHECK_ERR( out_link->mtu>=sizeof(fd_strmk_msg_t), "strmk_out link MTU too small" );
  ctx->out.out_idx  = out_idx;
  ctx->out.mem      = fd_wksp_containing( out_link->dcache );
  ctx->out.chunk0   = fd_dcache_compact_chunk0( ctx->out.mem, out_link->dcache );
  ctx->out.wmark    = fd_dcache_compact_wmark ( ctx->out.mem, out_link->dcache, out_link->mtu );
  ctx->out.chunk    = ctx->out.chunk0;
  ctx->out.seq_prod = fd_mcache_seq_laddr( out_link->mcache );
}

/* One snapshot start can close a stream, give the bank back and open
   the next stream. */

#define STEM_BURST (4UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_strmk_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_strmk_t)
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag
#define STEM_CALLBACK_METRICS_WRITE metrics_write

#include "../../disco/stem/fd_stem.c"

#ifndef FD_TILE_TEST
fd_topo_run_tile_t fd_tile_strmk = {
  .name                     = "strmk",
  .populate_allowed_fds     = populate_allowed_fds,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run
};
#endif

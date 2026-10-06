/* The strmk tile writes instant boot streams.

   A boot stream is an archive that starts at a slot and grows by one
   appendvec per block, so that a peer can start executing before its
   snapshot has finished loading.  The replay tile feeds this tile the
   accounts each block touches, the tile reads their values at the
   stream's start slot through a read-only accounts join, and the
   snapsv tile serves the files over HTTP.

   A stream opens with the fixed part of a Solana snapshot: the version
   file, the manifest and the status cache of its start slot, followed
   by one appendvec holding the accounts a booting peer needs before it
   has seen any block.  After that every block the validator replays
   adds one appendvec named after the block's slot, holding the
   accounts that block is the first to touch since the stream started,
   read at the block's parent fork, which is where they still have
   their value as of the start slot.

   A stream starts at the slot of an incremental snapshot, which is the
   slot replay just rooted, and replay is always rooting behind the
   blocks it has executed.  So the tile keeps the accounts of the last
   blocks it saw and writes the ones that ran after the start slot into
   the stream before it hands the bank back; otherwise the stream would
   be missing them, and the accounts of the blocks that follow would be
   read at a fork where they no longer hold their start slot value.

   This tile owns a fixed pool of files in a directory below the
   snapshots directory: one file per open stream plus the index.  The
   files are opened before the sandbox starts, because the sandbox bans
   opening files. */

#define _GNU_SOURCE
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>
#include <errno.h>
#include <string.h>

#include "fd_strmk_tile.h"
#include "fd_backup_wake.h"
#include "fd_snapmk_tile.h"
#include "fd_ssmanifest_writer.h"
#include "fd_txncache_writer.h"
#include "../replay/fd_replay_tile.h"
#include "../../disco/stem/fd_stem.h"
#include "../../disco/topo/fd_topo.h"
#include "../../flamenco/accdb/fd_accdb.h"
#include "../../flamenco/alpenglow/fd_alpenglow.h"
#include "../../flamenco/features/fd_features.h"
#include "../../flamenco/stakes/fd_vote_stakes.h"
#include "../../flamenco/runtime/fd_alut.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/program/fd_bpf_loader_program.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_cache_private.h"
#include "../../tango/fseq/fd_fseq.h"

#include "generated/fd_strmk_tile_seccomp.h"

/* One tar entry is staged uncompressed in the raw buffer, then
   compressed into one Zstandard frame and written out, so the buffer
   bounds how large an appendvec can be.  A block whose accounts do not
   fit is split into overflow files. */

#define STRMK_RAW_BUF_SZ  (64UL<<20)
#define STRMK_COMP_BUF_SZ ( 4UL<<20)

/* STRMK_BLOCK_LIVE_MAX bounds the blocks in flight, which replay
   bounds the same way with the ring of bank references it hands out.
   STRMK_BLOCK_RETAIN_MAX is how many completed blocks the tile keeps
   so that a stream opening later can cover them. */

#define STRMK_BLOCK_LIVE_MAX   ( 64UL)
#define STRMK_BLOCK_RETAIN_MAX (128UL)
#define STRMK_BLOCK_MAX        (STRMK_BLOCK_LIVE_MAX+STRMK_BLOCK_RETAIN_MAX)

/* A block entry is free, in flight, or kept for a stream that opens
   later. */

#define STRMK_BLOCK_FREE (0)
#define STRMK_BLOCK_LIVE (1)
#define STRMK_BLOCK_DONE (2)

/* An open addressed set is only probed while it is at most this full,
   past which it is grown or, for a stream, closed.  Open addressing
   degrades badly near capacity. */

#define STRMK_SENT_LOAD_NUM (3UL)
#define STRMK_SENT_LOAD_DEN (4UL)

/* The accounts of one block, as a set, because the keys arrive with
   heavy repeats and the whole set has to be kept until every stream
   that could want it has opened.  A mainnet block touches a few
   thousand distinct accounts; one that touches more than the set holds
   breaks the streams, loudly. */

#define STRMK_BLOCK_SLOT_MAX (16384UL)
#define STRMK_BLOCK_KEY_MAX  ((STRMK_BLOCK_SLOT_MAX*STRMK_SENT_LOAD_NUM)/STRMK_SENT_LOAD_DEN)

/* How a block named an account: as an ordinary transaction key, or as
   an address lookup table replay could not expand and the tile has to
   expand itself. */

#define STRMK_KEY_FREE  (0)
#define STRMK_KEY_PLAIN (1)
#define STRMK_KEY_TABLE (2)

/* STRMK_ALUT_ADDR_MAX bounds the addresses of an address lookup table
   the tile follows.  A transaction names them with a byte index, so
   the runtime can never reach past the first 256 of them. */

#define STRMK_ALUT_ADDR_MAX (256UL)

/* STRMK_CARRIED_MAX bounds the blocks a stream remembers carrying, so
   that it can tell whether a block chains off something it has.  One
   entry is one block, named by its bank index and sequence number
   together.  A stream is served for
   [snapshots.instant_boot.serve.stream_lifetime_seconds], 240 seconds
   by default, which is six hundred slots, so this has room for the
   blocks of a lifetime several times over even with forks.  A stream
   that fills it is broken, loudly. */

#define STRMK_CARRIED_MAX (4096UL)

/* One index line is a slot, a base58 hash and a unix second. */

#define STRMK_INDEX_LINE_MAX (128UL)

/* Streams are checked for expiry about once a second. */

#define STRMK_EXPIRE_CHECK_NS (1000L*1000L*1000L)

/* A block's reads hold no reference on the fork they read at, so the
   fork is re-checked every STRMK_FORK_CHECK_KEYS accounts.  That
   bounds both the work a purge under them wastes and how long a record
   read from a purged fork can sit staged. */

#define STRMK_FORK_CHECK_KEYS (64UL)

/* STRMK_REUSE_NS is how long a closed stream's file sits idle before a
   new stream is given it.  The file server learns a stream is gone
   from a message, and a peer in the middle of a download reads the
   file until it does, so the bytes under it must not change at once.
   A stream that broke is truncated the moment it closes on purpose:
   its archive is unusable, and a peer reading it has to fail rather
   than carry on. */

#define STRMK_REUSE_NS (10L*1000L*1000L*1000L)

/* STRMK_SENT_TABLE marks a sent set entry whose account was an address
   lookup table when the stream carried it.  The tile reads such a key
   again every time a block names it, because the table can have gained
   addresses since, and a stream has to carry those too.  This is the
   fallback for a table replay did expand, which arrives as an ordinary
   key: a table replay could not expand arrives named as one and is
   read whether or not it is marked. */

#define STRMK_SENT_TABLE (1UL<<63)

/* One entry of a stream's sent set.  key is an account the stream has
   already carried and slot is the appendvec it went into, with
   STRMK_SENT_TABLE on top.  A zero slot means the entry is free; a
   stream never starts at slot zero. */

struct strmk_sent {
  fd_pubkey_t key;
  ulong       slot;
};

typedef struct strmk_sent strmk_sent_t;

/* One block a stream carried.  A free entry has a bank index of
   ULONG_MAX. */

struct strmk_carried {
  ulong bank_idx;
  ulong bank_seq;
};

typedef struct strmk_carried strmk_carried_t;

/* One boot stream: a growing archive file plus the accounts it has
   already carried. */

struct strmk_stream {
  int             open;
  int             listed;     /* named in the index? */
  int             published;  /* told to the file server? */
  ulong           start_slot; /* the slot the stream starts at */
  ulong           bank_idx;   /* the bank of that slot */
  ulong           bank_seq;
  uchar           hash[ 32 ];
  /* unix nanoseconds: when the stream opened, when it expires, which
     restarts when it is listed, and when its file came free */
  long            started;
  long            expires;
  long            closed;
  int             fd;
  ZSTD_CStream *  zst;
  strmk_sent_t *  sent;
  ulong           sent_cnt;
  int             sent_full;  /* an account did not fit the sent set */
  ulong           file_sz;
  ulong           raw_sz;     /* bytes staged for the appendvec */
  ulong           vec_id;     /* overflow files of the appendvec */
  uchar *         raw;
  strmk_carried_t carried[ STRMK_CARRIED_MAX ];
};

typedef struct strmk_stream strmk_stream_t;

/* The account set of one block.  used holds a STRMK_KEY_* for every
   slot. */

struct strmk_keyset {
  uchar       used[ STRMK_BLOCK_SLOT_MAX ];
  fd_pubkey_t key [ STRMK_BLOCK_SLOT_MAX ];
};

typedef struct strmk_keyset strmk_keyset_t;

/* One block replay fed this tile.  Replay reuses a bank index once a
   block is gone, so a block is named by the index and the sequence
   number together.  The hold token goes back to replay once the block
   is written.  The parent's sequence number and the fork the block is
   read at are only named at the block end, and are ULONG_MAX and unset
   until then. */

struct strmk_block {
  int                state;
  ulong              slot;
  ulong              bank_idx;
  ulong              bank_seq;
  ulong              parent_bank_idx;
  ulong              hold_token;
  ulong              parent_bank_seq;
  fd_accdb_fork_id_t parent_fork;
  uint               key_cnt;
  int                overflow; /* more than the set holds? */
  int                linked;   /* chains back to the stream? */
  strmk_keyset_t *   keys;
};

typedef struct strmk_block strmk_block_t;

struct fd_strmk {
  /* the boot file directory, kept open so the files can be inspected */
  int    dir_fd;
  int    index_fd;
  uint   stream_max;
  ulong  key_max;      /* sent set entries per stream, a power of two */
  ulong  key_cap;      /* keys a stream carries before it closes */
  long   lifetime;     /* nanoseconds a stream is served for */
  long   expire_check; /* tick count of the next expiry sweep */
  double tick_per_ns;

  strmk_stream_t stream[ FD_STRMK_STREAM_MAX ];
  strmk_block_t  block [ STRMK_BLOCK_MAX ];

  /* the block in flight at each bank index, UINT_MAX where there is
     none, and the number of bank indices replay hands out */
  uint * bank_block;
  ulong  bank_max;

  /* completed blocks in the order they ended, oldest first, and the
     newest slot that ended since the last reset */
  uint  retain[ STRMK_BLOCK_RETAIN_MAX ];
  ulong retain_head;
  ulong retain_tail;
  ulong last_end_slot;

  /* in links, and the frag the stem callbacks hand to each other */
  fd_wksp_t * in_mem   [ 2 ];
  ulong       in_chunk0[ 2 ];
  ulong       in_wmark [ 2 ];
  ulong       in_mtu   [ 2 ];
  ulong       snapmk_in_idx;
  ulong       replay_seq_next;
  uchar       frag[ FD_STRMK_MTU ] __attribute__((aligned(16)));

  /* one account read, shared by every stream of a block, and the
     accounts that read implies */
  uchar *     acc_data;
  uchar *     comp;
  fd_pubkey_t follow[ 2 ][ STRMK_ALUT_ADDR_MAX ];
  uchar       vote_stakes_iter[ FD_VOTE_STAKES_ITER_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN)));

  fd_banks_t *    banks;
  fd_txncache_t * txncache;
  fd_accdb_t *    accdb;

  fd_ssmanifest_writer_t manifest_writer[1];
  fd_txncache_writer_t   txncache_writer[1];
  void *                 txncache_arena;
  ulong                  txncache_arena_sz;

  struct {
    ulong   out_idx;
    void *  mem;
    ulong   chunk;
    ulong   chunk0;
    ulong   wmark;
    ulong * seq_prod;
    int     published; /* a message is waiting for the file server */
  } out;

  ulong replay_out_idx;
};

typedef struct fd_strmk fd_strmk_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( fd_ulong_max( alignof(fd_strmk_t), fd_txncache_align() ),
                       fd_ulong_max( fd_accdb_align(), 4096UL ) );
}

/* strmk_file_cnt is one file per stream plus the index. */

FD_FN_PURE static inline uint
strmk_file_cnt( fd_strmk_t const * ctx ) {
  return ctx->stream_max+1U;
}

/* A stream below this carries too little to be worth opening. */

#define STRMK_KEY_MIN (1024UL)

/* strmk_key_max gives the number of sent set entries per stream, which
   is the configured key count rounded up to a power of two. */

FD_FN_PURE static inline ulong
strmk_key_max( fd_topo_tile_t const * tile ) {
  return fd_ulong_pow2_up( fd_ulong_max( tile->strmk.max_keys_per_stream, STRMK_KEY_MIN ) );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong max_live_slots = tile->strmk.max_live_slots;
  ulong stream_max     = tile->strmk.max_open_streams;
  ulong key_max        = strmk_key_max( tile );
  ulong zst_sz         = ZSTD_estimateCStreamSize( FD_BACKUP_ZSTD_LEVEL );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_strmk_t),              sizeof(fd_strmk_t)                                          );
  l = FD_LAYOUT_APPEND( l, fd_txncache_align(),              fd_txncache_footprint( max_live_slots )                     );
  l = FD_LAYOUT_APPEND( l, fd_accdb_align(),                 fd_accdb_footprint( max_live_slots, 0 )                     );
  l = FD_LAYOUT_APPEND( l, fd_txncache_writer_arena_align(), fd_txncache_writer_arena_sz( tile->strmk.max_txn_per_slot ) );
  l = FD_LAYOUT_APPEND( l, 16UL,                             FD_RUNTIME_ACC_SZ_MAX                                       );
  l = FD_LAYOUT_APPEND( l, 16UL,                             STRMK_COMP_BUF_SZ                                           );
  l = FD_LAYOUT_APPEND( l, alignof(strmk_keyset_t),          STRMK_BLOCK_MAX*sizeof(strmk_keyset_t)                      );
  l = FD_LAYOUT_APPEND( l, alignof(uint),                    max_live_slots*sizeof(uint)                                 );
  l = FD_LAYOUT_APPEND( l, 4096UL,                           stream_max*STRMK_RAW_BUF_SZ                                 );
  l = FD_LAYOUT_APPEND( l, alignof(strmk_sent_t),            stream_max*key_max*sizeof(strmk_sent_t)                     );
  l = FD_LAYOUT_APPEND( l, 64UL,                             stream_max*zst_sz                                           );
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
  if( FD_UNLIKELY( !sz && directive!=ZSTD_e_end ) ) return;
  ZSTD_inBuffer  in  = { .src = data,      .size = sz,                .pos = 0UL };
  ZSTD_outBuffer out = { .dst = ctx->comp, .size = STRMK_COMP_BUF_SZ, .pos = 0UL };
  for(;;) {
    out.pos = 0UL;
    ulong ret = ZSTD_compressStream2( stream->zst, &out, &in, directive );
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
  static uchar const zero[ sizeof(fd_tar_meta_t) ] = {0};
  zip_push( ctx, stream, zero, fd_ulong_align_up( content_sz, sizeof(fd_tar_meta_t) )-content_sz, ZSTD_e_end );
}

/* zip_entry compresses a tar entry the raw buffer holds whole, which is
   its tar header followed by content_sz bytes of content. */

static void
zip_entry( fd_strmk_t *     ctx,
           strmk_stream_t * stream,
           ulong            content_sz ) {
  ulong entry_sz = sizeof(fd_tar_meta_t) + fd_ulong_align_up( content_sz, sizeof(fd_tar_meta_t) );
  FD_CHECK_CRIT( entry_sz<=STRMK_RAW_BUF_SZ, "boot stream tar entry does not fit the raw buffer" );
  fd_memset( stream->raw + sizeof(fd_tar_meta_t) + content_sz, 0,
             entry_sz - sizeof(fd_tar_meta_t) - content_sz );
  zip_push( ctx, stream, stream->raw, entry_sz, ZSTD_e_end );
}

/* strmk_open_entries writes the version file and the two directory
   entries, which carry no content of their own. */

static void
strmk_open_entries( fd_strmk_t *     ctx,
                    strmk_stream_t * stream ) {
  ulong sz = fd_backup_tar_open_entries( stream->raw, stream->start_slot );
  zip_push( ctx, stream, stream->raw, sz, ZSTD_e_end );
}

/* strmk_manifest writes the snapshot manifest of the stream's start
   slot, which an initialized writer has already measured.  A mainnet
   manifest is far larger than the raw buffer, so it is compressed into
   the entry's frame a bufferful at a time. */

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
    ulong chunk_sz = fd_snap_manifest_serialize( ctx->manifest_writer, stream->raw, STRMK_RAW_BUF_SZ );
    if( FD_UNLIKELY( !chunk_sz ) ) break;
    zip_push( ctx, stream, stream->raw, chunk_sz, ZSTD_e_continue );
    wrote += chunk_sz;
  }
  FD_CHECK_CRIT( wrote==manifest_sz, "boot stream manifest does not match the size the writer measured" );
  zip_pad( ctx, stream, manifest_sz );
}

/* strmk_status_cache writes the status cache of the stream's start
   slot. */

static void
strmk_status_cache( fd_strmk_t *     ctx,
                    strmk_stream_t * stream ) {
  ulong status_sz = fd_txncache_writer_serialized_sz( ctx->txncache_writer );

  fd_tar_meta_t meta;
  zip_push( ctx, stream, fd_backup_tar_named_hdr( &meta, FD_BACKUP_STATUS_CACHE_NAME, status_sz ),
            sizeof(fd_tar_meta_t), ZSTD_e_continue );

  ulong wrote = 0UL;
  for(;;) {
    ulong chunk_sz = fd_txncache_writer_serialize( ctx->txncache_writer, stream->raw, STRMK_RAW_BUF_SZ );
    if( FD_UNLIKELY( !chunk_sz ) ) break;
    zip_push( ctx, stream, stream->raw, chunk_sz, ZSTD_e_continue );
    wrote += chunk_sz;
  }
  FD_CHECK_CRIT( wrote==status_sz, "boot stream status cache does not match the size the writer measured" );
  zip_pad( ctx, stream, status_sz );
}

/* strmk_encode_account appends one account to the raw buffer in the
   snapshot appendvec layout and returns the bytes it took.  slot is
   the slot the stream started at, which is where the value was read.
   A lamports of zero records that the account did not exist. */

static ulong
strmk_encode_account( uchar *             buf,
                      ulong               slot,
                      fd_pubkey_t const * key,
                      ulong               lamports,
                      int                 executable,
                      uchar const *       owner,
                      uchar const *       data,
                      ulong               data_len ) {
  snap_acc_hdr_t * hdr = (snap_acc_hdr_t *)buf;
  memset( hdr, 0, sizeof(snap_acc_hdr_t) );
  hdr->slot       = slot;
  hdr->data_len   = data_len;
  hdr->pubkey     = *key;
  hdr->lamports   = lamports;
  hdr->rent_epoch = ULONG_MAX;
  memcpy( hdr->owner.uc, owner, sizeof(fd_pubkey_t) );
  hdr->executable = (uchar)!!executable;

  ulong pad = fd_ulong_align_up( data_len, 8UL ) - data_len;
  if( FD_LIKELY( data_len ) ) memcpy( buf+sizeof(snap_acc_hdr_t), data, data_len );
  if( FD_UNLIKELY( pad )    ) memset( buf+sizeof(snap_acc_hdr_t)+data_len, 0, pad );
  return sizeof(snap_acc_hdr_t) + data_len + pad;
}

/* strmk_appendvec_flush writes the appendvec a stream has staged for
   slot.  id is the number after the dot in the file name; a booting
   peer treats the end of file zero as the end of the slot, so the
   overflow files of a slot are written first and file zero last. */

static void
strmk_appendvec_flush( fd_strmk_t *     ctx,
                       strmk_stream_t * stream,
                       ulong            slot,
                       ulong            id ) {
  char name[ FD_TAR_NAME_SZ ];
  FD_TEST( fd_cstr_printf_check( name, sizeof(name), NULL, "accounts/%lu.%lu", slot, id ) );
  fd_backup_tar_named_hdr( (fd_tar_meta_t *)stream->raw, name, stream->raw_sz );
  zip_entry( ctx, stream, stream->raw_sz );
  stream->raw_sz = 0UL;
}

/**********************************************************************/
/* Sent sets                                                          */
/**********************************************************************/

/* strmk_sent_query returns the entry key belongs in, which either
   holds key or is the free entry it would be inserted at, or NULL if
   the set has no free entry left. */

static strmk_sent_t *
strmk_sent_query( strmk_sent_t *      sent,
                  ulong               slot_cnt,
                  fd_pubkey_t const * key ) {
  ulong mask = slot_cnt-1UL;
  ulong idx  = fd_ulong_load_8( key->uc ) & mask;
  for( ulong i=0UL; i<slot_cnt; i++ ) {
    strmk_sent_t * ele = &sent[ idx ];
    if( FD_LIKELY( !ele->slot ) ) return ele;
    if( FD_UNLIKELY( fd_memeq( ele->key.uc, key->uc, sizeof(fd_pubkey_t) ) ) ) return ele;
    idx = (idx+1UL) & mask;
  }
  return NULL;
}

/* One key resolved against the sent set of every stream in a take
   mask.  ele holds the entry the key belongs in for each of them and
   is NULL for a stream that is not taking, or whose set is full.
   wanted says one of them has not carried the key, and table says one
   of them carried it as an address lookup table. */

struct strmk_probe {
  strmk_sent_t * ele[ FD_STRMK_STREAM_MAX ];
  int            wanted;
  int            table;
};

typedef struct strmk_probe strmk_probe_t;

/* strmk_sent_probe probes the sent set of each stream in take once, so
   that the rest of a key's handling reads the entry instead of probing
   again. */

static void
strmk_sent_probe( fd_strmk_t *        ctx,
                  uint                take,
                  fd_pubkey_t const * key,
                  strmk_probe_t *     probe ) {
  probe->wanted = 0;
  probe->table  = 0;
  for( uint i=0U; i<ctx->stream_max; i++ ) {
    if( FD_LIKELY( !( take & (1U<<i) ) ) ) {
      probe->ele[ i ] = NULL;
      continue;
    }
    strmk_sent_t * ele = strmk_sent_query( ctx->stream[ i ].sent, ctx->key_max, key );
    probe->ele[ i ] = ele;
    /* A set with no free entry left did not hold the key either: the
       probe walked all of it without finding a match. */
    probe->wanted |= !ele || !ele->slot;
    probe->table  |= !!ele && !!( ele->slot & STRMK_SENT_TABLE );
  }
}

/* strmk_sent_insert records through a probed entry that the stream
   carried key in the appendvec of slot, and whether the account was an
   address lookup table.  Returns 0 if the set had no room, which
   leaves the stream unusable: it would skip the account next time. */

static int
strmk_sent_insert( strmk_stream_t *    stream,
                   strmk_sent_t *      ele,
                   fd_pubkey_t const * key,
                   ulong               slot,
                   int                 table ) {
  if( FD_UNLIKELY( !ele  ) ) return 0;
  if( FD_UNLIKELY( ele->slot ) ) return 1;
  ele->key  = *key;
  ele->slot = slot | fd_ulong_if( table, STRMK_SENT_TABLE, 0UL );
  stream->sent_cnt++;
  return 1;
}

/* strmk_carried_entry returns the entry a block belongs in, which
   either names it or is the free entry it would go in, or NULL if the
   stream remembers as many blocks as it can.  A block is named by its
   bank index and sequence number together, because replay hands the
   same index out again once a block is gone. */

static strmk_carried_t *
strmk_carried_entry( strmk_stream_t * stream,
                     ulong            bank_idx,
                     ulong            bank_seq ) {
  ulong mask = STRMK_CARRIED_MAX-1UL;
  ulong idx  = fd_ulong_hash( bank_idx ^ fd_ulong_hash( bank_seq ) ) & mask;
  for( ulong i=0UL; i<STRMK_CARRIED_MAX; i++ ) {
    strmk_carried_t * ele = &stream->carried[ idx ];
    if( FD_LIKELY( ele->bank_idx==ULONG_MAX ) ) return ele;
    if( FD_UNLIKELY( ele->bank_idx==bank_idx && ele->bank_seq==bank_seq ) ) return ele;
    idx = (idx+1UL) & mask;
  }
  return NULL;
}

/* strmk_carried_test returns 1 if the stream carried that block. */

static int
strmk_carried_test( strmk_stream_t * stream,
                    ulong            bank_idx,
                    ulong            bank_seq ) {
  strmk_carried_t const * ele = strmk_carried_entry( stream, bank_idx, bank_seq );
  return ele && ele->bank_idx!=ULONG_MAX;
}

/* strmk_carried_insert records that the stream carried a block.
   Returns 0 if the stream has no room left to remember it. */

static int
strmk_carried_insert( strmk_stream_t * stream,
                      ulong            bank_idx,
                      ulong            bank_seq ) {
  strmk_carried_t * ele = strmk_carried_entry( stream, bank_idx, bank_seq );
  if( FD_UNLIKELY( !ele ) ) return 0;
  ele->bank_idx = bank_idx;
  ele->bank_seq = bank_seq;
  return 1;
}

/**********************************************************************/
/* Stream pool                                                        */
/**********************************************************************/

/* strmk_msg_publish publishes one message on strmk_out.  A pass can
   publish one per stream, so the file server is woken once at the end
   of it rather than per message. */

static void
strmk_msg_publish( fd_strmk_t *        ctx,
                   fd_stem_context_t * stem,
                   ulong               msg_type,
                   ulong               sz ) {
  ulong chunk = ctx->out.chunk;
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->out.out_idx, msg_type, chunk, sz, 0UL, 0UL, tspub );
  ctx->out.chunk     = fd_dcache_compact_next( chunk, sz, ctx->out.chunk0, ctx->out.wmark );
  ctx->out.published = 1;
}

/* strmk_msg_flush hands the file server everything the pass
   published. */

static void
strmk_msg_flush( fd_strmk_t *        ctx,
                 fd_stem_context_t * stem ) {
  if( FD_LIKELY( !ctx->out.published ) ) return;
  ctx->out.published = 0;
  fd_backup_out_wake( ctx->out.seq_prod, stem->seqs[ ctx->out.out_idx ] );
}

/* strmk_bank_release gives a bank reference back to replay by handing
   its token back.  Replay ignores a token it minted before a reset. */

static void
strmk_bank_release( fd_strmk_t *        ctx,
                    fd_stem_context_t * stem,
                    ulong               hold_token ) {
  fd_stem_publish( stem, ctx->replay_out_idx, hold_token, 0UL, 0UL, 0UL, 0UL, 0UL );
}

/* strmk_index_write rewrites the index, which names one listed stream
   per line, newest first: a peer takes the first line it can use.  The
   file is rewritten in place because the file server holds it open and
   would not see a replacement; a reader that catches the file empty
   retries. */

static void
strmk_index_write( fd_strmk_t * ctx ) {
  char  line [ STRMK_INDEX_LINE_MAX ];
  uchar index[ FD_STRMK_STREAM_MAX*STRMK_INDEX_LINE_MAX ];
  ulong index_sz = 0UL;

  uint  order[ FD_STRMK_STREAM_MAX ];
  ulong cnt = 0UL;
  for( uint i=0U; i<ctx->stream_max; i++ ) {
    if( FD_LIKELY( !ctx->stream[ i ].open || !ctx->stream[ i ].listed ) ) continue;
    ulong at = cnt++;
    for( ; at && ctx->stream[ order[ at-1UL ] ].start_slot<ctx->stream[ i ].start_slot; at-- ) {
      order[ at ] = order[ at-1UL ];
    }
    order[ at ] = i;
  }

  for( ulong i=0UL; i<cnt; i++ ) {
    strmk_stream_t const * stream = &ctx->stream[ order[ i ] ];
    char hash_b58[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( stream->hash, NULL, hash_b58 );
    ulong line_sz;
    fd_cstr_printf( line, sizeof(line), &line_sz, "%lu %s %ld\n",
                    stream->start_slot, hash_b58, stream->expires/(1000L*1000L*1000L) );
    memcpy( index+index_sz, line, line_sz );
    index_sz += line_sz;
  }

  if( FD_UNLIKELY( -1==ftruncate( ctx->index_fd, 0L ) ) ) {
    FD_LOG_ERR(( "ftruncate(boot index) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( -1==lseek( ctx->index_fd, 0L, SEEK_SET ) ) ) {
    FD_LOG_ERR(( "lseek(boot index) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( !index_sz ) ) return;
  ulong wrote;
  int   err = fd_io_write( ctx->index_fd, index, index_sz, index_sz, &wrote );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_io_write failed (%i-%s)", err, fd_io_strerror( err ) ));
}

/* strmk_stream_close ends a stream.  A stream that was fully written
   ends with the two zero blocks of an end of archive marker, which
   tells a peer that is still downloading that there is no more; a
   broken one is truncated away instead. */

static int
strmk_stream_close( fd_strmk_t *        ctx,
                    fd_stem_context_t * stem,
                    uint                idx,
                    int                 broken ) {
  strmk_stream_t * stream = &ctx->stream[ idx ];
  if( FD_LIKELY( !stream->open ) ) return 0;

  FD_LOG_INFO(( "closing the boot stream at slot %lu after %ld seconds (%lu bytes, %lu accounts)%s",
                stream->start_slot, ( fd_log_wallclock()-stream->started )/(1000L*1000L*1000L),
                stream->file_sz, stream->sent_cnt, broken ? ", broken" : "" ));

  if( FD_LIKELY( !broken ) ) {
    memset( stream->raw, 0, FD_BACKUP_TAR_END_SZ );
    zip_push( ctx, stream, stream->raw, FD_BACKUP_TAR_END_SZ, ZSTD_e_end );
  }

  int listed = stream->listed;
  stream->open      = 0;
  stream->listed    = 0;
  stream->closed    = fd_log_wallclock();
  stream->sent_cnt  = 0UL;
  stream->sent_full = 0;
  stream->raw_sz    = 0UL;

  /* A stream the file server was never told about has nothing to
     withdraw. */
  if( FD_LIKELY( stream->published ) ) {
    fd_snapmk_msg_t * msg = fd_chunk_to_laddr( ctx->out.mem, ctx->out.chunk );
    msg->deleted = (fd_snapmk_msg_deleted_t) {
      .slot      = stream->start_slot,
      .base_slot = ULONG_MAX,
      .pool_idx  = idx
    };
    fd_strmk_stream_name( msg->deleted.name, idx );
    strmk_msg_publish( ctx, stem, FD_SNAPMK_MSG_DELETED, sizeof(fd_snapmk_msg_deleted_t) );
  }
  stream->published = 0;

  if( FD_UNLIKELY( broken ) ) {
    if( FD_UNLIKELY( -1==ftruncate( stream->fd, 0L ) ) ) {
      FD_LOG_ERR(( "ftruncate(boot stream) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    stream->file_sz = 0UL;
  }
  return listed;
}

/* strmk_close_mask closes the streams in mask and rewrites the index
   once, if one of them was named in it. */

static void
strmk_close_mask( fd_strmk_t *        ctx,
                  fd_stem_context_t * stem,
                  uint                mask,
                  int                 broken ) {
  int listed = 0;
  for( uint i=0U; i<ctx->stream_max; i++ ) {
    if( FD_LIKELY( !( mask & (1U<<i) ) ) ) continue;
    listed |= strmk_stream_close( ctx, stem, i, broken );
  }
  if( FD_UNLIKELY( listed ) ) strmk_index_write( ctx );
}

/* strmk_streams_break closes every stream because a block that a
   stream needs can no longer be written. */

static void
strmk_streams_break( fd_strmk_t *        ctx,
                     fd_stem_context_t * stem ) {
  strmk_close_mask( ctx, stem, (1U<<ctx->stream_max)-1U, 1 );
}

/* strmk_streams_expire closes the streams whose lifetime ran out.
   Returns 1 if any work was done. */

static int
strmk_streams_expire( fd_strmk_t *        ctx,
                      fd_stem_context_t * stem,
                      long                now ) {
  uint mask = 0U;
  for( uint i=0U; i<ctx->stream_max; i++ ) {
    if( FD_LIKELY( !ctx->stream[ i ].open ) ) continue;
    if( FD_LIKELY( now<ctx->stream[ i ].expires ) ) continue;
    mask |= 1U<<i;
  }
  strmk_close_mask( ctx, stem, mask, 0 );
  return !!mask;
}

/* strmk_stream_publish tells the file server how large a stream is. */

static void
strmk_stream_publish( fd_strmk_t *        ctx,
                      fd_stem_context_t * stem,
                      uint                idx ) {
  strmk_stream_t * stream = &ctx->stream[ idx ];
  fd_snapmk_msg_t * msg = fd_chunk_to_laddr( ctx->out.mem, ctx->out.chunk );
  msg->created = (fd_snapmk_msg_created_t) {
    .slot      = stream->start_slot,
    .base_slot = ULONG_MAX,
    .sz        = stream->file_sz,
    .pool_idx  = idx
  };
  fd_strmk_stream_name( msg->created.name, idx );
  strmk_msg_publish( ctx, stem, FD_SNAPMK_MSG_CREATED, sizeof(fd_snapmk_msg_created_t) );
  ctx->stream[ idx ].published = 1;
}

/**********************************************************************/
/* Block keys                                                         */
/**********************************************************************/

/* strmk_block_bank returns the one block in flight at bank_idx.  Keys
   name only the bank index, which is enough because replay ends a
   block before it hands the index out again. */

static strmk_block_t *
strmk_block_bank( fd_strmk_t * ctx,
                  ulong        bank_idx ) {
  if( FD_UNLIKELY( bank_idx>=ctx->bank_max ) ) return NULL;
  uint idx = ctx->bank_block[ bank_idx ];
  if( FD_UNLIKELY( idx==UINT_MAX ) ) return NULL;
  return &ctx->block[ idx ];
}

/* strmk_block_unlive takes a block out of the index of blocks in
   flight, unless a newer block at the same bank has replaced it
   there. */

static void
strmk_block_unlive( fd_strmk_t *          ctx,
                    strmk_block_t const * block ) {
  if( FD_UNLIKELY( block->bank_idx>=ctx->bank_max ) ) return;
  uint idx = (uint)( block-ctx->block );
  if( FD_LIKELY( ctx->bank_block[ block->bank_idx ]==idx ) ) ctx->bank_block[ block->bank_idx ] = UINT_MAX;
}

/* strmk_block_alloc takes a free block entry and clears its account
   set, or returns NULL if every entry is in use. */

static strmk_block_t *
strmk_block_alloc( fd_strmk_t * ctx ) {
  for( ulong i=0UL; i<STRMK_BLOCK_MAX; i++ ) {
    strmk_block_t * block = &ctx->block[ i ];
    if( FD_UNLIKELY( block->state!=STRMK_BLOCK_FREE ) ) continue;
    memset( block->keys->used, 0, sizeof(block->keys->used) );
    block->state    = STRMK_BLOCK_LIVE;
    block->key_cnt  = 0U;
    block->overflow = 0;
    block->linked   = 0;
    return block;
  }
  return NULL;
}

/* strmk_block_release frees a block entry. */

static void
strmk_block_release( fd_strmk_t *    ctx,
                     strmk_block_t * block ) {
  block->state = STRMK_BLOCK_FREE;
  strmk_block_unlive( ctx, block );
}

/* strmk_block_retain keeps a completed block for a stream that opens
   later, dropping the oldest one it kept to make room. */

static void
strmk_block_retain( fd_strmk_t *    ctx,
                    strmk_block_t * block ) {
  if( FD_UNLIKELY( ctx->retain_tail-ctx->retain_head>=STRMK_BLOCK_RETAIN_MAX ) ) {
    strmk_block_release( ctx, &ctx->block[ ctx->retain[ ctx->retain_head%STRMK_BLOCK_RETAIN_MAX ] ] );
    ctx->retain_head++;
  }
  block->state = STRMK_BLOCK_DONE;
  strmk_block_unlive( ctx, block );
  ctx->retain[ ctx->retain_tail%STRMK_BLOCK_RETAIN_MAX ] = (uint)( block-ctx->block );
  ctx->retain_tail++;
}

/* strmk_blocks_drop frees every block entry, kept or in flight. */

static void
strmk_blocks_drop( fd_strmk_t * ctx ) {
  for( ulong i=0UL; i<STRMK_BLOCK_MAX; i++ ) ctx->block[ i ].state = STRMK_BLOCK_FREE;
  for( ulong i=0UL; i<ctx->bank_max;   i++ ) ctx->bank_block[ i ] = UINT_MAX;
  ctx->retain_head   = 0UL;
  ctx->retain_tail   = 0UL;
  ctx->last_end_slot = 0UL;
}

/* strmk_block_key_add adds one account to a block's set, which drops
   the repeats the keys arrive with.  table says the block named it as
   a lookup table replay could not expand, which upgrades a key that
   arrived as an ordinary one.  Marks the block overflowed, and returns
   0, once the set is as full as it gets. */

static int
strmk_block_key_add( strmk_block_t *     block,
                     fd_pubkey_t const * key,
                     int                 table ) {
  if( FD_UNLIKELY( block->overflow ) ) return 0;
  strmk_keyset_t * keys = block->keys;
  uchar kind = (uchar)( table ? STRMK_KEY_TABLE : STRMK_KEY_PLAIN );
  ulong mask = STRMK_BLOCK_SLOT_MAX-1UL;
  ulong idx  = fd_ulong_load_8( key->uc ) & mask;
  for(;;) {
    if( FD_LIKELY( keys->used[ idx ]==STRMK_KEY_FREE ) ) break;
    if( FD_UNLIKELY( fd_memeq( keys->key[ idx ].uc, key->uc, sizeof(fd_pubkey_t) ) ) ) {
      keys->used[ idx ] = fd_uchar_max( keys->used[ idx ], kind );
      return 1;
    }
    idx = (idx+1UL) & mask;
  }
  if( FD_UNLIKELY( block->key_cnt>=STRMK_BLOCK_KEY_MAX ) ) {
    block->overflow = 1;
    return 0;
  }
  keys->used[ idx ] = kind;
  keys->key [ idx ] = *key;
  block->key_cnt++;
  return 1;
}

/**********************************************************************/
/* Account writing                                                    */
/**********************************************************************/

/* strmk_write_key reads one account at fork and adds it to the streams
   in take that have not carried it yet, which probe says.  slot names
   the appendvec they are building.

   force reads the account even when every one of them has it already,
   which is how a lookup table that gained addresses since the stream
   opened still gets them followed.  The streams remember which of the
   keys they carried were tables, so this is on for those keys only.

   out_follow, which holds STRMK_ALUT_ADDR_MAX addresses or is NULL,
   receives the accounts this one implies and that no transaction
   names: the program data account of an upgradeable program, or the
   addresses of an address lookup table that replay could not expand.
   Returns how many it wrote.  Flushes an overflow file for a stream
   whose raw buffer filled up. */

static ulong
strmk_write_key( fd_strmk_t *          ctx,
                 uint                  take,
                 strmk_probe_t const * probe,
                 int                   force,
                 fd_accdb_fork_id_t    fork,
                 fd_pubkey_t const *   key,
                 ulong                 slot,
                 fd_pubkey_t *         out_follow ) {
  int wanted = probe->wanted;
  if( FD_LIKELY( !wanted && !force ) ) return 0UL;

  ulong lamports   = 0UL;
  ulong data_len   = 0UL;
  int   executable = 0;
  uchar owner[ 32 ];
  int   source = fd_accdb_read_one_nocache( ctx->accdb, fork, key->uc,
                                            &lamports, &executable, owner,
                                            ctx->acc_data, &data_len );
  if( FD_UNLIKELY( source==FD_ACCDB_READ_ONE_NOCACHE_MISS ) ) {
    /* An account that does not exist is carried as a zero lamport
       record, so that a peer does not go looking for it. */
    lamports   = 0UL;
    data_len   = 0UL;
    executable = 0;
    memcpy( owner, fd_solana_system_program_id.uc, sizeof(fd_pubkey_t) );
  }
  FD_CHECK_CRIT( data_len<=FD_RUNTIME_ACC_SZ_MAX, "accdb returned an oversized account" );

  int is_table = lamports && fd_memeq( owner, fd_solana_address_lookup_table_program_id.uc, sizeof(fd_pubkey_t) );

  ulong rec_sz = sizeof(snap_acc_hdr_t) + fd_ulong_align_up( data_len, 8UL );
  for( uint i=0U; wanted && i<ctx->stream_max; i++ ) {
    strmk_stream_t * stream = &ctx->stream[ i ];
    strmk_sent_t *   ele    = probe->ele[ i ];
    if( FD_LIKELY( !( take & (1U<<i) ) ) ) continue;
    if( FD_UNLIKELY( ele && ele->slot ) ) continue;
    if( FD_UNLIKELY( sizeof(fd_tar_meta_t)+stream->raw_sz+rec_sz>STRMK_RAW_BUF_SZ ) ) {
      strmk_appendvec_flush( ctx, stream, slot, ++stream->vec_id );
    }
    stream->raw_sz += strmk_encode_account( stream->raw + sizeof(fd_tar_meta_t) + stream->raw_sz,
                                            stream->start_slot, key, lamports, executable, owner,
                                            ctx->acc_data, data_len );
    if( FD_UNLIKELY( !strmk_sent_insert( stream, ele, key, slot, is_table ) ) ) stream->sent_full = 1;
  }

  if( FD_LIKELY( !out_follow || !lamports ) ) return 0UL;

  /* An upgradeable program is useless without its program data
     account, which no transaction names. */
  if( FD_UNLIKELY( fd_memeq( owner, fd_solana_bpf_loader_upgradeable_program_id.uc, sizeof(fd_pubkey_t) ) ) ) {
    fd_bpf_state_t state[1];
    if( FD_LIKELY( !fd_bpf_state_decode( state, ctx->acc_data, data_len ) &&
                   state->discriminant==FD_BPF_STATE_PROGRAM ) ) {
      out_follow[ 0 ] = state->inner.program.programdata_address;
      return 1UL;
    }
    return 0UL;
  }

  /* Replay hands over the address of a lookup table it could not
     expand, so the tile expands it: a transaction names an address by
     a byte index, so nothing past the first STRMK_ALUT_ADDR_MAX of
     them can be reached. */
  if( FD_UNLIKELY( is_table ) ) {
    if( FD_UNLIKELY( data_len<FD_LOOKUP_TABLE_META_SIZE ) ) return 0UL;
    ulong cnt = fd_ulong_min( ( data_len-FD_LOOKUP_TABLE_META_SIZE )/sizeof(fd_pubkey_t), STRMK_ALUT_ADDR_MAX );
    memcpy( out_follow, ctx->acc_data+FD_LOOKUP_TABLE_META_SIZE, cnt*sizeof(fd_pubkey_t) );
    return cnt;
  }

  return 0UL;
}

/* strmk_write_account writes one account a block named and the
   accounts it implies: the program data of an upgradeable program, the
   addresses of an address lookup table, and the program data of those.
   Nothing is followed past that, which is as far as a transaction can
   reach.

   table says a block named this account as a lookup table replay
   could not expand, in which case its addresses have to come from
   here whether or not the streams carry the table already: the table
   may not even have existed at their slot.  The mark the streams keep
   on the tables they carried is the fallback for a table that arrived
   as an ordinary key, which is how replay sends one it did expand. */

static void
strmk_write_account( fd_strmk_t *        ctx,
                     uint                take,
                     fd_accdb_fork_id_t  fork,
                     fd_pubkey_t const * key,
                     ulong               slot,
                     int                 table ) {
  strmk_probe_t probe[1];
  strmk_sent_probe( ctx, take, key, probe );
  ulong cnt = strmk_write_key( ctx, take, probe, table||probe->table, fork, key, slot, ctx->follow[ 0 ] );
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_pubkey_t next = ctx->follow[ 0 ][ i ];
    strmk_sent_probe( ctx, take, &next, probe );
    ulong deep = strmk_write_key( ctx, take, probe, 0, fork, &next, slot, ctx->follow[ 1 ] );
    for( ulong j=0UL; j<deep; j++ ) {
      fd_pubkey_t leaf = ctx->follow[ 1 ][ j ];
      strmk_sent_probe( ctx, take, &leaf, probe );
      strmk_write_key( ctx, take, probe, 0, fork, &leaf, slot, NULL );
    }
  }
}

/**********************************************************************/
/* Block writing                                                      */
/**********************************************************************/

/* strmk_fork_live checks that the fork a block names is still the one
   its parent bank holds.  Replay drops the holds it handed out when it
   resets, while block ends it published before the reset are still
   ahead of the reset in the queue, so a block can name a fork that has
   since been reclaimed. */

static int
strmk_fork_live( fd_strmk_t *          ctx,
                 strmk_block_t const * block ) {
  if( FD_UNLIKELY( block->parent_bank_seq==ULONG_MAX ) ) return 0;
  fd_bank_t * parent = fd_banks_bank_query( ctx->banks, block->parent_bank_idx );
  if( FD_UNLIKELY( !parent ) ) return 0;
  if( FD_UNLIKELY( FD_VOLATILE_CONST( parent->bank_seq )!=block->parent_bank_seq ) ) return 0;
  ulong state = FD_VOLATILE_CONST( parent->state );
  if( FD_UNLIKELY( state==FD_BANK_STATE_DEAD || state==FD_BANK_STATE_PRUNABLE ) ) return 0;
  return 1;
}

/* strmk_block_takers gives the streams a block belongs in: the ones
   whose start slot is its parent, or that already carried its parent.
   A block that chains off something a stream does not have is simply
   not that stream's block. */

static uint
strmk_block_takers( fd_strmk_t *          ctx,
                    strmk_block_t const * block ) {
  uint take = 0U;
  for( uint i=0U; i<ctx->stream_max; i++ ) {
    strmk_stream_t * stream = &ctx->stream[ i ];
    if( FD_LIKELY( !stream->open ) ) continue;
    int root = block->parent_bank_idx==stream->bank_idx && block->parent_bank_seq==stream->bank_seq;
    if( FD_UNLIKELY( root || strmk_carried_test( stream, block->parent_bank_idx, block->parent_bank_seq ) ) ) {
      take |= 1U<<i;
    }
  }
  return take;
}

/* strmk_block_read reads the accounts of one block and stages them for
   the streams in take.  Each account is read once, at the block's
   parent fork.  Returns 0 once that fork turns out to be gone, which
   makes everything staged for the block worthless. */

static int
strmk_block_read( fd_strmk_t *          ctx,
                  uint                  take,
                  strmk_block_t const * block ) {
  strmk_keyset_t const * keys  = block->keys;
  ulong                  since = 0UL;
  /* Most slots of the set are free, so they are skipped eight at a
     time.  The bytes of a word come out lowest first, which is the
     order the slots are in. */
  for( ulong w=0UL; w<STRMK_BLOCK_SLOT_MAX; w+=8UL ) {
    ulong used = fd_ulong_load_8( keys->used+w );
    while( FD_UNLIKELY( used ) ) {
      ulong byte = (ulong)fd_ulong_find_lsb( used )>>3;
      ulong i    = w+byte;
      used &= ~( 0xffUL<<( byte<<3 ) );
      if( FD_UNLIKELY( ++since>=STRMK_FORK_CHECK_KEYS ) ) {
        since = 0UL;
        if( FD_UNLIKELY( !strmk_fork_live( ctx, block ) ) ) return 0;
      }
      strmk_write_account( ctx, take, block->parent_fork, &keys->key[ i ], block->slot,
                           keys->used[ i ]==STRMK_KEY_TABLE );
    }
  }
  return strmk_fork_live( ctx, block );
}

/* strmk_block_flush writes out the appendvec each stream in take
   staged for a block, and records that it carried it.  A stream that
   is still being opened is not told how large it grew, because it is
   not being served yet. */

static void
strmk_block_flush( fd_strmk_t *          ctx,
                   fd_stem_context_t *   stem,
                   uint                  take,
                   int                   publish,
                   strmk_block_t const * block ) {
  int listed = 0;
  for( uint i=0U; i<ctx->stream_max; i++ ) {
    strmk_stream_t * stream = &ctx->stream[ i ];
    if( FD_LIKELY( !( take & (1U<<i) ) || !stream->open ) ) continue;

    /* A block that touched nothing new still gets a file of its own,
       because a peer treats the end of it as the end of the slot and a
       tar entry cannot be empty.  The Instructions sysvar fills it: it
       is built per transaction and never stored, so recording that it
       does not exist is true at every slot and changes nothing. */
    if( FD_UNLIKELY( !stream->raw_sz ) ) {
      stream->raw_sz = strmk_encode_account( stream->raw + sizeof(fd_tar_meta_t), stream->start_slot,
                                             &fd_sysvar_instructions_id, 0UL, 0,
                                             fd_solana_system_program_id.uc, NULL, 0UL );
    }

    strmk_appendvec_flush( ctx, stream, block->slot, 0UL );
    stream->vec_id = 0UL;
    if( FD_UNLIKELY( !strmk_carried_insert( stream, block->bank_idx, block->bank_seq ) ) ) {
      FD_LOG_WARNING(( "the boot stream at slot %lu cannot remember slot %lu, breaking it",
                       stream->start_slot, block->slot ));
      listed |= strmk_stream_close( ctx, stem, i, 1 );
      continue;
    }
    if( FD_UNLIKELY( stream->sent_full ) ) {
      /* An account the stream carried is not in its set, so it would
         skip that account the next time a block touches it. */
      FD_LOG_WARNING(( "the boot stream at slot %lu ran out of sent set entries inside slot %lu, breaking it",
                       stream->start_slot, block->slot ));
      listed |= strmk_stream_close( ctx, stem, i, 1 );
      continue;
    }
    if( FD_UNLIKELY( !publish ) ) continue;
    if( FD_UNLIKELY( stream->sent_cnt>=ctx->key_cap ) ) {
      FD_LOG_WARNING(( "the boot stream at slot %lu carried %lu accounts, which is all "
                       "[snapshots.instant_boot.serve.max_keys_per_stream] allows for",
                       stream->start_slot, stream->sent_cnt ));
      listed |= strmk_stream_close( ctx, stem, i, 0 );
      continue;
    }
    strmk_stream_publish( ctx, stem, i );
  }
  if( FD_UNLIKELY( listed ) ) strmk_index_write( ctx );
}

/* strmk_block_discard throws away what the streams in take staged for
   a block and closes them, because the fork the block was read at
   turned out to be gone.  The streams that did not take the block are
   not affected: the block was never theirs.  Each caller logs its own
   reason first. */

static void
strmk_block_discard( fd_strmk_t *        ctx,
                     fd_stem_context_t * stem,
                     uint                take ) {
  for( uint i=0U; i<ctx->stream_max; i++ ) {
    if( FD_LIKELY( !( take & (1U<<i) ) ) ) continue;
    ctx->stream[ i ].raw_sz = 0UL;
    ctx->stream[ i ].vec_id = 0UL;
  }
  strmk_close_mask( ctx, stem, take, 1 );
}

/* strmk_backlog_link marks the kept blocks that chain back to the bank
   a stream is opening at.  A block whose parent is another kept block
   that does not chain back is on a fork that left the chain below the
   stream's slot, and is simply dropped.  Returns 0 when the kept
   blocks do not cover everything that ran after that bank, in which
   case a stream opening there would be missing blocks and must not be
   served. */

static int
strmk_backlog_link( fd_strmk_t * ctx,
                    ulong        start_slot,
                    ulong        bank_idx,
                    ulong        bank_seq ) {
  /* 1 once a kept block is a child of the stream's slot */
  int have_child = 0;

  for( ulong r=ctx->retain_head; r!=ctx->retain_tail; r++ ) {
    strmk_block_t * block = &ctx->block[ ctx->retain[ r%STRMK_BLOCK_RETAIN_MAX ] ];
    block->linked = 0;
    if( FD_LIKELY( block->slot<=start_slot ) ) continue;

    if( FD_UNLIKELY( block->parent_bank_idx==bank_idx && block->parent_bank_seq==bank_seq ) ) {
      block->linked = 1;
      have_child    = 1;
      continue;
    }

    int kept = 0;
    for( ulong p=ctx->retain_head; p!=r; p++ ) {
      strmk_block_t const * parent = &ctx->block[ ctx->retain[ p%STRMK_BLOCK_RETAIN_MAX ] ];
      if( FD_LIKELY( parent->bank_idx!=block->parent_bank_idx ||
                     parent->bank_seq!=block->parent_bank_seq ) ) continue;
      kept           = 1;
      block->linked |= parent->linked;
    }
    if( FD_UNLIKELY( !kept ) ) {
      FD_LOG_WARNING(( "not starting a boot stream at slot %lu: slot %lu ran after it and the block "
                       "it chains off is no longer kept", start_slot, block->slot ));
      return 0;
    }
  }

  if( FD_UNLIKELY( ctx->last_end_slot>start_slot && !have_child ) ) {
    FD_LOG_WARNING(( "not starting a boot stream at slot %lu: slot %lu already ran and the blocks "
                     "that follow it are not kept", start_slot, ctx->last_end_slot ));
    return 0;
  }
  return 1;
}

/* strmk_backlog_write writes the appendvecs of the kept blocks that
   chain off the stream's slot, in the order they ran, so that they
   come before the blocks the stream carries live.  Returns 0 if one of
   them turned out to be unreadable, which breaks every stream. */

static int
strmk_backlog_write( fd_strmk_t *        ctx,
                     fd_stem_context_t * stem,
                     uint                idx ) {
  strmk_stream_t * stream = &ctx->stream[ idx ];
  uint  take = 1U<<idx;
  ulong cnt  = 0UL;
  for( ulong r=ctx->retain_head; r!=ctx->retain_tail; r++ ) {
    strmk_block_t const * block = &ctx->block[ ctx->retain[ r%STRMK_BLOCK_RETAIN_MAX ] ];
    if( FD_LIKELY( !block->linked ) ) continue;
    if( FD_UNLIKELY( !strmk_fork_live( ctx, block ) || !strmk_block_read( ctx, take, block ) ) ) {
      FD_LOG_WARNING(( "the fork slot %lu was read at is gone, not starting the boot stream at slot %lu",
                       block->slot, stream->start_slot ));
      strmk_block_discard( ctx, stem, take );
      return 0;
    }
    strmk_block_flush( ctx, stem, take, 0, block );
    if( FD_UNLIKELY( !stream->open ) ) return 0;
    cnt++;
  }
  if( FD_UNLIKELY( cnt ) ) {
    FD_LOG_INFO(( "the boot stream at slot %lu starts with the %lu blocks that already ran", stream->start_slot, cnt ));
  }
  return 1;
}

/**********************************************************************/
/* Stream lifecycle                                                   */
/**********************************************************************/

/* strmk_bundle writes the first appendvec of a stream, which holds the
   accounts a booting peer reads before it has executed a block: every
   sysvar, the alpenglow clock a block footer reads and the genesis
   certificate a block start reads, every feature gate, and every vote
   account the manifest names. */

static void
strmk_bundle( fd_strmk_t *       ctx,
              uint               idx,
              fd_bank_t *        bank,
              fd_accdb_fork_id_t fork ) {
  strmk_stream_t * stream = &ctx->stream[ idx ];
  uint             take   = 1U<<idx;

  for( ulong i=0UL; i<FD_SYSVAR_CACHE_ENTRY_CNT; i++ ) {
    strmk_write_account( ctx, take, fork, &fd_sysvar_key_tbl[ i ], stream->start_slot, 0 );
  }

  /* The alpenglow native accounts, which the runtime reads outside any
     transaction and so no block names. */
  static char const * const pda_seed[] = { "alpenclock", "carlgration", "vote_reward_account" };
  for( ulong i=0UL; i<sizeof(pda_seed)/sizeof(pda_seed[ 0 ]); i++ ) {
    fd_pubkey_t pda;
    fd_alpenglow_pda( pda_seed[ i ], &pda );
    strmk_write_account( ctx, take, fork, &pda, stream->start_slot, 0 );
  }

  for( fd_feature_id_t const * id = fd_feature_iter_init();
       !fd_feature_iter_done( id );
       id = fd_feature_iter_next( id ) ) {
    strmk_write_account( ctx, take, fork, &id->id, stream->start_slot, 0 );
  }

  /* The manifest names a vote account for every entry of every epoch
     stakes set it holds, which is more than the writer's epoch maps:
     those drop the accounts with no authorized voter. */
  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );
  ulong              fork_id     = bank->vote_stakes_fork_id;
  ulong              epoch_cnt   = fd_ssmanifest_epoch_cnt( bank );
  for( ulong e=0UL; e<epoch_cnt; e++ ) {
    int kind = fd_ssmanifest_epoch_iter_kind( bank, e );
    for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, fork_id, kind, ctx->vote_stakes_iter );
         !fd_vote_stakes_iter_done( vote_stakes, fork_id, kind, iter );
         fd_vote_stakes_iter_next( vote_stakes, fork_id, kind, iter ) ) {
      fd_pubkey_t vote;
      fd_pubkey_t node;
      fd_vote_stakes_iter_ele( vote_stakes, fork_id, kind, iter, &vote, &node, NULL,
                               NULL, NULL, NULL, NULL, NULL, NULL, NULL );
      strmk_write_account( ctx, take, fork, &vote, stream->start_slot, 0 );
      strmk_write_account( ctx, take, fork, &node, stream->start_slot, 0 );
    }
  }

  strmk_appendvec_flush( ctx, stream, stream->start_slot, 0UL );
  stream->vec_id = 0UL;
}

/* strmk_stream_start opens a stream at the slot of an incremental
   snapshot replay just asked for, writing everything a peer needs
   before the first block.  Returns once the bank is no longer
   needed. */

static void
strmk_stream_start( fd_strmk_t *                    ctx,
                    fd_stem_context_t *             stem,
                    fd_strmk_stream_start_t const * msg,
                    long                            now ) {
  strmk_streams_expire( ctx, stem, now );

  /* A stream file is free once its stream closed, but not straight
     away: the file server learns a stream is gone from a message, and
     a peer in the middle of a download reads the file until it does. */
  uint idx = UINT_MAX;
  for( uint i=0U; i<ctx->stream_max; i++ ) {
    if( FD_UNLIKELY( ctx->stream[ i ].open ) ) continue;
    if( FD_UNLIKELY( now-ctx->stream[ i ].closed<STRMK_REUSE_NS ) ) continue;
    idx = i;
    break;
  }
  if( FD_UNLIKELY( idx==UINT_MAX ) ) {
    FD_LOG_INFO(( "not starting a boot stream at slot %lu, all %u stream files are in use", msg->slot, ctx->stream_max ));
    strmk_bank_release( ctx, stem, msg->hold_token );
    return;
  }

  /* Replay takes its holds back before the reset that follows them
     reaches this tile, so a stream start from before a reset can name
     a bank that is gone, or one replay has since handed out again.
     Neither is fatal: the hold goes back and the start is dropped. */
  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, msg->bank_idx );
  if( FD_UNLIKELY( !bank || !msg->slot || bank->f.slot!=msg->slot ||
                   bank->accdb_fork_id.val==USHORT_MAX ) ) {
    FD_LOG_INFO(( "not starting a boot stream at slot %lu, the bank replay named is gone", msg->slot ));
    strmk_bank_release( ctx, stem, msg->hold_token );
    return;
  }

  fd_pubkey_t const * leader = fd_epoch_leaders_get( fd_bank_epoch_leaders_query( bank, bank->f.epoch ), bank->f.slot );
  if( FD_UNLIKELY( !leader ) ) {
    FD_LOG_WARNING(( "not starting a boot stream at slot %lu, its leader is unknown", msg->slot ));
    strmk_bank_release( ctx, stem, msg->hold_token );
    return;
  }

  fd_accdb_fork_id_t fork = bank->accdb_fork_id;

  /* Nothing is written until the blocks that already ran after this
     slot are known to be covered, so a refused stream leaves no
     file. */
  if( FD_UNLIKELY( !strmk_backlog_link( ctx, msg->slot, msg->bank_idx, bank->bank_seq ) ) ) {
    strmk_bank_release( ctx, stem, msg->hold_token );
    return;
  }

  ulong         slot_history_sz = 0UL;
  uchar const * slot_history    =
      fd_sysvar_cache_data_query( &bank->f.sysvar_cache, fd_sysvar_slot_history_id.uc, &slot_history_sz );
  if( FD_UNLIKELY( !fd_txncache_writer_init( ctx->txncache_writer, ctx->txncache, bank->txncache_fork_id,
                                             bank->f.slot, slot_history, slot_history_sz,
                                             ctx->txncache_arena, ctx->txncache_arena_sz ) ) ) {
    FD_LOG_WARNING(( "not starting a boot stream at slot %lu, the status cache moved under it", msg->slot ));
    strmk_bank_release( ctx, stem, msg->hold_token );
    return;
  }

  strmk_stream_t * stream = &ctx->stream[ idx ];
  stream->open       = 1;
  stream->listed     = 0;
  stream->published  = 0;
  stream->start_slot = msg->slot;
  stream->bank_idx   = msg->bank_idx;
  stream->bank_seq   = bank->bank_seq;
  stream->started    = now;
  /* The lifetime a peer can join within really starts when the stream
     is listed; until then this is the longest it can wait for that. */
  stream->expires    = now + ctx->lifetime;
  stream->file_sz    = 0UL;
  stream->raw_sz     = 0UL;
  stream->vec_id     = 0UL;
  stream->sent_cnt   = 0UL;
  memset( stream->carried, 0xff, sizeof(stream->carried) );
  /* The sent set is cleared here rather than at close, so that a file
     that is never handed out again costs nothing. */
  memset( stream->sent, 0, ctx->key_max*sizeof(strmk_sent_t) );
  fd_blake3_hash( bank->f.lthash.bytes, FD_LTHASH_LEN_BYTES, stream->hash );

  if( FD_UNLIKELY( -1==ftruncate( stream->fd, 0L ) ) ) {
    FD_LOG_ERR(( "ftruncate(boot stream) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( -1==lseek( stream->fd, 0L, SEEK_SET ) ) ) {
    FD_LOG_ERR(( "lseek(boot stream) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  ulong zst_err = ZSTD_CCtx_reset( stream->zst, ZSTD_reset_session_only );
  if( FD_UNLIKELY( ZSTD_isError( zst_err ) ) ) {
    FD_LOG_ERR(( "ZSTD_CCtx_reset failed: %s", ZSTD_getErrorName( zst_err ) ));
  }

  fd_ssmanifest_writer_init( ctx->manifest_writer, bank, leader, ctx->accdb, fork, ctx->acc_data );

  long t0 = fd_log_wallclock();
  strmk_open_entries ( ctx, stream );
  strmk_manifest     ( ctx, stream );
  strmk_status_cache ( ctx, stream );
  strmk_bundle       ( ctx, idx, bank, fork );
  int covered = strmk_backlog_write( ctx, stem, idx );
  strmk_bank_release( ctx, stem, msg->hold_token );
  if( FD_UNLIKELY( !covered ) ) return;

  if( FD_UNLIKELY( stream->sent_full || stream->sent_cnt>=ctx->key_cap ) ) {
    FD_LOG_WARNING(( "the boot stream at slot %lu needed %lu accounts to open, which is all "
                     "[snapshots.instant_boot.serve.max_keys_per_stream] allows for",
                     stream->start_slot, stream->sent_cnt ));
    (void)strmk_stream_close( ctx, stem, idx, 1 );
    return;
  }

  FD_LOG_NOTICE(( "boot stream at slot %lu opened in %ld millis (%lu bytes, %lu accounts)",
                  stream->start_slot, ( fd_log_wallclock()-t0 )/(1000L*1000L), stream->file_sz, stream->sent_cnt ));
  strmk_stream_publish( ctx, stem, idx );
}

/**********************************************************************/
/* Message handling                                                   */
/**********************************************************************/

/* strmk_reset forgets every block and closes every stream.  The banks
   of the blocks it drops are not returned: a reset replay sends has
   already taken them back, and returning one would drop a reference it
   handed out since.  The holds of a reset the tile decides on time out
   at replay instead, which is also what keeps this bounded to one
   message per stream. */

static void
strmk_reset( fd_strmk_t *        ctx,
             fd_stem_context_t * stem ) {
  strmk_blocks_drop( ctx );
  strmk_streams_break( ctx, stem );
}

static void
strmk_block_start( fd_strmk_t *                   ctx,
                   fd_stem_context_t *            stem,
                   fd_strmk_block_start_t const * msg ) {
  FD_CHECK_CRIT( msg->bank_idx<ctx->bank_max, "replay named a bank outside its pool" );
  if( FD_UNLIKELY( strmk_block_bank( ctx, msg->bank_idx ) ) ) {
    FD_LOG_WARNING(( "bank %lu started slot %lu while it still held a block, resetting the boot streams",
                     msg->bank_idx, msg->slot ));
    strmk_reset( ctx, stem );
  }
  strmk_block_t * block = strmk_block_alloc( ctx );
  if( FD_UNLIKELY( !block ) ) {
    FD_LOG_WARNING(( "more than %lu blocks in flight at slot %lu, resetting the boot streams", STRMK_BLOCK_LIVE_MAX, msg->slot ));
    strmk_reset( ctx, stem );
    /* The reset gave up the holds the dropped blocks owed, but not
       this one, which the pool had no room to record. */
    strmk_bank_release( ctx, stem, msg->hold_token );
    return;
  }
  block->slot            = msg->slot;
  block->bank_idx        = msg->bank_idx;
  block->bank_seq        = msg->bank_seq;
  block->parent_bank_idx = msg->parent_bank_idx;
  block->hold_token      = msg->hold_token;
  ctx->bank_block[ msg->bank_idx ] = (uint)( block-ctx->block );
}

/* strmk_keys_ok rejects a key message that names more keys than the
   link can carry, which would read past the frag. */

static int
strmk_keys_ok( fd_strmk_t *                ctx,
               fd_stem_context_t *         stem,
               fd_strmk_txn_keys_t const * msg ) {
  if( FD_LIKELY( (ulong)msg->key_cnt<=FD_STRMK_TXN_KEY_MAX ) ) return 1;
  FD_LOG_WARNING(( "slot %lu named %hu accounts in one message, resetting the boot streams",
                   msg->slot, msg->key_cnt ));
  strmk_reset( ctx, stem );
  return 0;
}

/* strmk_txn_keys takes the accounts a block named.  table says they
   are lookup tables replay could not expand, which the tile expands
   itself when it writes the block. */

static void
strmk_txn_keys( fd_strmk_t *                ctx,
                fd_stem_context_t *         stem,
                fd_strmk_txn_keys_t const * msg,
                int                         table ) {
  if( FD_UNLIKELY( !strmk_keys_ok( ctx, stem, msg ) ) ) return;
  strmk_block_t * block = strmk_block_bank( ctx, msg->bank_idx );
  if( FD_UNLIKELY( !block ) ) return;
  for( ulong i=0UL; i<(ulong)msg->key_cnt; i++ ) strmk_block_key_add( block, &msg->keys[ i ], table );
}

static void
strmk_block_end( fd_strmk_t *                 ctx,
                 fd_stem_context_t *          stem,
                 fd_strmk_block_end_t const * msg,
                 int                          dead ) {
  strmk_block_t * block = strmk_block_bank( ctx, msg->bank_idx );
  if( FD_UNLIKELY( !block || block->bank_seq!=msg->bank_seq ) ) return;

  if( FD_UNLIKELY( dead ) ) {
    strmk_bank_release( ctx, stem, block->hold_token );
    strmk_block_release( ctx, block );
    return;
  }

  ctx->last_end_slot = fd_ulong_max( ctx->last_end_slot, msg->slot );

  /* The fee collector is credited at block end without a transaction
     naming it.  Replay leaves it zero when it knows no leader for the
     block, and the all-zero address is the system program, which no
     stream needs carried as a fee collector. */
  if( FD_LIKELY( !fd_pubkey_check_zero( &msg->collector ) ) ) {
    strmk_block_key_add( block, &msg->collector, 0 );
  }
  if( FD_UNLIKELY( block->overflow ) ) {
    FD_LOG_WARNING(( "slot %lu touched more than %lu accounts, resetting the boot streams", msg->slot, STRMK_BLOCK_KEY_MAX ));
    strmk_bank_release( ctx, stem, block->hold_token );
    strmk_block_release( ctx, block );
    strmk_streams_break( ctx, stem );
    return;
  }

  block->parent_fork     = msg->parent_accdb_fork_id;
  block->parent_bank_seq = msg->parent_bank_seq;

  uint take = strmk_block_takers( ctx, block );
  if( FD_UNLIKELY( !take ) ) {
    /* No stream has this block's parent, so the block is on a chain
       none of them follows. */
    strmk_bank_release( ctx, stem, block->hold_token );
    strmk_block_retain( ctx, block );
    return;
  }

  if( FD_UNLIKELY( !strmk_fork_live( ctx, block ) || !strmk_block_read( ctx, take, block ) ) ) {
    FD_LOG_WARNING(( "the fork slot %lu was read at is gone, breaking the boot streams that needed it", block->slot ));
    strmk_bank_release( ctx, stem, block->hold_token );
    strmk_block_discard( ctx, stem, take );
    strmk_block_release( ctx, block );
    return;
  }

  /* The accounts are read, so replay can root past the parent now; the
     rest of this is compression and file writes. */
  strmk_bank_release( ctx, stem, block->hold_token );
  strmk_block_flush( ctx, stem, take, 1, block );

  /* The block is kept so that a stream opening at a slot below it can
     still cover it. */
  strmk_block_retain( ctx, block );
}

/* strmk_snapmk lists a stream once the incremental snapshot it chains
   off exists, which is what makes it usable to a peer. */

static void
strmk_snapmk( fd_strmk_t *                    ctx,
              fd_snapmk_msg_created_t const * msg ) {
  /* a full snapshot starts no stream */
  if( FD_LIKELY( msg->base_slot==ULONG_MAX ) ) return;
  int listed = 0;
  for( uint i=0U; i<ctx->stream_max; i++ ) {
    strmk_stream_t * stream = &ctx->stream[ i ];
    if( FD_LIKELY( !stream->open || stream->listed || stream->start_slot!=msg->slot ) ) continue;
    /* A peer can only join a stream once it is in the index, so the
       lifetime it is served for starts here, not when it opened. */
    stream->listed  = 1;
    stream->expires = fd_log_wallclock() + ctx->lifetime;
    listed          = 1;
    FD_LOG_NOTICE(( "serving the boot stream at slot %lu", stream->start_slot ));
  }
  if( FD_UNLIKELY( listed ) ) strmk_index_write( ctx );
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
  if( FD_LIKELY( sz ) ) fd_memcpy( ctx->frag, fd_chunk_to_laddr_const( ctx->in_mem[ in_idx ], chunk ), sz );
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
  (void)sz; (void)tsorig; (void)tspub;

  if( FD_UNLIKELY( in_idx==ctx->snapmk_in_idx ) ) {
    if( FD_LIKELY( sig==FD_SNAPMK_MSG_CREATED ) ) {
      strmk_snapmk( ctx, &( (fd_snapmk_msg_t const *)ctx->frag )->created );
    }
    return;
  }

  /* The link is unreliable, so a tile that fell behind has missed
     blocks and has to start over. */
  if( FD_UNLIKELY( ctx->replay_seq_next!=ULONG_MAX && seq!=ctx->replay_seq_next ) ) {
    FD_LOG_WARNING(( "the boot stream feed skipped %ld frags, resetting the boot streams",
                     fd_seq_diff( seq, ctx->replay_seq_next ) ));
    strmk_reset( ctx, stem );
  }
  ctx->replay_seq_next = fd_seq_inc( seq, 1UL );

  switch( sig ) {
  case FD_STRMK_SIG_BLOCK_START:
    strmk_block_start( ctx, stem, (fd_strmk_block_start_t const *)ctx->frag );
    break;
  case FD_STRMK_SIG_TXN_KEYS:
    strmk_txn_keys( ctx, stem, (fd_strmk_txn_keys_t const *)ctx->frag, 0 );
    break;
  case FD_STRMK_SIG_TXN_TABLES:
    strmk_txn_keys( ctx, stem, (fd_strmk_txn_keys_t const *)ctx->frag, 1 );
    break;
  case FD_STRMK_SIG_BLOCK_END:
    strmk_block_end( ctx, stem, (fd_strmk_block_end_t const *)ctx->frag, 0 );
    break;
  case FD_STRMK_SIG_BLOCK_DEAD:
    strmk_block_end( ctx, stem, (fd_strmk_block_end_t const *)ctx->frag, 1 );
    break;
  case FD_STRMK_SIG_STREAM_START:
    strmk_stream_start( ctx, stem, (fd_strmk_stream_start_t const *)ctx->frag, fd_log_wallclock() );
    break;
  case FD_STRMK_SIG_RESET:
    strmk_reset( ctx, stem );
    break;
  default:
    FD_LOG_CRIT(( "unexpected boot stream message %lu", sig ));
  }

  strmk_msg_flush( ctx, stem );
}

static void
after_credit( fd_strmk_t *        ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)opt_poll_in;
  if( FD_LIKELY( stem->now<ctx->expire_check ) ) return;
  ctx->expire_check = stem->now + (long)( (double)STRMK_EXPIRE_CHECK_NS*ctx->tick_per_ns );
  *charge_busy = strmk_streams_expire( ctx, stem, fd_log_wallclock() );
  strmk_msg_flush( ctx, stem );
}

/**********************************************************************/
/* Tile setup                                                         */
/**********************************************************************/

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_strmk_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_strmk_t), sizeof(fd_strmk_t) );
  memset( ctx, 0, sizeof(fd_strmk_t) );

  FD_TEST( tile->strmk.max_open_streams && tile->strmk.max_open_streams<=FD_STRMK_STREAM_MAX );
  ctx->stream_max = (uint)tile->strmk.max_open_streams;

  char dir_path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( dir_path, PATH_MAX, NULL, "%s/%s", tile->strmk.snapshots_path, FD_STRMK_DIR ) );
  ctx->dir_fd   = fd_strmk_dir_open( dir_path );
  ctx->index_fd = FD_STRMK_FD( ctx->stream_max );

  char name[ FD_SNAP_NAME_MAX ];
  for( uint i=0U; i<ctx->stream_max; i++ ) {
    fd_strmk_file_open( ctx->dir_fd, dir_path, fd_strmk_stream_name( name, i ), O_RDWR, FD_STRMK_FD( i ) );
  }
  fd_strmk_file_open( ctx->dir_fd, dir_path, FD_STRMK_INDEX, O_RDWR, ctx->index_fd );

  /* Nothing from a previous run is served: a stream cannot be resumed,
     and the index would name streams that are gone. */
  for( uint i=0U; i<strmk_file_cnt( ctx ); i++ ) {
    if( FD_UNLIKELY( -1==ftruncate( FD_STRMK_FD( i ), 0L ) ) ) {
      FD_LOG_ERR(( "ftruncate() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
  }

  /* The tile writes the files after it drops to the configured user,
     so they belong to that user, like the snapshot pool does. */
  if( FD_UNLIKELY( -1==fchown( ctx->dir_fd, tile->strmk.target_uid, tile->strmk.target_gid ) ) ) {
    FD_LOG_ERR(( "fchown(%s) failed (%i-%s)", dir_path, errno, fd_io_strerror( errno ) ));
  }
  for( uint i=0U; i<strmk_file_cnt( ctx ); i++ ) {
    if( FD_UNLIKELY( -1==fchown( FD_STRMK_FD( i ), tile->strmk.target_uid, tile->strmk.target_gid ) ) ) {
      FD_LOG_ERR(( "fchown(%s) failed (%i-%s)", dir_path, errno, fd_io_strerror( errno ) ));
    }
  }
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_strmk_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_UNLIKELY( out_fds_cnt<5UL+(ulong)ctx->stream_max ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = ctx->dir_fd;
  out_fds[ out_cnt++ ] = FD_ACCDB_FD_RO;
  /* the streams and the index */
  for( uint i=0U; i<strmk_file_cnt( ctx ); i++ ) out_fds[ out_cnt++ ] = FD_STRMK_FD( i );
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
      (uint)FD_STRMK_FD( 0 ), (uint)FD_STRMK_FD( ctx->stream_max ),
      (uint)FD_ACCDB_FD_RO );
  return sock_filter_policy_fd_strmk_tile_instr_cnt;
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch        = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  ulong  max_live_slots = tile->strmk.max_live_slots;
  ulong  stream_max     = tile->strmk.max_open_streams;
  ulong  key_max        = strmk_key_max( tile );
  ulong  zst_sz         = ZSTD_estimateCStreamSize( FD_BACKUP_ZSTD_LEVEL );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_strmk_t * ctx       = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_strmk_t),              sizeof(fd_strmk_t) );
  void *       _txncache = FD_SCRATCH_ALLOC_APPEND( l, fd_txncache_align(),              fd_txncache_footprint( max_live_slots ) );
  void *       _accdb    = FD_SCRATCH_ALLOC_APPEND( l, fd_accdb_align(),                 fd_accdb_footprint( max_live_slots, 0 ) );
  void *       _arena    = FD_SCRATCH_ALLOC_APPEND( l, fd_txncache_writer_arena_align(), fd_txncache_writer_arena_sz( tile->strmk.max_txn_per_slot ) );
  void *       _acc_data = FD_SCRATCH_ALLOC_APPEND( l, 16UL,                             FD_RUNTIME_ACC_SZ_MAX );
  void *       _comp     = FD_SCRATCH_ALLOC_APPEND( l, 16UL,                             STRMK_COMP_BUF_SZ );
  void *       _keys     = FD_SCRATCH_ALLOC_APPEND( l, alignof(strmk_keyset_t),          STRMK_BLOCK_MAX*sizeof(strmk_keyset_t) );
  void *       _banks    = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                    max_live_slots*sizeof(uint) );
  void *       _raw      = FD_SCRATCH_ALLOC_APPEND( l, 4096UL,                           stream_max*STRMK_RAW_BUF_SZ );
  void *       _sent     = FD_SCRATCH_ALLOC_APPEND( l, alignof(strmk_sent_t),            stream_max*key_max*sizeof(strmk_sent_t) );
  void *       _zst      = FD_SCRATCH_ALLOC_APPEND( l, 64UL,                             stream_max*zst_sz );
  ulong end = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  FD_CHECK_CRIT( end==(ulong)scratch + scratch_footprint( tile ), "bug when calculating tile memory layout" );

  ctx->key_max           = key_max;
  ctx->key_cap           = ( key_max*STRMK_SENT_LOAD_NUM )/STRMK_SENT_LOAD_DEN;
  ctx->lifetime          = (long)tile->strmk.stream_lifetime_seconds*1000L*1000L*1000L;
  ctx->tick_per_ns       = fd_tempo_tick_per_ns( NULL );
  /* the first frag starts no gap */
  ctx->replay_seq_next   = ULONG_MAX;
  ctx->acc_data          = _acc_data;
  ctx->comp              = _comp;
  ctx->txncache_arena    = _arena;
  ctx->txncache_arena_sz = fd_txncache_writer_arena_sz( tile->strmk.max_txn_per_slot );

  for( ulong i=0UL; i<STRMK_BLOCK_MAX; i++ ) ctx->block[ i ].keys = (strmk_keyset_t *)_keys + i;
  ctx->bank_block = _banks;
  ctx->bank_max   = max_live_slots;
  memset( ctx->bank_block, 0xff, max_live_slots*sizeof(uint) );

  for( uint i=0U; i<ctx->stream_max; i++ ) {
    strmk_stream_t * stream = &ctx->stream[ i ];
    stream->fd   = FD_STRMK_FD( i );
    stream->raw  = (uchar *)_raw  + (ulong)i*STRMK_RAW_BUF_SZ;
    stream->sent = (strmk_sent_t *)_sent + (ulong)i*key_max;
    stream->zst  = ZSTD_initStaticCStream( (uchar *)_zst + (ulong)i*zst_sz, zst_sz );
    FD_TEST( stream->zst );
    ulong zst_err = ZSTD_CCtx_setParameter( stream->zst, ZSTD_c_compressionLevel, FD_BACKUP_ZSTD_LEVEL );
    if( FD_UNLIKELY( ZSTD_isError( zst_err ) ) ) {
      FD_LOG_ERR(( "ZSTD_CCtx_setParameter failed: %s", ZSTD_getErrorName( zst_err ) ));
    }
    memset( stream->sent, 0, key_max*sizeof(strmk_sent_t) );
  }

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

  FD_CHECK_ERR( tile->in_cnt==2UL, "the stream tile needs the replay_strmk and snapmk_out links" );
  ctx->snapmk_in_idx = ULONG_MAX;
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if( FD_UNLIKELY( strcmp( link->name, "replay_strmk" ) && strcmp( link->name, "snapmk_out" ) ) ) {
      FD_LOG_ERR(( "unexpected input link \"%s\"", link->name ));
    }
    FD_TEST( link->dcache );
    ctx->in_mem   [ i ] = fd_wksp_containing( link->dcache );
    FD_TEST( ctx->in_mem[ i ] );
    ctx->in_chunk0[ i ] = fd_dcache_compact_chunk0( ctx->in_mem[ i ], link->dcache );
    ctx->in_wmark [ i ] = fd_dcache_compact_wmark ( ctx->in_mem[ i ], link->dcache, link->mtu );
    ctx->in_mtu   [ i ] = link->mtu;
    FD_CHECK_ERR( link->mtu<=sizeof(ctx->frag), "input link MTU too large" );
    if( FD_UNLIKELY( !strcmp( link->name, "snapmk_out" ) ) ) ctx->snapmk_in_idx = i;
  }
  FD_CHECK_ERR( ctx->snapmk_in_idx!=ULONG_MAX, "missing snapmk_out link" );

  /* The tile asks replay for banks on strmk_replay and tells the file
     server about stream files on strmk_out. */
  ctx->replay_out_idx = fd_topo_find_tile_out_link( topo, tile, "strmk_replay", 0UL );
  FD_CHECK_ERR( ctx->replay_out_idx!=ULONG_MAX, "missing strmk_replay link" );
  ulong out_idx = fd_topo_find_tile_out_link( topo, tile, "strmk_out", 0UL );
  FD_CHECK_ERR( out_idx!=ULONG_MAX, "missing strmk_out link" );
  fd_topo_link_t const * out_link = &topo->links[ tile->out_link_id[ out_idx ] ];
  FD_CHECK_ERR( out_link->mtu>=sizeof(fd_snapmk_msg_t), "strmk_out link MTU too small" );
  ctx->out.out_idx  = out_idx;
  ctx->out.mem      = fd_wksp_containing( out_link->dcache );
  ctx->out.chunk0   = fd_dcache_compact_chunk0( ctx->out.mem, out_link->dcache );
  ctx->out.wmark    = fd_dcache_compact_wmark ( ctx->out.mem, out_link->dcache, out_link->mtu );
  ctx->out.chunk    = ctx->out.chunk0;
  ctx->out.seq_prod = fd_mcache_seq_laddr( out_link->mcache );
}

/* One STREAM_START can expire every stream, open one and give a bank
   back. */

#define STEM_BURST (FD_STRMK_STREAM_MAX+2UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_strmk_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_strmk_t)
#define STEM_CALLBACK_AFTER_CREDIT  after_credit
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

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

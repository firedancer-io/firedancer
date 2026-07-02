#define _GNU_SOURCE
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

#include "fd_backup.h"
#include "fd_backup_cache.h"
#include "fd_backup_visited.h"
#include "fd_ssmanifest_writer.h"
#include "fd_txncache_writer.h"
#include "../replay/fd_replay_tile.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../tango/fseq/fd_fseq.h"

#define FD_ZSTD_LEVEL 1
#define RAW_BUF_SZ    (32UL<<20)
#define COMP_BUF_SZ   ZSTD_COMPRESSBOUND( RAW_BUF_SZ )

/* FD_SNAPMK_ZP_DEPTH must match the snapmk_zp link depth in topology.c.
   Asserted at init.  Sizes the per-link snaprd-seq shadow rings. */
#define FD_SNAPMK_ZP_DEPTH 1024UL

#define SNAPMK_STEM_BURST 1UL
#define SNAPMK_STEM_LAZY  8700UL

/* fd_snapmk_accparse_t does streaming zero-copy parsing of accdb
   partitions.  Ingests a stream of disk data (arbitrarily fragmented)
   and produces an account-aligned fragment stream. */

struct fd_snapmk_accparse {

  union __attribute__((packed)) {
    uchar buf[ sizeof(fd_accdb_disk_meta_t) ];
    fd_accdb_disk_meta_t meta;
  };

  uchar const * data;
  ulong         data_sz;
  ulong         src_gaddr;
  ulong         src_off;
  ulong         frag_base_gaddr; /* src_gaddr at start of current frag */
  uchar const * pf_cursor;       /* sequential-prefetch high-water mark within current frag */
  int           input_active;

  uint meta_sz;
  int  acc_active;
  uint acc_off;
  uint acc_sz;
  uint acc_snap_sz;
  uint acc_idx;
  uint acc_keep;

  ulong acc_file_off;

  ulong pub_gaddr;
  ulong pub_off;
  uint  pub_sz;
  uint  pub_acc_idx;
  uint  pub_snap_sz;
  uint  pub_size;
  fd_pubkey_t pub_pubkey;
  fd_pubkey_t pub_owner;
  int   pub_pending;
  int   pub_som;
  int   pub_eom;

  uint const *               acc_map;
  fd_accdb_accmeta_t const * acc_pool;
  visited_set_t *            visited_set;
  ulong                      max_accounts;
  ulong                      acc_seed;
  ulong                      acc_chain_mask;
  uint                       root_generation;

  /* Prestaged disk batch (see fd_snapmk_accparse_prestage).  ps_cnt!=0
     iff a batch is buffered; always consumed before the streaming
     single-account path runs, so it never outlives the snaprd frag it
     was staged from. */
  uint        ps_cnt;
  ulong       ps_base_gaddr;
  uint        ps_head    [ FD_BACKUP_DISK_PARA ];
  uint        ps_frag_off[ FD_BACKUP_DISK_PARA ];
  ulong       ps_file_off[ FD_BACKUP_DISK_PARA ];
  fd_pubkey_t ps_pubkey  [ FD_BACKUP_DISK_PARA ];
  ulong       accounts_seen;
};

typedef struct fd_snapmk_accparse fd_snapmk_accparse_t;

struct fd_snapmk {
  uint state;

  fd_backup_cache_t acc_cache[1];
  visited_set_t *   visited_set;

  int  out_fd;
  int  snap_dir_fd;
  char out_path  [ PATH_MAX ];
  char snap_dir  [ PATH_MAX ];
  char final_name[ FD_BACKUP_NAME_MAX ];
  char wip_name  [ FD_BACKUP_NAME_MAX ];

  ulong            zp_cnt; /* [0,zp_cnt] out links are to zp */
  ulong const *    zp_cons_fseq[ SNAPZP_TILE_MAX ];
  ulong volatile * zp_file_off;
  ulong *          accdb_epoch_idx;

  /* snaprd input lifetime management.  snapmk takes manual ownership of
     the flow control credit it returns to snaprd so that snaprd does not
     overwrite dcache slots whose bytes are still referenced (zero-copy)
     by in-flight frags queued at the zp tiles.  The stem is redirected to
     publish its parse cursor into stem_snaprd_fseq (a throwaway), while
     snapmk publishes the lagging release watermark to snaprd_release_fseq
     (the real fseq object snaprd waits on).  See snapmk_run. */
  ulong *          snaprd_release_fseq;
  ulong            stem_snaprd_fseq[1];
  ulong            snaprd_parse_seq;  /* seq of the snaprd frag last parsed */
  ulong            snaprd_release_seq;/* last watermark published to snaprd */

  /* per zp out link shadow ring: rd_shadow[i][seq%depth] = snaprd seq
     referenced by the mk_zp frag published at seq on link i */
  ulong *          rd_shadow[ SNAPZP_TILE_MAX ];
  ulong            zp_depth [ SNAPZP_TILE_MAX ];

  ulong in_idle_cnt;

  ulong out_meta_idx;
  ulong out_ready;         /* bit set */
  ulong out_flush_pending; /* bit set */
  ulong out_catchup_seq[ SNAPZP_TILE_MAX ];
  ulong out_flush_seq  [ SNAPZP_TILE_MAX ];

  fd_banks_t *    banks;
  fd_bank_t *     bank;
  fd_txncache_t * txncache;
  fd_wksp_t *     replay_in_mem;
  fd_wksp_t *     snaprd_in_mem;
  ulong           snaprd_in_mtu;
  fd_ssmanifest_writer_t manifest_writer[1];
  fd_txncache_writer_t   txncache_writer[1];
  fd_accdb_shmem_t * accdb_shmem;

  ulong manifest_pad;
  ulong status_cache_pad;
  long  start_time;

  /* IPC */
  struct {
    void * mem;
    ulong  chunk0;
    ulong  wmark;
    ulong  chunk;
  } zp_out[ FD_TOPO_MAX_TILE_OUT_LINKS ];
  fd_backup_cache_msg_t scan_batch[1];
  ushort                in_kind   [ FD_TOPO_MAX_TILE_IN_LINKS  ];
  fd_snapmk_accparse_t  accparse[1];

  /* disk batch staging (FD_BACKUP_ORIG_ACC_DISK_BATCH).  A batch is
     staged out of the parser, then flushed to a zp tile once an output
     link has credit.  disk_batch_pending guards against re-staging while
     a staged batch is awaiting credit. */
  fd_backup_disk_batch_msg_t disk_batch[1];
  ulong                      disk_batch_base_gaddr;
  int                        disk_batch_pending;

  ulong                disk_out_idx;
  ulong                rr_out; /* round-robin cursor over zp out links */
  uint                 drain_next_state;

  /* account data cache */
  uchar * cache    [ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong   cache_max[ FD_ACCDB_CACHE_CLASS_CNT ];

  /* accdb root fork */
  fd_accdb_fork_shmem_t const * accdb_shfork;
  fd_accdb_fork_id_t const *    accdb_root_fork;

  /* output buffer */
  ZSTD_CCtx *    zst;
  ZSTD_inBuffer  raw_buf;
  ZSTD_outBuffer comp_buf;
  uchar raw [ RAW_BUF_SZ  ];
  uchar comp[ COMP_BUF_SZ ];

  struct {
    ulong accounts_seen;
    ulong data_read_bytes;
    ulong compress_ticks;
    ulong io_ticks;
    ulong bytes_compressed;
    ulong bytes_written;
    ulong disk_batches_emitted;
    ulong disk_accounts_single;

    ulong accparse_accounts_seen;
    struct {
      ulong accounts_seen;
      ulong data_read_bytes;
      ulong bytes_compressed;
      ulong bytes_written;
    } snapshot;
  } metrics;
};

typedef struct fd_snapmk fd_snapmk_t;

static inline void
fd_snapmk_accparse_reset( fd_snapmk_accparse_t *     parse,
                          uint const *               acc_map,
                          fd_accdb_accmeta_t const * acc_pool,
                          visited_set_t *            visited_set,
                          ulong                      max_accounts,
                          ulong                      acc_seed,
                          ulong                      acc_chain_mask,
                          ulong                      root_generation ) {
  *parse = (fd_snapmk_accparse_t) {
    .acc_keep        = 1U,
    .acc_map         = acc_map,
    .acc_pool        = acc_pool,
    .visited_set     = visited_set,
    .max_accounts    = max_accounts,
    .acc_seed        = acc_seed,
    .acc_chain_mask  = acc_chain_mask,
    .root_generation = (uint)root_generation
  };
}

static inline void
metrics_snapshot_clear( fd_snapmk_t * ctx ) {
  ctx->metrics.snapshot.accounts_seen    = 0UL;
  ctx->metrics.snapshot.data_read_bytes  = 0UL;
  ctx->metrics.snapshot.bytes_compressed = 0UL;
  ctx->metrics.snapshot.bytes_written    = 0UL;
  FD_MGAUGE_SET( SNAPMK, SNAPSHOT_ACCOUNTS_SEEN,                    0UL );
  FD_MGAUGE_SET( SNAPMK, SNAPSHOT_DATA_READ_BYTES,                 0UL );
  FD_MGAUGE_SET( SNAPMK, SNAPSHOT_UNCOMPRESSED_DATA_WRITTEN_BYTES, 0UL );
  FD_MGAUGE_SET( SNAPMK, SNAPSHOT_COMPRESSED_DATA_WRITTEN_BYTES,   0UL );
}

static inline void
metrics_accounts_seen_add( fd_snapmk_t * ctx,
                           ulong         cnt ) {
  ctx->metrics.accounts_seen          += cnt;
  ctx->metrics.snapshot.accounts_seen += cnt;
}

static inline void
metrics_data_read_add( fd_snapmk_t * ctx,
                       ulong         bytes ) {
  ctx->metrics.data_read_bytes          += bytes;
  ctx->metrics.snapshot.data_read_bytes += bytes;
}

static inline void
metrics_raw_written_add( fd_snapmk_t * ctx,
                         ulong         bytes ) {
  ctx->metrics.bytes_compressed          += bytes;
  ctx->metrics.snapshot.bytes_compressed += bytes;
}

static inline void
metrics_compressed_written_add( fd_snapmk_t * ctx,
                                ulong         bytes ) {
  ctx->metrics.bytes_written          += bytes;
  ctx->metrics.snapshot.bytes_written += bytes;
}

static inline void
metrics_accparse_seen_sync( fd_snapmk_t * ctx ) {
  ulong accounts_seen = ctx->accparse->accounts_seen;
  ulong delta         = accounts_seen - ctx->metrics.accparse_accounts_seen;
  ctx->metrics.accparse_accounts_seen = accounts_seen;
  metrics_accounts_seen_add( ctx, delta );
}

static inline int
fd_snapmk_accparse_keep( fd_snapmk_accparse_t * parse ) {
  ulong hash = fd_accdb_hash( parse->meta.pubkey, parse->acc_seed ) & parse->acc_chain_mask;
  uint acc_idx = FD_VOLATILE_CONST( parse->acc_map[ hash ] );

  while( acc_idx!=UINT_MAX ) {
    if( FD_UNLIKELY( (ulong)acc_idx>=parse->max_accounts ) ) {
      return 0;
    }

    fd_accdb_accmeta_t const * acc = &parse->acc_pool[ acc_idx ];
    uint  next_idx    = FD_VOLATILE_CONST( acc->map.next );
    uint  generation  = FD_VOLATILE_CONST( acc->key.generation );
    ulong offset_fork = FD_VOLATILE_CONST( acc->offset_fork );

    if( FD_LIKELY( !memcmp( acc->key.pubkey, parse->meta.pubkey, sizeof(parse->meta.pubkey) ) ) ) {
      if( FD_LIKELY( generation<=parse->root_generation ) ) {
        ulong cur_off = offset_fork & FD_ACCDB_OFF_MASK;
        if( FD_LIKELY( cur_off==parse->acc_file_off ) ) {
          if( FD_UNLIKELY( fd_backup_visited_test( parse->visited_set, (ulong)acc_idx ) ) ) {
            return 0;
          }
          fd_backup_visited_insert( parse->visited_set, (ulong)acc_idx );
          parse->acc_idx = acc_idx;
          return 1;
        }
      }
    }

    acc_idx = next_idx;
  }

  return 0;
}

/* fd_snapmk_accparse_insert ingests a contiguous source data frag at
   data in the local address space, and src_gaddr workspace-relative. */

static inline void
fd_snapmk_accparse_insert( fd_snapmk_accparse_t * parse,
                           uchar const *          data,
                           ulong                  data_sz,
                           ulong                  src_gaddr,
                           ulong                  src_off ) {
  parse->data      = data;
  parse->data_sz   = data_sz;
  parse->src_gaddr = src_gaddr;
  parse->src_off   = src_off;
  parse->frag_base_gaddr = src_gaddr;
  parse->pf_cursor = data;
  parse->input_active = 1;
}

/* fd_snapmk_accparse_publish produces an account-aligned frag from
   accumulated source data.  Should be called after each accparse_insert
   calls.  Returns meta if a frag was produced, NULL otherwise.
   meta->sig set to the wksp-relative pos.  meta->tspub is the account
   data byte count for this frag.  meta->ctl.som=1 set if this is the
   first frag of an account, meta->ctl.eom=1 set if it's the last (both
   if the frag fully contains the account). */

static inline fd_frag_meta_t *
fd_snapmk_accparse_publish( fd_snapmk_accparse_t * parse,
                            fd_frag_meta_t *       meta ) {
  for(;;) {
    if( FD_UNLIKELY( parse->pub_pending ) ) {
      meta->sig    = parse->pub_gaddr;
      meta->chunk  = parse->pub_acc_idx;
      meta->sz     = 0;
      meta->ctl    = (ushort)fd_frag_meta_ctl( FD_BACKUP_ORIG_ACC_DISK, parse->pub_som, parse->pub_eom, 0 );
      meta->tsorig = 0U;
      meta->tspub  = (uint)parse->pub_sz;
      parse->pub_pending = 0;
      return meta;
    }

    if( FD_UNLIKELY( !parse->data_sz ) ) return NULL;

    if( FD_UNLIKELY( !parse->acc_active ) ) {
      if( FD_UNLIKELY( !parse->meta_sz ) ) {
        parse->acc_file_off = parse->src_off;
        parse->acc_snap_sz  = 0U;
        parse->acc_idx      = UINT_MAX;
        parse->acc_keep     = 1U;
      }

      ulong meta_rem = sizeof(fd_accdb_disk_meta_t) - (ulong)parse->meta_sz;
      ulong take     = fd_ulong_min( meta_rem, parse->data_sz );
      fd_memcpy( parse->buf + parse->meta_sz, parse->data, take );
      parse->meta_sz   += (uint)take;
      parse->data      += take;
      parse->data_sz   -= take;
      parse->src_gaddr += take;
      parse->src_off   += take;

      if( FD_UNLIKELY( parse->meta_sz < sizeof(fd_accdb_disk_meta_t) ) ) continue;

      ulong data_sz = (ulong)FD_ACCDB_SIZE_DATA( parse->meta.size );
      ulong snap_sz = sizeof(snap_acc_hdr_t) + fd_ulong_align_up( data_sz, 8UL );
      if( FD_UNLIKELY( data_sz>UINT_MAX ) ) {
        FD_LOG_CRIT(( "accdb disk account data too large (%lu bytes)", data_sz ));
      }
      if( FD_UNLIKELY( snap_sz>UINT_MAX ) ) {
        FD_LOG_CRIT(( "snapshot account record too large (%lu bytes)", snap_sz ));
      }

      parse->accounts_seen++;
      parse->acc_active  = 1;
      parse->acc_off     = 0U;
      parse->acc_sz      = (uint)data_sz;
      parse->acc_snap_sz = (uint)snap_sz;
      parse->meta_sz     = 0U;
      parse->acc_keep    = (uint)fd_snapmk_accparse_keep( parse );

      if( FD_UNLIKELY( !parse->acc_sz ) ) {
        if( FD_LIKELY( parse->acc_keep ) ) {
          parse->pub_gaddr   = 0UL;
          parse->pub_off     = parse->src_off;
          parse->pub_sz      = 0U;
          parse->pub_acc_idx = parse->acc_idx;
          parse->pub_snap_sz = parse->acc_snap_sz;
          parse->pub_size    = parse->meta.size;
          memcpy( &parse->pub_pubkey, parse->meta.pubkey, sizeof(fd_pubkey_t) );
          memcpy( &parse->pub_owner,  parse->meta.owner,  sizeof(fd_pubkey_t) );
          parse->pub_som     = 1;
          parse->pub_eom     = 1;
          parse->pub_pending = 1;
        }
        parse->acc_active = 0;
        parse->acc_off    = 0U;
        parse->acc_sz     = 0U;
        continue;
      }

      continue;
    }

    ulong acc_rem = (ulong)parse->acc_sz - (ulong)parse->acc_off;
    ulong take    = fd_ulong_min( acc_rem, parse->data_sz );
    if( FD_UNLIKELY( !take ) ) return NULL;

    if( FD_UNLIKELY( !parse->acc_keep ) ) {
      parse->acc_off   += (uint)take;
      parse->data      += take;
      parse->data_sz   -= take;
      parse->src_gaddr += take;
      parse->src_off   += take;
      if( FD_UNLIKELY( parse->acc_off==parse->acc_sz ) ) {
        parse->acc_active = 0;
        parse->acc_off    = 0U;
        parse->acc_sz     = 0U;
        parse->acc_keep   = 1U;
      }
      continue;
    }

    uint old_acc_off = parse->acc_off;
    parse->pub_gaddr   = parse->src_gaddr;
    parse->pub_off     = parse->src_off;
    parse->pub_sz      = (uint)take;
    parse->pub_acc_idx = parse->acc_idx;
    parse->pub_snap_sz = parse->acc_snap_sz;
    parse->pub_size    = parse->meta.size;
    memcpy( &parse->pub_pubkey, parse->meta.pubkey, sizeof(fd_pubkey_t) );
    memcpy( &parse->pub_owner,  parse->meta.owner,  sizeof(fd_pubkey_t) );
    parse->pub_som     = !old_acc_off;
    parse->pub_eom     = ( old_acc_off + take )==parse->acc_sz;
    parse->pub_pending = 1;

    parse->acc_off   += (uint)take;
    parse->data      += take;
    parse->data_sz   -= take;
    parse->src_gaddr += take;
    parse->src_off   += take;

    if( FD_UNLIKELY( parse->pub_eom ) ) {
      parse->acc_active = 0;
      parse->acc_sz     = 0U;
      parse->acc_off    = 0U;
    }
  }

}

/* fd_snapmk_accparse_keep_batch resolves a batch of staged disk accounts
   to their in-memory account index, walking all hash chains in lockstep
   (one chain hop per round) so the acc_pool loads of a round issue
   independently.

   The staged pubkey determines the hash bucket before this function is
   called.  Candidates must be rooted (generation<=root_generation) and be
   the on-disk copy the index currently points at (offset_fork low bits ==
   the account's file offset).  The visited-set dedup is then applied
   in lane order (lane n's insert is visible to lane n+1's test, which is
   what catches intra-batch duplicates).  acc_idx[n] is set to the
   resolved index or UINT_MAX. */

static void
fd_snapmk_accparse_keep_batch( fd_snapmk_accparse_t * parse,
                               ulong const *          file_off,
                               uint const *           head,
                               uint *                 acc_idx,
                               ulong                  cnt ) {
  fd_accdb_accmeta_t const * acc_pool     = parse->acc_pool;
  ulong                      max_accounts = parse->max_accounts;
  uint                       root_gen     = parse->root_generation;

  uint matched[ FD_BACKUP_DISK_PARA ];
  for( ulong n=0UL; n<FD_BACKUP_DISK_PARA; n++ ) matched[ n ] = UINT_MAX;

  /* lane[i]/cur[i]: compacted live-lane list, lane index and the chain
     node it sits on.  head[] was loaded (and prefetched) when the
     batch was prestaged, a full batch resolve ago. */
  uint  lane[ FD_BACKUP_DISK_PARA ];
  uint  cur [ FD_BACKUP_DISK_PARA ];

  ulong active_cnt = 0UL;
  for( ulong n=0UL; n<cnt; n++ ) {
    uint h    = head[ n ];
    uint live = ( h!=UINT_MAX ) & ( (ulong)h<max_accounts );
    lane[ active_cnt ] = (uint)n;
    cur [ active_cnt ] = h;
    active_cnt += live;
  }

  while( active_cnt ) {
    /* One chain hop per live lane; hit/next are resolved in the same
       pass, so the next-node prefetch only fires for lanes that
       continue.  Lanes that hit or exhaust their chain drop out via
       branchless compaction (next_cnt<=i). */
    ulong next_cnt = 0UL;
    for( ulong i=0UL; i<active_cnt; i++ ) {
      uint n    = lane[ i ];
      uint idx  = cur [ i ];
      fd_accdb_accmeta_t const * m = &acc_pool[ idx ];
      uint  next = FD_VOLATILE_CONST( m->map.next       );
      uint  gen  = FD_VOLATILE_CONST( m->key.generation );
      ulong off  = FD_VOLATILE_CONST( m->offset_fork    );
      uint hit  = ( gen<=root_gen )
                & ( ( off & FD_ACCDB_OFF_MASK )==file_off[ n ] );
      uint hm   = 0U-hit;
      matched[ n ] = ( idx & hm ) | ( matched[ n ] & ~hm );
      uint cont = ( hit^1U ) & ( next!=UINT_MAX ) & ( (ulong)next<max_accounts );
      __builtin_prefetch( &acc_pool[ next & ( 0U-cont ) ], 0, 0 );
      lane[ next_cnt ] = n;
      cur [ next_cnt ] = next;
      next_cnt += cont;
    }
    active_cnt = next_cnt;
  }

  for( ulong n=0UL; n<FD_BACKUP_DISK_PARA; n++ ) {
    uint  idx  = matched[ n ];
    uint  have = idx!=UINT_MAX;
    ulong safe = (ulong)( idx & ( 0U-have ) );
    uint  keep = have & (uint)!fd_backup_visited_test( parse->visited_set, safe );
    fd_backup_visited_insert_if( parse->visited_set, (int)keep, safe );
    acc_idx[ n ] = idx | ( keep-1U );
  }
}

/* fd_snapmk_accparse_prestage stages the next batch of wholly-contained
   accounts out of the current frag: a record walk (pubkey copy, hash,
   acc_map prefetch) followed by a head pass (acc_map[hash] lookup,
   acc_pool prefetch).  The chain walk itself happens one publish later
   in fd_snapmk_accparse_publish_batch.  No-op if a batch is already
   staged or the parser is not at a clean account boundary. */

static void
fd_snapmk_accparse_prestage( fd_snapmk_accparse_t * parse ) {
  if( FD_UNLIKELY( parse->ps_cnt ) ) return;
  /* Only batch at a clean account boundary with no straddle carry. */
  if( FD_UNLIKELY( parse->pub_pending || parse->acc_active || parse->meta_sz ) ) return;

  ulong const meta_sz = sizeof(fd_accdb_disk_meta_t);
  ulong hash[ FD_BACKUP_DISK_PARA ];
  ulong seed       = parse->acc_seed;
  uint  chain_mask = (uint)parse->acc_chain_mask;
  uint const *               acc_map  = parse->acc_map;
  fd_accdb_accmeta_t const * acc_pool = parse->acc_pool;
  ulong n = 0UL;

  while( n<FD_BACKUP_DISK_PARA ) {
    if( parse->data_sz < meta_sz ) break; /* partial meta straddles frag end */

    /* Prefetch a fixed FD_SNAPMK_PF_LEAD-byte window ahead of the record
       cursor.  pf_cursor is a per-frag high-water mark, so each line is
       prefetched only once. */
    #define FD_SNAPMK_PF_LEAD 4096UL
    uchar const * pf_lim = parse->data + fd_ulong_min( parse->data_sz, FD_SNAPMK_PF_LEAD );
    uchar const * pf     = fd_ptr_if( parse->pf_cursor>parse->data, parse->pf_cursor, parse->data );
    for( ; pf<pf_lim; pf+=64UL ) __builtin_prefetch( pf, 0, 2 );
    parse->pf_cursor = pf_lim;

    fd_accdb_disk_meta_t const * dm = (fd_accdb_disk_meta_t const *)parse->data;
    ulong data_len = (ulong)FD_ACCDB_SIZE_DATA( dm->size );
    ulong rec      = meta_sz + data_len;
    if( parse->data_sz < rec ) break;     /* account data straddles frag end */

    fd_memcpy( parse->ps_pubkey[ n ].uc, dm->pubkey, sizeof(fd_pubkey_t) );
    hash[ n ] = fd_accdb_hash( parse->ps_pubkey[ n ].uc, seed ) & chain_mask;
    __builtin_prefetch( &acc_map[ hash[ n ] ], 0, 0 );
    parse->ps_frag_off[ n ] = (uint)( parse->src_gaddr - parse->frag_base_gaddr );
    parse->ps_file_off[ n ] = parse->src_off;
    n++;

    parse->data      += rec;
    parse->data_sz   -= rec;
    parse->src_gaddr += rec;
    parse->src_off   += rec;
  }

  /* Head pass: acc_map lines were prefetched during the record walk
     above; prefetch the acc_pool[head] lines here. */
  ulong max_accounts = parse->max_accounts;
  for( ulong i=0UL; i<n; i++ ) {
    uint head = FD_VOLATILE_CONST( acc_map[ hash[ i ] ] );
    uint live = ( head!=UINT_MAX ) & ( (ulong)head<max_accounts );
    __builtin_prefetch( &acc_pool[ head & ( 0U-live ) ], 0, 0 );
    parse->ps_head[ i ] = head;
  }

  parse->ps_cnt        = (uint)n;
  parse->ps_base_gaddr = parse->frag_base_gaddr;
  parse->accounts_seen += n;
}

static ulong
fd_snapmk_accparse_publish_batch( fd_snapmk_accparse_t *       parse,
                                  fd_backup_disk_batch_msg_t * batch,
                                  ulong *                      base_gaddr ) {
  fd_snapmk_accparse_prestage( parse ); /* no-op unless prestage empty */

  ulong n = (ulong)parse->ps_cnt;
  if( !n ) return 0UL;

  /* Move batch N out of the prestage buffer, then stage N+1 before
     resolving N so N+1's prefetches overlap N's chain walk below. */
  uint  head    [ FD_BACKUP_DISK_PARA ];
  ulong file_off[ FD_BACKUP_DISK_PARA ];
  memcpy( head,            parse->ps_head,     n*sizeof(uint)        );
  memcpy( file_off,        parse->ps_file_off, n*sizeof(ulong)       );
  memcpy( batch->frag_off, parse->ps_frag_off, n*sizeof(uint)        );
  memcpy( batch->pubkey,   parse->ps_pubkey,   n*sizeof(fd_pubkey_t) );
  *base_gaddr   = parse->ps_base_gaddr;
  parse->ps_cnt = 0U;

  fd_snapmk_accparse_prestage( parse );

  fd_snapmk_accparse_keep_batch( parse, file_off, head, batch->acc_idx, n );
  for( ulong i=n; i<FD_BACKUP_DISK_PARA; i++ ) batch->acc_idx[ i ] = UINT_MAX;

  return n;
}

#define IN_KIND_REPLAY 1
#define IN_KIND_SNAPRD 2

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( fd_ulong_max( alignof(fd_snapmk_t), 32UL ), fd_txncache_align() );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong max_live_slots = tile->snapmk.max_live_slots;

  ulong zp_cnt = tile->out_cnt - 1UL; /* last out link is snapmk_replay */

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapmk_t), sizeof(fd_snapmk_t)                       );
  l = FD_LAYOUT_APPEND( l, 32UL,                 ZSTD_estimateCStreamSize( FD_ZSTD_LEVEL ) );
  l = FD_LAYOUT_APPEND( l, fd_txncache_align(),  fd_txncache_footprint( max_live_slots )   );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),       zp_cnt*FD_SNAPMK_ZP_DEPTH*sizeof(ulong)   );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  FD_SCRATCH_ALLOC_INIT( l, fd_topo_obj_laddr( topo, tile->tile_obj_id ) );
  fd_snapmk_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapmk_t), sizeof(fd_snapmk_t) );
  memset( ctx, 0, sizeof(fd_snapmk_t) );

  fd_cstr_ncpy( ctx->snap_dir, tile->snapmk.out_path, PATH_MAX );
  char * last_slash = strrchr( ctx->snap_dir, '/' );
  if( FD_LIKELY( last_slash ) ) *last_slash = '\0';

  int dir_fd = open( ctx->snap_dir, O_RDONLY|O_DIRECTORY );
  if( FD_UNLIKELY( dir_fd<0 ) ) {
    FD_LOG_ERR(( "open(%s) failed: %s", ctx->snap_dir, fd_io_strerror( errno ) ));
  }
  ctx->snap_dir_fd = dir_fd;
  ctx->out_fd      = -1;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_snapmk_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_UNLIKELY( out_fds_cnt<4UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = ctx->snap_dir_fd;
  out_fds[ out_cnt++ ] = FD_ACCDB_FD_RO; /* accounts db readonly fd */
  return out_cnt;
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  ulong max_live_slots = tile->snapmk.max_live_slots;

  ulong zp_cnt = tile->out_cnt - 1UL;

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapmk_t * ctx      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapmk_t), sizeof(fd_snapmk_t) );
  void *        _zstd    = FD_SCRATCH_ALLOC_APPEND( l, 32UL,                 ZSTD_estimateCStreamSize( FD_ZSTD_LEVEL ) );
  void *        _txnc_lj = FD_SCRATCH_ALLOC_APPEND( l, fd_txncache_align(),  fd_txncache_footprint( max_live_slots ) );
  ulong *       _rd_shdw = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),       zp_cnt*FD_SNAPMK_ZP_DEPTH*sizeof(ulong) );
  ulong end = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  FD_TEST( end==(ulong)scratch + scratch_footprint( tile ) );

  for( ulong i=0UL; i<zp_cnt; i++ ) {
    ctx->rd_shadow[ i ] = _rd_shdw + i*FD_SNAPMK_ZP_DEPTH;
    ctx->zp_depth [ i ] = FD_SNAPMK_ZP_DEPTH;
  }
  ctx->stem_snaprd_fseq[0] = 0UL;
  ctx->snaprd_parse_seq    = 0UL;
  ctx->snaprd_release_seq  = ULONG_MAX; /* force first publish */

  ctx->state = SNAPMK_STATE_IDLE;
  ctx->visited_set = visited_set_join( fd_topo_obj_laddr( topo, tile->snapmk.visited_set_obj_id ) );
  FD_TEST( ctx->visited_set );

  ulong banks_obj_id = tile->snapmk.banks_obj_id;
  FD_TEST( banks_obj_id!=ULONG_MAX );
  ctx->banks = fd_banks_join( fd_topo_obj_laddr( topo, banks_obj_id ) );
  FD_TEST( ctx->banks );

  fd_txncache_shmem_t * tc_shmem = fd_txncache_shmem_join( fd_topo_obj_laddr( topo, tile->snapmk.txncache_obj_id ) );
  FD_TEST( tc_shmem );
  ctx->txncache = fd_txncache_join( fd_txncache_new( _txnc_lj, tc_shmem ) );
  FD_TEST( ctx->txncache );

  ulong * zp_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, tile->snapmk.zp_fseq_id ) ); FD_TEST( zp_fseq );
  ctx->zp_file_off = fd_fseq_app_laddr( zp_fseq );

  void * _accdb_shmem = fd_topo_obj_laddr( topo, tile->snapmk.accdb_obj_id );
  fd_accdb_shmem_t * accdb_shmem_ro = fd_accdb_shmem_join( _accdb_shmem );
  FD_TEST( accdb_shmem_ro );
  ctx->accdb_shmem = accdb_shmem_ro;
  ulong * epoch_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, tile->snapmk.accdb_epoch_fseq_obj_id ) );
  FD_TEST( epoch_fseq );
  ctx->accdb_epoch_idx = epoch_fseq;
  FD_VOLATILE( *ctx->accdb_epoch_idx ) = ULONG_MAX;
  fd_backup_cache_join( ctx->acc_cache, accdb_shmem_ro );
  {
    FD_SCRATCH_ALLOC_INIT( l, accdb_shmem_ro );
    FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_SHMEM_ALIGN, sizeof(fd_accdb_shmem_t) );
    ctx->accdb_shfork = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_fork_shmem_t), max_live_slots*sizeof(fd_accdb_fork_shmem_t) );
  }
  ctx->accdb_root_fork = &accdb_shmem_ro->root_fork_id;

  for( ulong i=0UL; i < tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if( 0==strcmp( link->name, "replay_out" ) ) {
      FD_TEST( !ctx->in_kind[ i ] );
      ctx->in_kind[ i ] = IN_KIND_REPLAY;
      fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];
      ctx->replay_in_mem = link_wksp->wksp;
    } else if( 0==strcmp( link->name, "snaprd_out" ) ) {
      FD_TEST( !ctx->in_kind[ i ] );
      ctx->in_kind[ i ] = IN_KIND_SNAPRD;
      fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];
      ctx->snaprd_in_mem = link_wksp->wksp;
      ctx->snaprd_in_mtu = link->mtu;
      /* Take manual ownership of the credit we return to snaprd.  The
         stem is redirected (see snapmk_run) to publish its parse cursor
         into the throwaway stem_snaprd_fseq, while we drive the real fseq
         (snaprd_release_fseq) to the lagging release watermark. */
      FD_TEST( tile->in_link_fseq[ i ] );
      ctx->snaprd_release_fseq = tile->in_link_fseq[ i ];
    } else {
      FD_LOG_ERR(( "Unexpected input link \"%s\"", link->name ));
    }
  }

  /* snaprd_release_fseq is required: the disk phase drives it as snaprd's
     flow control credit.  Fail loudly at boot rather than NULL-deref in
     snapmk_update_release if the snaprd_out link is missing. */
  FD_TEST( ctx->snaprd_release_fseq );
  FD_TEST( ctx->snaprd_in_mtu && ctx->snaprd_in_mtu<=UINT_MAX );

  FD_TEST( tile->out_cnt >= 2 );
  FD_TEST( tile->out_cnt <= SNAPZP_TILE_MAX );
  ctx->zp_cnt = tile->out_cnt - 1UL;
  for( ulong i=0UL; i < ctx->zp_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ i ] ];
    if( 0!=strcmp( link->name, "snapmk_zp" ) ) {
      FD_LOG_ERR(( "Unexpected output link \"%s\"", link->name ));
    }
    FD_TEST( link->mcache );
    FD_TEST( fd_mcache_depth( link->mcache )==FD_SNAPMK_ZP_DEPTH );
    ctx->zp_out[ i ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->zp_out[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->zp_out[ i ].mem, link->dcache );
    ctx->zp_out[ i ].wmark  = fd_dcache_compact_wmark ( ctx->zp_out[ i ].mem, link->dcache, link->mtu );
    ctx->zp_out[ i ].chunk  = ctx->zp_out[ i ].chunk0;

    for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
      fd_topo_tile_t const * consumer = &topo->tiles[ j ];
      for( ulong k=0UL; k<consumer->in_cnt; k++ ) {
        if( FD_LIKELY( consumer->in_link_id[ k ]!=tile->out_link_id[ i ] ) ) continue;
        if( FD_UNLIKELY( !consumer->in_link_reliable[ k ] ) ) continue;
        FD_TEST( !ctx->zp_cons_fseq[ i ] );
        ctx->zp_cons_fseq[ i ] = consumer->in_link_fseq[ k ];
      }
    }
    FD_TEST( ctx->zp_cons_fseq[ i ] );
  }
  ctx->out_meta_idx = tile->out_cnt - 1UL;
  if( 0!=strcmp( topo->links[ tile->out_link_id[ ctx->out_meta_idx ] ].name, "snapmk_replay" ) ) {
    FD_LOG_ERR(( "Unexpected output link \"%s\"", topo->links[ tile->out_link_id[ ctx->out_meta_idx ] ].name ));
  }

  ctx->zst = ZSTD_initStaticCStream( _zstd, ZSTD_estimateCStreamSize( FD_ZSTD_LEVEL ) );
  FD_TEST( ctx->zst );
  ulong zst_err;
  zst_err = ZSTD_CCtx_setParameter( ctx->zst, ZSTD_c_compressionLevel, FD_ZSTD_LEVEL );
  if( FD_UNLIKELY( ZSTD_isError( zst_err ) ) ) {
    FD_LOG_ERR(( "ZSTD_CCtx_setParameter(ZSTD_c_compressionLevel) failed: %s", ZSTD_getErrorName( zst_err ) ));
  }
  ctx->raw_buf  = (ZSTD_inBuffer ){ .src = ctx->raw,  .size = 0UL         };
  ctx->comp_buf = (ZSTD_outBuffer){ .dst = ctx->comp, .size = COMP_BUF_SZ };
}

static void
refresh_zp_flow_control( fd_snapmk_t *             ctx,
                         fd_stem_context_t const * stem ) {
  for( ulong i=0UL; i < ctx->zp_cnt; i++ ) {
    ulong cons_seq = fd_fseq_query( ctx->zp_cons_fseq[ i ] );
    long  in_flight = fd_long_max( fd_seq_diff( stem->seqs[ i ], cons_seq ), 0L );
    ulong cr_avail = fd_ulong_if( in_flight>=(long)stem->depths[ i ], 0UL, stem->depths[ i ]-(ulong)in_flight );
    stem->cr_avail[ i ] = cr_avail;
  }
}

static void
update_flow_control( fd_snapmk_t *             ctx,
                     fd_stem_context_t const * stem ) {
  refresh_zp_flow_control( ctx, stem );

  ulong out_ready = 0UL;
  for( ulong i=0UL; i < ctx->zp_cnt; i++ ) {
    out_ready |= fd_ulong_if( !!stem->cr_avail[ i ], 1UL<<i, 0UL );
  }
  ctx->out_ready = out_ready;
}

/* pick_out_rr returns the next ready zp out link in round-robin order,
   or ULONG_MAX if none are ready.  Rotating (rather than always picking
   the lowest ready index) avoids starving higher-index zp tiles. */

static inline ulong
pick_out_rr( fd_snapmk_t * ctx ) {
  ulong n = ctx->zp_cnt;
  for( ulong k=0UL; k<n; k++ ) {
    ulong idx = ctx->rr_out;
    ctx->rr_out = fd_ulong_if( ctx->rr_out+1UL>=n, 0UL, ctx->rr_out+1UL );
    if( ctx->out_ready & (1UL<<idx) ) return idx;
  }
  return ULONG_MAX;
}

static void
set_zp_catchup_seq( fd_snapmk_t *             ctx,
                    fd_stem_context_t const * stem ) {
  for( ulong i=0UL; i < ctx->zp_cnt; i++ ) ctx->out_catchup_seq[ i ] = stem->seqs[ i ];
}

/* snapmk_stamp_shadow records, for the mk_zp frag about to be published at
   seq `pub_seq` on out link `out_idx`, the snaprd input seq whose dcache
   bytes that frag references zero-copy.  Must be called for every frag
   that references snaprd data (ACC_DISK and ACC_DISK_BATCH).  See the
   shadow-ring lifetime tracker in snapmk_update_release. */

static inline void
snapmk_stamp_shadow( fd_snapmk_t * ctx,
                     ulong         out_idx,
                     ulong         pub_seq ) {
  ctx->rd_shadow[ out_idx ][ pub_seq % ctx->zp_depth[ out_idx ] ] = ctx->snaprd_parse_seq;
}

/* snapmk_update_release recomputes the snaprd release watermark from the
   per-link shadow rings and zp consumer fseqs, then publishes it to the
   real snaprd consumer fseq that snaprd's flow control waits on.

   A zp tile caught up (consumed everything published to it) imposes no
   floor -- this is the deadlock guard, since a tile with queued frags is
   guaranteed to drain.  The release is clamped to our own parse cursor so
   snaprd is never told to free a frag we have not parsed yet.

   Must be called every loop iteration during the disk phase, including
   when backpressured, so the watermark keeps advancing as zp drains. */

static void
snapmk_update_release( fd_snapmk_t *             ctx,
                       fd_stem_context_t const * stem ) {
  ulong release = ctx->snaprd_parse_seq;
  for( ulong i=0UL; i < ctx->zp_cnt; i++ ) {
    ulong cons = fd_fseq_query( ctx->zp_cons_fseq[ i ] );
    ulong pub  = stem->seqs[ i ];
    if( FD_UNLIKELY( !fd_seq_lt( cons, pub ) ) ) continue; /* caught up: no floor */
    /* rd_shadow[cons] is always stamped here: DRAIN leaves every tile
       caught up at disk-phase entry, and a slot is stamped before its
       frag is published.  Must NOT pre-zero rd_shadow to a sentinel --
       fd_seq_lt would treat a large sentinel as older and drag the
       watermark back. */
    ulong floor = ctx->rd_shadow[ i ][ cons % ctx->zp_depth[ i ] ];
    if( fd_seq_lt( floor, release ) ) release = floor;
  }
  if( release!=ctx->snaprd_release_seq ) {
    __atomic_store_n( ctx->snaprd_release_fseq, release, __ATOMIC_RELEASE );
    ctx->snaprd_release_seq = release;
  }
}

static int
accdb_compaction_paused( fd_snapmk_t * ctx,
                         ulong         snapshot_epoch ) {
  fd_accdb_shmem_t const * accdb = ctx->accdb_shmem;
  fd_accdb_partition_t const * partition_pool =
      (fd_accdb_partition_t const *)( (uchar const *)accdb + accdb->partition_pool_off );

  ulong partition_max = FD_VOLATILE_CONST( accdb->partition_max );
  for( ulong partition_idx=0UL; partition_idx<partition_max; partition_idx++ ) {
    fd_accdb_partition_t const * partition = partition_pool_ele_const( partition_pool, partition_idx );

    if( FD_UNLIKELY( FD_VOLATILE_CONST( partition->compacting_now ) ) ) return 0;
    if( FD_UNLIKELY( FD_VOLATILE_CONST( partition->queued ) &&
                     FD_VOLATILE_CONST( partition->compaction_ready_epoch )<snapshot_epoch ) ) return 0;
  }

  return 1;
}

static void
pause_accdb_compaction( fd_snapmk_t * ctx ) {
  ulong snapshot_epoch = FD_VOLATILE_CONST( ctx->accdb_shmem->epoch );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *ctx->accdb_epoch_idx ) = snapshot_epoch;
  FD_HW_MFENCE();

  while( FD_UNLIKELY( !accdb_compaction_paused( ctx, snapshot_epoch ) ) ) FD_YIELD();
}

static void
resume_accdb_compaction( fd_snapmk_t * ctx ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *ctx->accdb_epoch_idx ) = ULONG_MAX;
  FD_COMPILER_MFENCE();
}

/* check_credit is called every run loop iteration */

static void
check_credit( fd_snapmk_t *       ctx,
              fd_stem_context_t * stem,
              int *               charge_busy,
              int *               is_backpressured ) {
  (void)stem; (void)is_backpressured;
  switch( ctx->state ) {
  case SNAPMK_STATE_IDLE:
    // if( ctx->in_idle_cnt++ > 128 ) fd_log_sleep( (long)1e6 );
    *charge_busy = 0;
    *is_backpressured = 0;
    break;
  case SNAPMK_STATE_START:
  case SNAPMK_STATE_ACCOUNTS_CACHE:
  case SNAPMK_STATE_ACCOUNTS_DISK:
    *is_backpressured = 0;
    if( FD_UNLIKELY( ctx->state==SNAPMK_STATE_ACCOUNTS_DISK ) ) {
      /* Advance the release watermark every iteration, including
         backpressured paths, so snaprd keeps getting credit as zp
         drains -- avoids deadlocking the lifetime tracker. */
      snapmk_update_release( ctx, stem );
    }
    /* Refresh cr_avail/out_ready every iteration: stem housekeeping can
       drive cr_avail to 0 without clearing our cached out_ready bit,
       and publishing to such a tile trips the BURST assertion. */
    update_flow_control( ctx, stem );
    if( FD_UNLIKELY( ctx->state==SNAPMK_STATE_ACCOUNTS_DISK && ctx->disk_out_idx<ctx->zp_cnt ) ) {
      if( FD_UNLIKELY( !stem->cr_avail[ ctx->disk_out_idx ] ) ) {
        *is_backpressured = 1;
        return;
      }
      break;
    }
    if( FD_UNLIKELY( !ctx->out_ready ) ) {
      *is_backpressured = 1;
      return;
    }
    break;
  case SNAPMK_STATE_ACCOUNTS_FLUSH1:
  case SNAPMK_STATE_ACCOUNTS_FLUSH2:
  case SNAPMK_STATE_ACCOUNTS_DRAIN:
    refresh_zp_flow_control( ctx, stem );
    ulong const * target_seq = ctx->state==SNAPMK_STATE_ACCOUNTS_DRAIN ? ctx->out_flush_seq : ctx->out_catchup_seq;
    *is_backpressured = 0;
    for( ulong i=0UL; i < ctx->zp_cnt; i++ ) {
      if( FD_LIKELY( !fd_seq_lt( fd_fseq_query( ctx->zp_cons_fseq[ i ] ), target_seq[ i ] ) ) ) continue;
      *is_backpressured = 1;
      return;
    }
    break;
  case SNAPMK_STATE_DONE:
    refresh_zp_flow_control( ctx, stem );
    *is_backpressured = 0;
    if( FD_UNLIKELY( ctx->out_flush_pending ) ) {
      for( ulong i=0UL; i < ctx->zp_cnt; i++ ) {
        if( !fd_ulong_extract_bit( ctx->out_flush_pending, (int)i ) ) continue;
        if( stem->cr_avail[ i ] ) return;
      }
      *is_backpressured = 1;
      return;
    }
    for( ulong i=0UL; i < ctx->zp_cnt; i++ ) {
      if( FD_LIKELY( !fd_seq_lt( fd_fseq_query( ctx->zp_cons_fseq[ i ] ), ctx->out_flush_seq[ i ] ) ) ) continue;
      *is_backpressured = 1;
      return;
    }
    if( FD_UNLIKELY( !stem->cr_avail[ ctx->out_meta_idx ] ) ) {
      *is_backpressured = 1;
      return;
    }
    break;
  }
}

static void
flush_buffer( fd_snapmk_t *     ctx,
              ZSTD_EndDirective directive ) {

  /* Compress chunk */
  long t0 = fd_tickcount();
  ulong ret = ZSTD_compressStream2( ctx->zst, &ctx->comp_buf, &ctx->raw_buf, directive );
  metrics_raw_written_add( ctx, ctx->raw_buf.pos );
  if( FD_UNLIKELY( ZSTD_isError( ret ) ) ) {
    FD_LOG_ERR(( "ZSTD_compressStream2 failed: %s", ZSTD_getErrorName( ret ) ));
  }

  /* Move uncompressed bytes to left */
  if( ctx->raw_buf.pos < ctx->raw_buf.size ) {
    memmove( ctx->raw,
             ctx->raw + ctx->raw_buf.pos,
             ctx->raw_buf.size - ctx->raw_buf.pos );
    ctx->raw_buf.size -= ctx->raw_buf.pos;
    ctx->raw_buf.pos   = 0UL;
  } else {
    ctx->raw_buf.size = 0UL;
    ctx->raw_buf.pos  = 0UL;
  }
  long t1 = fd_tickcount();
  ctx->metrics.compress_ticks += (ulong)( t1 - t0 );

  /* Write compressed bytes to file */
  ulong comp_wr_;
  ulong comp_sz = ctx->comp_buf.pos;
  int wr_err = fd_io_write(
      ctx->out_fd,
      ctx->comp,
      comp_sz, comp_sz,
      &comp_wr_ );
  if( FD_UNLIKELY( wr_err ) ) {
    FD_LOG_ERR(( "fd_io_write failed: %s", fd_io_strerror( wr_err ) ));
  }
  if( FD_UNLIKELY( comp_wr_ != comp_sz ) ) {
    FD_LOG_ERR(( "fd_io_write did not write full buffer (expected %lu bytes, wrote %lu bytes)", comp_sz, comp_wr_ ));
  }
  long t2 = fd_tickcount();
  metrics_compressed_written_add( ctx, comp_sz );
  ctx->metrics.io_ticks += (ulong)( t2 - t1 );
  ctx->comp_buf.pos  = 0UL;
  ctx->comp_buf.size = COMP_BUF_SZ;
}

static void
align_stream( fd_snapmk_t * ctx ) {
  long off = lseek( ctx->out_fd, 0L, SEEK_CUR );
  if( FD_UNLIKELY( off<0L ) ) {
    FD_LOG_ERR(( "lseek failed: %i-%s", errno, fd_io_strerror( errno ) ));
  }
  ulong uoff   = (ulong)off;
  /* Align using skippable frame */
  ulong aoff   = fd_ulong_align_up( uoff, 4096UL );
  ulong pad_sz = aoff - uoff;
  if( FD_UNLIKELY( pad_sz>0UL && pad_sz<8UL ) ) {
    aoff   += 4096UL;
    pad_sz += 4096UL;
  }
  if( pad_sz>0UL ) {
    uchar frame_hdr[ 8 ];
    FD_STORE( uint, frame_hdr,   ZSTD_MAGIC_SKIPPABLE_START );
    FD_STORE( uint, frame_hdr+4, (uint)( pad_sz-8 ) );
    ulong wr_sz_;
    int err = fd_io_write( ctx->out_fd, frame_hdr, 8UL, 8UL, &wr_sz_ );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "fd_io_write failed: %i-%s", err, fd_io_strerror( err ) ));
    }
    static uchar const zero[ 4096UL ] = {0};
    err = fd_io_write( ctx->out_fd, zero, pad_sz-8UL, pad_sz-8UL, &wr_sz_ );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "fd_io_write failed: %i-%s", err, fd_io_strerror( err ) ));
    }
    metrics_compressed_written_add( ctx, pad_sz );
  }
  __atomic_store_n( ctx->zp_file_off, aoff, __ATOMIC_RELEASE );
}

/* after_credit is called if we can publish at least one frag */

static inline void *
alloc_zp_payload( fd_snapmk_t * ctx,
                  ulong         out_idx,
                  ulong         sz,
                  ulong *       chunk ) {
  FD_TEST( sz );
  FD_TEST( out_idx<ctx->zp_cnt );
  *chunk = ctx->zp_out[ out_idx ].chunk;
  void * laddr = fd_chunk_to_laddr( ctx->zp_out[ out_idx ].mem, *chunk );
  ctx->zp_out[ out_idx ].chunk =
      fd_dcache_compact_next( *chunk, sz, ctx->zp_out[ out_idx ].chunk0, ctx->zp_out[ out_idx ].wmark );
  return laddr;
}

static void
after_credit( fd_snapmk_t *       ctx,
              fd_stem_context_t * stem,
              int *               poll_in,
              int *               charge_busy ) {
  (void)poll_in;

  switch( ctx->state ) {
  case SNAPMK_STATE_IDLE:
    break;
  case SNAPMK_STATE_START: {
    for( ulong i=0UL; i < ctx->zp_cnt; i++ ) {
      /* FIXME use find_lsb? */
      if( !fd_ulong_extract_bit( ctx->out_flush_pending, (int)i ) ) continue;
      if( !stem->cr_avail[ i ] ) continue;
      ulong chunk;
      fd_backup_start_msg_t * frag = alloc_zp_payload( ctx, i, sizeof(fd_backup_start_msg_t), &chunk );
      memset( frag, 0, sizeof(fd_backup_start_msg_t) );
      ulong name_len = strlen( ctx->wip_name );
      FD_TEST( name_len < FD_BACKUP_NAME_MAX );
      frag->name_len = (ushort)name_len;
      fd_memcpy( frag->name, ctx->wip_name, name_len+1UL );
      ulong ctl = fd_frag_meta_ctl( FD_BACKUP_ORIG_START, 0, 0, 0 );
      fd_stem_publish( stem, i, 0UL, chunk, sizeof(fd_backup_start_msg_t), ctl, 0UL, 0UL );
      ctx->out_flush_pending &= ~fd_ulong_mask_bit( (int)i );
      ctx->out_ready         &= ~fd_ulong_mask_bit( (int)i );
      *charge_busy = 1;
      break;
    }
    if( !ctx->out_flush_pending ) {
      ctx->state = SNAPMK_STATE_TAR_HEADERS;
    }
    break;
  }
  case SNAPMK_STATE_TAR_HEADERS: {
    ulong slot = ctx->bank->f.slot;

    ctx->raw_buf.pos = ctx->raw_buf.size = 0UL;
    uchar * p = ctx->raw;
    fd_tar_meta_t meta;

    fd_backup_tar_file_hdr( &meta, 5UL );
    fd_cstr_ncpy( meta.name, "version", sizeof(meta.name) );
    fd_tar_meta_set_chksum( &meta );
    memcpy( p, &meta, sizeof(fd_tar_meta_t) );
    p += sizeof(fd_tar_meta_t);

    memcpy( p,   "1.2.0",       5UL );
    memset( p+5, 0,       512UL-5UL );
    p += 512UL;

    fd_backup_tar_dir_hdr( &meta );
    fd_cstr_ncpy( meta.name, "snapshots/", sizeof(meta.name) );
    fd_tar_meta_set_chksum( &meta );
    memcpy( p, &meta, sizeof(fd_tar_meta_t) );
    p += sizeof(fd_tar_meta_t);

    fd_backup_tar_dir_hdr( &meta );
    fd_cstr_printf_check( meta.name, sizeof(meta.name), NULL, "snapshots/%lu/", slot );
    fd_tar_meta_set_chksum( &meta );
    memcpy( p, &meta, sizeof(fd_tar_meta_t) );
    p += sizeof(fd_tar_meta_t);

    ulong manifest_sz = fd_snap_manifest_serialized_sz( ctx->bank );
    fd_backup_tar_file_hdr( &meta, manifest_sz );
    fd_cstr_printf_check( meta.name, sizeof(meta.name), NULL, "snapshots/%lu/%lu", slot, slot );
    fd_tar_meta_set_chksum( &meta );
    memcpy( p, &meta, sizeof(fd_tar_meta_t) );
    p += sizeof(fd_tar_meta_t);
    ctx->raw_buf.size = (ulong)( p - ctx->raw );
    ctx->manifest_pad = fd_ulong_align_up( manifest_sz, 512UL ) - manifest_sz;

    flush_buffer( ctx, ZSTD_e_end );
    ctx->state = SNAPMK_STATE_MANIFEST;
    *charge_busy = 1;
    break;
  }
  case SNAPMK_STATE_MANIFEST: {
    if( FD_UNLIKELY( ctx->raw_buf.size + FD_SSMANIFEST_BUF_MIN > RAW_BUF_SZ ) ) {
      flush_buffer( ctx, ZSTD_e_continue );
      *charge_busy = 1;
      return;
    }
    ulong buf_rem = RAW_BUF_SZ - ctx->raw_buf.size;
    ulong chunk_sz = fd_snap_manifest_serialize(
        ctx->manifest_writer,
        (uchar *)ctx->raw_buf.src + ctx->raw_buf.size,
        buf_rem );
    ctx->raw_buf.size += chunk_sz;
    if( FD_UNLIKELY( !chunk_sz ) ) {
      flush_buffer( ctx, ZSTD_e_continue );
      if( ctx->manifest_pad ) {
        fd_memset( ctx->raw, 0, ctx->manifest_pad );
        ctx->raw_buf.size = ctx->manifest_pad;
      }
      flush_buffer( ctx, ZSTD_e_end );
      ctx->state = SNAPMK_STATE_ACCOUNTS_CACHE;
      align_stream( ctx );
      *charge_busy = 1;
      return;
    }
    break;
  }
  case SNAPMK_STATE_ACCOUNTS_CACHE: {
    ulong out_idx = pick_out_rr( ctx );
    fd_backup_cache_msg_t * frag = ctx->scan_batch;
    frag = fd_backup_cache_scan( ctx->acc_cache, frag );
    if( FD_UNLIKELY( !frag ) ) {
      set_zp_catchup_seq( ctx, stem );
      ctx->state = SNAPMK_STATE_ACCOUNTS_FLUSH1;
      ctx->out_flush_pending = fd_ulong_mask( 0, (int)ctx->zp_cnt-1 );
      break;
    }

    ulong cache_accounts_seen = 0UL;
    for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++ ) {
      uint acc_idx = frag->acc_idx[ i ];
      if( acc_idx==UINT_MAX ) continue;
      cache_accounts_seen++;
    }

    /* remove duplicates
       first pass (fast), ILP-friendly/vectorizable check */
    for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++ ) {
      uint acc_idx = frag->acc_idx[ i ];
      if( acc_idx==UINT_MAX ) continue;
      if( FD_UNLIKELY( fd_backup_visited_test( ctx->visited_set, (ulong)acc_idx ) ) ) {
        frag->acc_idx[ i ] = UINT_MAX;
      }
    }
    /* second pass: intra-batch conflict detect */
    for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++ ) {
      uint acc_idx = frag->acc_idx[ i ];
      if( acc_idx==UINT_MAX ) continue;
      if( FD_UNLIKELY( fd_backup_visited_test( ctx->visited_set, (ulong)acc_idx ) ) ) {
        frag->acc_idx[ i ] = UINT_MAX;
        memset( frag->pubkey[ i ].uc, 0, sizeof(fd_pubkey_t) );
        continue;
      }
      fd_backup_visited_insert( ctx->visited_set, (ulong)acc_idx );
    }
    metrics_accounts_seen_add( ctx, cache_accounts_seen );

    ulong chunk;
    void * payload = alloc_zp_payload( ctx, (ulong)out_idx, sizeof(fd_backup_cache_msg_t), &chunk );
    fd_memcpy( payload, frag, sizeof(fd_backup_cache_msg_t) );
    ulong ctl = fd_frag_meta_ctl( FD_BACKUP_ORIG_ACC_CACHE, 0, 0, 0 );
    fd_stem_publish( stem, (ulong)out_idx, 0UL, chunk, sizeof(fd_backup_cache_msg_t), ctl, 0UL, 0UL );
    _Bool blocked = !stem->cr_avail[ out_idx ];
    ctx->out_ready &= blocked ? ~fd_ulong_mask_bit( (int)out_idx ) : ULONG_MAX;
    *charge_busy = 1;
    break;
  }
  case SNAPMK_STATE_ACCOUNTS_DISK:
    break;
  case SNAPMK_STATE_ACCOUNTS_FLUSH1:
  case SNAPMK_STATE_ACCOUNTS_FLUSH2: {
    uint flush_state = ctx->state;

    /* Broadcast FLUSH packets */
    for( ulong i=0UL; i < ctx->zp_cnt; i++ ) {
      if( !fd_ulong_extract_bit( ctx->out_flush_pending, (int)i ) ) continue;
      if( !stem->cr_avail[ i ] ) continue;
      ulong ctl = fd_frag_meta_ctl( FD_BACKUP_ORIG_FLUSH, 0, 0, 0 );
      fd_stem_publish( stem, i, 0UL, 0UL, 0UL, ctl, 0UL, 0UL );
      ctx->out_flush_seq[ i ] = stem->seqs[ i ];
      ctx->out_flush_pending &= ~fd_ulong_mask_bit( (int)i );
      *charge_busy = 1;
      break;
    }
    if( !ctx->out_flush_pending ) {
      ctx->drain_next_state = flush_state==SNAPMK_STATE_ACCOUNTS_FLUSH1 ? SNAPMK_STATE_ACCOUNTS_DISK : SNAPMK_STATE_STATUS_CACHE;
      ctx->state = SNAPMK_STATE_ACCOUNTS_DRAIN;
      FD_MGAUGE_SET( SNAPMK, STATE, ctx->state );
    }
    break;
  }
  case SNAPMK_STATE_ACCOUNTS_DRAIN: {
    if( FD_UNLIKELY( ctx->drain_next_state==SNAPMK_STATE_ACCOUNTS_DISK ) ) {
      ctx->state = SNAPMK_STATE_ACCOUNTS_DISK;
      FD_MGAUGE_SET( SNAPMK, STATE, ctx->state );
      *charge_busy = 1;
      break;
    }

    if( FD_UNLIKELY( lseek( ctx->out_fd, 0L, SEEK_END )<0L ) ) {
      FD_LOG_ERR(( "lseek failed: %i-%s", errno, fd_io_strerror( errno ) ));
    }

    fd_txncache_writer_init( ctx->txncache_writer, ctx->txncache, ctx->bank->f.slot );
    ulong sc_sz = fd_txncache_writer_serialized_sz( ctx->txncache, ctx->bank->f.slot );

    ctx->raw_buf.pos = ctx->raw_buf.size = 0UL;
    fd_tar_meta_t meta;
    fd_backup_tar_file_hdr( &meta, sc_sz );
    fd_cstr_ncpy( meta.name, "snapshots/status_cache", sizeof(meta.name) );
    fd_tar_meta_set_chksum( &meta );
    memcpy( ctx->raw, &meta, sizeof(fd_tar_meta_t) );
    ctx->raw_buf.size    = sizeof(fd_tar_meta_t);
    ctx->status_cache_pad = fd_ulong_align_up( sc_sz, 512UL ) - sc_sz;

    flush_buffer( ctx, ZSTD_e_continue );
    ctx->state = SNAPMK_STATE_STATUS_CACHE;
    break;
  }
  case SNAPMK_STATE_STATUS_CACHE: {
    if( FD_UNLIKELY( ctx->raw_buf.size + FD_TXNCACHE_WRITER_BUF_MIN > RAW_BUF_SZ ) ) {
      flush_buffer( ctx, ZSTD_e_continue );
      *charge_busy = 1;
      return;
    }
    ulong buf_rem  = RAW_BUF_SZ - ctx->raw_buf.size;
    ulong chunk_sz = fd_txncache_writer_serialize(
        ctx->txncache_writer,
        (uchar *)ctx->raw_buf.src + ctx->raw_buf.size,
        buf_rem );
    ctx->raw_buf.size += chunk_sz;
    if( FD_UNLIKELY( !chunk_sz ) ) {
      flush_buffer( ctx, ZSTD_e_continue );
      if( ctx->status_cache_pad ) {
        fd_memset( ctx->raw, 0, ctx->status_cache_pad );
        ctx->raw_buf.size = ctx->status_cache_pad;
      }
      flush_buffer( ctx, ZSTD_e_end );
      ctx->state = SNAPMK_STATE_EOF_MARKER;
    }
    *charge_busy = 1;
    break;
  }
  case SNAPMK_STATE_EOF_MARKER: {
    ctx->raw_buf.pos = 0UL;
    ctx->raw_buf.size = 1024UL;
    fd_memset( ctx->raw, 0, 1024UL );
    flush_buffer( ctx, ZSTD_e_end );

    struct stat st;
    if( FD_UNLIKELY( fstat( ctx->out_fd, &st ) ) ) {
      FD_LOG_ERR(( "fstat failed: %s", fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( close( ctx->out_fd ) ) ) {
      FD_LOG_ERR(( "close(%s) failed: %s", ctx->out_path, fd_io_strerror( errno ) ));
    }
    ctx->out_fd = -1;
    if( FD_UNLIKELY( renameat( ctx->snap_dir_fd, ctx->wip_name, ctx->snap_dir_fd, ctx->final_name ) ) ) {
      FD_LOG_ERR(( "renameat(%s, %s) failed: %s", ctx->wip_name, ctx->final_name, fd_io_strerror( errno ) ));
    }
    char final_path[ PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( final_path, PATH_MAX, NULL, "%s/%s", ctx->snap_dir, ctx->final_name ) );

    FD_LOG_NOTICE(( "Snapshot created in %.3f seconds (%s, %.3f GB)",
                    (double)( fd_log_wallclock() - ctx->start_time )/1e9,
                    final_path, (double)st.st_size/1e9 ));

    ctx->out_flush_pending = fd_ulong_mask( 0, (int)ctx->zp_cnt-1 );
    ctx->state = SNAPMK_STATE_DONE;
    FD_MGAUGE_SET( SNAPMK, STATE, ctx->state );
    *charge_busy = 1;
    break;
  }
  case SNAPMK_STATE_DONE: {
    ulong ctl = fd_frag_meta_ctl( FD_BACKUP_ORIG_DONE, 0, 1, 0 );
    int published_done = 0;
    for( ulong i=0UL; i < ctx->zp_cnt; i++ ) {
      if( !fd_ulong_extract_bit( ctx->out_flush_pending, (int)i ) ) continue;
      if( !stem->cr_avail[ i ] ) continue;
      fd_stem_publish( stem, i, 0UL, 0UL, 0UL, ctl, 0UL, 0UL );
      ctx->out_flush_seq[ i ] = stem->seqs[ i ];
      ctx->out_flush_pending &= ~fd_ulong_mask_bit( (int)i );
      *charge_busy = 1;
      published_done = 1;
      break;
    }
    if( published_done ) break;
    if( ctx->out_flush_pending ) break;

    fd_stem_publish( stem, ctx->out_meta_idx, 0UL, 0UL, 0UL, ctl, 0UL, 0UL );
    resume_accdb_compaction( ctx );
    metrics_snapshot_clear( ctx );
    ctx->state = SNAPMK_STATE_IDLE;
    FD_MGAUGE_SET( SNAPMK, STATE, ctx->state );
    *charge_busy = 1;
    break;
  }
  default:
    FD_LOG_CRIT(( "invalid state %u", ctx->state ));
  }
}

static void
snap_begin( fd_snapmk_t * ctx,
            ulong         bank_idx ) {
  if( FD_UNLIKELY( ctx->state != SNAPMK_STATE_IDLE ) ) {
    FD_LOG_ERR(( "invariant violation: snapshot creation requested state is %u", ctx->state ));
    return;
  }

  if( FD_UNLIKELY( ctx->out_fd!=-1 ) ) {
    if( FD_UNLIKELY( close( ctx->out_fd ) ) ) {
      FD_LOG_ERR(( "close(%s) failed: %s", ctx->out_path, fd_io_strerror( errno ) ));
    }
    ctx->out_fd = -1;
  }

  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, bank_idx );
  FD_TEST( bank );
  ctx->bank = bank;

  uchar snap_hash[32];
  fd_blake3_hash( ctx->bank->f.lthash.bytes, FD_LTHASH_LEN_BYTES, snap_hash );
  char encoded_hash[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( snap_hash, NULL, encoded_hash );
  FD_TEST( fd_cstr_printf_check( ctx->final_name, FD_BACKUP_NAME_MAX, NULL,
           "snapshot-%lu-%s.tar.zst", ctx->bank->f.slot, encoded_hash ) );
  FD_TEST( fd_cstr_printf_check( ctx->wip_name, FD_BACKUP_NAME_MAX, NULL, "%s.wip", ctx->final_name ) );
  FD_TEST( fd_cstr_printf_check( ctx->out_path, PATH_MAX, NULL, "%s/%s", ctx->snap_dir, ctx->wip_name ) );

  if( FD_UNLIKELY( unlinkat( ctx->snap_dir_fd, ctx->wip_name, 0 ) && errno!=ENOENT ) ) {
    FD_LOG_ERR(( "unlinkat(%s) failed: %s", ctx->wip_name, fd_io_strerror( errno ) ));
  }
  ctx->out_fd = openat( ctx->snap_dir_fd, ctx->wip_name, O_CREAT|O_EXCL|O_WRONLY, 0644 );
  if( FD_UNLIKELY( ctx->out_fd<0 ) ) {
    FD_LOG_ERR(( "openat(%s) failed: %s", ctx->wip_name, fd_io_strerror( errno ) ));
  }

  pause_accdb_compaction( ctx );

  *ctx->zp_file_off  = 0UL;
  ctx->raw_buf.size  = 0UL;
  ctx->raw_buf.pos   = 0UL;
  ctx->comp_buf.pos  = 0UL;
  ctx->comp_buf.size = COMP_BUF_SZ;
  ctx->metrics.accparse_accounts_seen = 0UL;
  metrics_snapshot_clear( ctx );

  ulong zst_err = ZSTD_CCtx_reset( ctx->zst, ZSTD_reset_session_only );
  if( FD_UNLIKELY( ZSTD_isError( zst_err ) ) ) {
    FD_LOG_ERR(( "ZSTD_CCtx_reset failed: %s", ZSTD_getErrorName( zst_err ) ));
  }

  fd_ssmanifest_writer_init( ctx->manifest_writer, bank );

  fd_accdb_fork_id_t root_fork_id = bank->accdb_fork_id;
  FD_TEST( root_fork_id.val!=USHORT_MAX );
  /* Replay publishes the bank root after submitting accdb advance_root,
     but the accdb tile applies that command asynchronously.  Wait until
     accdb reaches the same fork as the bank manifest we are writing. */
  while( FD_UNLIKELY( __atomic_load_n( &ctx->accdb_root_fork->val, __ATOMIC_ACQUIRE )!=root_fork_id.val ) ) FD_SPIN_PAUSE();
  ulong root_generation = __atomic_load_n( &ctx->accdb_shfork[ root_fork_id.val ].generation, __ATOMIC_ACQUIRE );
  fd_backup_cache_reset( ctx->acc_cache, root_generation );
  fd_snapmk_accparse_reset( ctx->accparse,
                            ctx->acc_cache->acc_map,
                            ctx->acc_cache->acc_pool,
                            ctx->visited_set,
                            ctx->acc_cache->max_accounts,
                            ctx->acc_cache->acc_map_seed,
                            ctx->acc_cache->chain_mask,
                            root_generation );
  visited_set_null( ctx->visited_set );

  ctx->state = SNAPMK_STATE_START;
  ctx->out_flush_pending = fd_ulong_mask( 0, (int)ctx->zp_cnt-1 );
  ctx->out_ready = 0UL;
  ctx->disk_out_idx = ULONG_MAX;
  ctx->disk_batch_pending = 0;
  ctx->start_time = fd_log_wallclock();
  FD_MGAUGE_SET( SNAPMK, STATE, ctx->state );
  FD_MCNT_INC  ( SNAPMK, SNAPSHOTS_CREATED, 1UL );
  FD_LOG_NOTICE(( "Snapshot creation started" ));
}

static int
returnable_frag( fd_snapmk_t *       ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)sz; (void)tsorig;
  ctx->in_idle_cnt = 0UL;
  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_REPLAY:
    switch( sig ) {
    case REPLAY_SIG_SNAP_CREATE: {
      fd_replay_snap_create_t const * msg = fd_chunk_to_laddr_const( ctx->replay_in_mem, chunk );
      snap_begin( ctx, msg->bank_idx );
      break;
    }
    default:
      break;
    }
    break;
  case IN_KIND_SNAPRD: {
    FD_CHECK_ERR( ctx->state==SNAPMK_STATE_ACCOUNTS_DISK, "lifecycle bug" );

    /* Record the snaprd seq currently being parsed.  mk_zp frags emitted
       while parsing this frag reference its dcache bytes zero-copy; the
       shadow ring stamps this seq so snapmk can hold back snaprd's credit
       until the zp tiles drain those frags (see snapmk_update_release). */
    ctx->snaprd_parse_seq = seq;

    ulong orig = fd_frag_meta_ctl_orig( ctl );
    if( FD_UNLIKELY( orig!=FD_BACKUP_ORIG_DISK_FRAG ) ) {
      FD_LOG_CRIT(( "unexpected snaprd msg from link %lu with orig %lu", in_idx, orig ));
    }

    ulong frag_sz = tspub;
    if( FD_UNLIKELY( !frag_sz || frag_sz>FD_BACKUP_RD_MTU || frag_sz>UINT_MAX ) ) {
      FD_LOG_CRIT(( "invalid snaprd frag size %lu", frag_sz ));
    }

    fd_snapmk_accparse_t * parse = ctx->accparse;
    if( FD_LIKELY( !parse->input_active ) ) {
      uchar const * data = fd_chunk_to_laddr_const( ctx->snaprd_in_mem, chunk );
      fd_snapmk_accparse_insert( parse,
                                 data,
                                 frag_sz,
                                 fd_wksp_gaddr_fast( ctx->snaprd_in_mem, data ),
                                 sig );
      metrics_data_read_add( ctx, frag_sz );
    }

    for(;;) {
      /* (A) Flush a previously-staged batch once an output link frees up.
         A batch is self-contained within one snaprd frag, so it may be
         routed to any ready zp tile (no disk_out_idx pinning). */
      if( FD_UNLIKELY( ctx->disk_batch_pending ) ) {
        update_flow_control( ctx, stem );
        if( FD_UNLIKELY( !ctx->out_ready ) ) return 1;
        ulong out_idx = pick_out_rr( ctx );
        ulong out_chunk;
        void * payload = alloc_zp_payload( ctx, out_idx, sizeof(fd_backup_disk_batch_msg_t), &out_chunk );
        fd_memcpy( payload, ctx->disk_batch, sizeof(fd_backup_disk_batch_msg_t) );
        ulong ctl_batch = fd_frag_meta_ctl( FD_BACKUP_ORIG_ACC_DISK_BATCH, 1, 1, 0 );
        snapmk_stamp_shadow( ctx, out_idx, stem->seqs[ out_idx ] );
        fd_stem_publish( stem, out_idx, ctx->disk_batch_base_gaddr, out_chunk,
                         sizeof(fd_backup_disk_batch_msg_t), ctl_batch, 0UL, 0UL );
        if( FD_UNLIKELY( !stem->cr_avail[ out_idx ] ) ) ctx->out_ready &= ~fd_ulong_mask_bit( (int)out_idx );
        ctx->disk_batch_pending = 0;
        ctx->metrics.disk_batches_emitted++;
        return 1;
      }

      /* (B) Stage a batch of wholly-contained accounts (no straddle).
         Staging consumes the accounts into ctx->disk_batch; (A) flushes
         it on the next iteration once credit is available. */
      if( FD_LIKELY( ctx->disk_out_idx>=ctx->zp_cnt ) ) {
        ulong base_gaddr;
        ulong n = fd_snapmk_accparse_publish_batch( parse, ctx->disk_batch, &base_gaddr );
        metrics_accparse_seen_sync( ctx );
        if( n ) {
          ctx->disk_batch_pending    = 1;
          ctx->disk_batch_base_gaddr = base_gaddr;
          continue;
        }
      }

      /* (C) Single-account fallback for straddling / mid-record accounts. */
      ulong out_idx = ctx->disk_out_idx;
      if( FD_LIKELY( out_idx<ctx->zp_cnt ) ) {
        if( FD_UNLIKELY( !stem->cr_avail[ out_idx ] ) ) return 1;
      } else {
        update_flow_control( ctx, stem );
        if( FD_UNLIKELY( !ctx->out_ready ) ) return 1;
        out_idx = pick_out_rr( ctx );
      }

      fd_frag_meta_t meta[1];
      if( FD_UNLIKELY( !fd_snapmk_accparse_publish( parse, meta ) ) ) {
        metrics_accparse_seen_sync( ctx );
        parse->input_active = 0;
        /* A prestaged batch references the current frag's bytes and must
           be drained before this frag is released (publish_batch above
           returns 0 only once the prestage is empty). */
        FD_CHECK_ERR( !parse->ps_cnt, "prestaged batch outlived its frag" );
        if( FD_UNLIKELY( fd_frag_meta_ctl_eom( ctl ) ) ) {
          if( FD_UNLIKELY( parse->meta_sz || parse->acc_active || parse->pub_pending ) ) {
            FD_LOG_CRIT(( "snaprd stream ended mid-account record" ));
          }
          ctx->disk_out_idx      = ULONG_MAX;
          set_zp_catchup_seq( ctx, stem );
          ctx->out_flush_pending = fd_ulong_mask( 0, (int)ctx->zp_cnt-1 );
          ctx->state             = SNAPMK_STATE_ACCOUNTS_FLUSH2;
          FD_MGAUGE_SET( SNAPMK, STATE, ctx->state );
        }
        return 0;
      }

      int som = fd_frag_meta_ctl_som( meta->ctl );
      int eom = fd_frag_meta_ctl_eom( meta->ctl );
      metrics_accparse_seen_sync( ctx );
      ulong out_chunk = 0UL;
      ulong out_sz    = 0UL;
      if( FD_UNLIKELY( som ) ) {
        ctx->disk_out_idx = out_idx;
        ctx->metrics.disk_accounts_single++;
        fd_backup_disk_msg_t * frag = alloc_zp_payload( ctx, out_idx, sizeof(fd_backup_disk_msg_t), &out_chunk );
        frag->pubkey  = parse->pub_pubkey;
        frag->owner   = parse->pub_owner;
        frag->size    = parse->pub_size;
        frag->acc_idx = parse->pub_acc_idx;
        frag->snap_sz = parse->pub_snap_sz;
        frag->data_sz = (uint)meta->tspub;
        out_sz = sizeof(fd_backup_disk_msg_t);
      }

      snapmk_stamp_shadow( ctx, out_idx, stem->seqs[ out_idx ] );
      fd_stem_publish( stem, out_idx, meta->sig, out_chunk, out_sz, meta->ctl, meta->tsorig, meta->tspub );
      if( FD_UNLIKELY( !stem->cr_avail[ out_idx ] ) ) ctx->out_ready &= ~fd_ulong_mask_bit( (int)out_idx );
      if( FD_UNLIKELY( eom ) ) ctx->disk_out_idx = ULONG_MAX;
      return 1;
    }

    break;
  }
  default:
    FD_LOG_CRIT(( "unexpected msg from link %lu with sig %lu", in_idx, sig ));
  }
  return 0;
}

static void
metrics_write( fd_snapmk_t * ctx ) {
  FD_MGAUGE_SET( SNAPMK, STATE,                       ctx->state                    );
  FD_MCNT_SET(   SNAPMK, ACCOUNTS_SEEN,               ctx->metrics.accounts_seen    );
  FD_MCNT_SET(   SNAPMK, DATA_READ_BYTES,             ctx->metrics.data_read_bytes  );
  FD_MCNT_SET(   SNAPMK, BYTES_COMPRESSED,            ctx->metrics.bytes_compressed );
  FD_MCNT_SET(   SNAPMK, BYTES_WRITTEN,               ctx->metrics.bytes_written    );
  FD_MCNT_SET(   SNAPMK, IO_BLOCKED_DURATION_SECONDS, ctx->metrics.io_ticks         );
  FD_MCNT_SET(   SNAPMK, COMPRESS_DURATION_SECONDS,   ctx->metrics.compress_ticks   );
  FD_MCNT_SET(   SNAPMK, DISK_BATCHES_EMITTED,        ctx->metrics.disk_batches_emitted );
  FD_MCNT_SET(   SNAPMK, DISK_ACCOUNTS_SINGLE,        ctx->metrics.disk_accounts_single );
  FD_MGAUGE_SET( SNAPMK, SNAPSHOT_ACCOUNTS_SEEN,                    ctx->metrics.snapshot.accounts_seen    );
  FD_MGAUGE_SET( SNAPMK, SNAPSHOT_DATA_READ_BYTES,                 ctx->metrics.snapshot.data_read_bytes  );
  FD_MGAUGE_SET( SNAPMK, SNAPSHOT_UNCOMPRESSED_DATA_WRITTEN_BYTES, ctx->metrics.snapshot.bytes_compressed );
  FD_MGAUGE_SET( SNAPMK, SNAPSHOT_COMPRESSED_DATA_WRITTEN_BYTES,   ctx->metrics.snapshot.bytes_written    );
  ulong inflight_frags = ( ctx->snaprd_release_seq==ULONG_MAX ) ? 0UL
                       : fd_ulong_if( fd_seq_lt( ctx->snaprd_release_seq, ctx->snaprd_parse_seq ),
                                      ctx->snaprd_parse_seq - ctx->snaprd_release_seq, 0UL );
  FD_MGAUGE_SET( SNAPMK, SNAPRD_INFLIGHT_FRAGS,       inflight_frags                    );
}

#define STEM_BURST SNAPMK_STEM_BURST
#define STEM_LAZY  SNAPMK_STEM_LAZY
#define STEM_CALLBACK_CONTEXT_TYPE    fd_snapmk_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(fd_snapmk_t)
#define STEM_CALLBACK_CHECK_CREDIT    check_credit
#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#include "../../disco/stem/fd_stem.c"

/* snapmk_run wraps stem_run1 so snapmk can take manual ownership of the
   flow control credit it returns to snaprd.  It is a copy of the
   generated stem_run() preamble with one change: the snaprd_out link's
   in_fseq entry is redirected to ctx->stem_snaprd_fseq (a throwaway), so
   the stem publishes its parse cursor there instead of the real fseq.
   snapmk drives the real fseq (snaprd_release_fseq) to the lagging
   release watermark itself (see snapmk_update_release), which avoids
   editing the shared fd_stem.c. */

static void
snapmk_run( fd_topo_t *      topo,
            fd_topo_tile_t * tile ) {
  fd_snapmk_t * ctx = (fd_snapmk_t *)fd_ulong_align_up( (ulong)fd_topo_obj_laddr( topo, tile->tile_obj_id ), alignof(fd_snapmk_t) );

  fd_frag_meta_t const * in_mcache[ FD_TOPO_MAX_LINKS ];
  ulong *                in_fseq  [ FD_TOPO_MAX_TILE_IN_LINKS ];

  ulong polled_in_cnt = 0UL;
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    if( FD_UNLIKELY( !tile->in_link_poll[ i ] ) ) continue;
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    in_mcache[ polled_in_cnt ] = link->mcache;
    FD_TEST( in_mcache[ polled_in_cnt ] );
    /* Redirect the snaprd link's fseq to the throwaway; snapmk owns the
       real credit return to snaprd. */
    if( 0==strcmp( link->name, "snaprd_out" ) ) in_fseq[ polled_in_cnt ] = ctx->stem_snaprd_fseq;
    else                                        in_fseq[ polled_in_cnt ] = tile->in_link_fseq[ i ];
    FD_TEST( in_fseq[ polled_in_cnt ] );
    polled_in_cnt += 1UL;
  }

  fd_frag_meta_t * out_mcache[ FD_TOPO_MAX_LINKS ];
  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    out_mcache[ i ] = topo->links[ tile->out_link_id[ i ] ].mcache;
    FD_TEST( out_mcache[ i ] );
  }

  ulong            reliable_cons_cnt = 0UL;
  ulong            cons_out [ FD_TOPO_MAX_LINKS ];
  ulong *          cons_fseq[ FD_TOPO_MAX_LINKS ];
  volatile ulong * cons_slow[ FD_TOPO_MAX_LINKS ];
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * consumer_tile = &topo->tiles[ i ];
    ulong polled_in_idx = 0UL;
    for( ulong j=0UL; j<consumer_tile->in_cnt; j++ ) {
      int is_polled = consumer_tile->in_link_poll[ j ];
      for( ulong k=0UL; k<tile->out_cnt; k++ ) {
        if( FD_UNLIKELY( consumer_tile->in_link_id[ j ]==tile->out_link_id[ k ] && consumer_tile->in_link_reliable[ j ] ) ) {
          cons_out [ reliable_cons_cnt ] = k;
          cons_fseq[ reliable_cons_cnt ] = consumer_tile->in_link_fseq[ j ];
          FD_TEST( cons_fseq[ reliable_cons_cnt ] );
          cons_slow[ reliable_cons_cnt ] = fd_metrics_link_in( consumer_tile->metrics, polled_in_idx ) + FD_METRICS_COUNTER_LINK_SLOW_OFF;
          reliable_cons_cnt++;
          FD_TEST( reliable_cons_cnt<FD_TOPO_MAX_LINKS );
        }
      }
      if( FD_LIKELY( is_polled ) ) polled_in_idx++;
    }
  }

  fd_rng_t rng[1];
  FD_TEST( fd_rng_join( fd_rng_new( rng, (uint)fd_ulong_hash( (ulong)fd_tickcount() + tile->id ), 0UL ) ) );

  uchar __attribute__((aligned(FD_STEM_SCRATCH_ALIGN))) stem_scratch[ stem_scratch_footprint( polled_in_cnt, tile->out_cnt, reliable_cons_cnt ) ];

  stem_run1( polled_in_cnt, in_mcache, in_fseq,
             tile->out_cnt, out_mcache,
             reliable_cons_cnt, cons_out, cons_fseq, cons_slow,
             SNAPMK_STEM_BURST, SNAPMK_STEM_LAZY,
             rng, stem_scratch, ctx );
}

fd_topo_run_tile_t fd_tile_snapmk = {
  .name                 = "snapmk",
  .populate_allowed_fds = populate_allowed_fds,
  .scratch_align        = scratch_align,
  .scratch_footprint    = scratch_footprint,
  .privileged_init      = privileged_init,
  .unprivileged_init    = unprivileged_init,
  .run                  = snapmk_run,
  .allow_renameat       = 1
};

#ifndef HEADER_fd_src_discof_backup_fd_backup_disk_h
#define HEADER_fd_src_discof_backup_fd_backup_disk_h

/* fd_backup_disk.h does streaming parsing of accdb disk partitions.
   Publishes discovered accounts (by disk offset) onto mcache/dcache. */

#include "fd_backup.h"
#include "fd_backup_visited.h"
#include "../../flamenco/accdb/fd_accdb_private.h"
#include "../../tango/fd_tango_base.h"

/* fd_snapmk_accparse_t does streaming zero-copy parsing of accdb
   partitions.  Ingests a stream of disk data (arbitrarily fragmented)
   and produces an account-aligned fragment stream. */

struct fd_snapmk_accparse {

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

  /* accdb in-memory index */
  uint const *               acc_map;      /* map chains */
  fd_accdb_accmeta_t const * acc_pool;     /* map ele pool */
  ulong                      max_accounts; /* map ele pool max */
  ulong                      acc_map_seed; /* map hash function */
  uint                       chain_mask;   /* map chain count - 1 */

  ulong *       epoch_slot;
  ulong const * epoch;

  visited_set_t *            visited_set;

  uint root_generation;

  /* defrag buffer for torn disk partition data */
  union __attribute__((packed)) {
    uchar buf[ sizeof(fd_accdb_disk_meta_t) ];
    fd_accdb_disk_meta_t meta;
  };

  /* deslop this shit */
  uint        ps_cnt;
  ulong       ps_base_gaddr;
  ulong       ps_hash    [ FD_BACKUP_DISK_PARA ];
  uint        ps_frag_off[ FD_BACKUP_DISK_PARA ];
  ulong       ps_file_off[ FD_BACKUP_DISK_PARA ];
  fd_pubkey_t ps_pubkey  [ FD_BACKUP_DISK_PARA ];
  ulong       accounts_seen;
};

typedef struct fd_snapmk_accparse fd_snapmk_accparse_t;

FD_PROTOTYPES_BEGIN

/* Public API */

/* fd_snapmk_accparse_push ingests a accdb disk data fragment.  data
   points to data_sz bytes of data read from disk.  src_gaddr points to
   the same data wksp-relative.  src_off is the disk offset of this
   data frag.  You must call pop() until it returns NULL before the next
   push. */

static inline void
fd_snapmk_accparse_push( fd_snapmk_accparse_t * parse,
                         uchar const *          data,
                         ulong                  data_sz,
                         ulong                  src_gaddr,
                         ulong                  src_off );

/* fd_snapmk_accparse_pop produces a frag from accumulated source data.
   Returns meta if a frag was produced, NULL otherwise (needs more data
   in push()). */

static inline fd_frag_meta_t *
fd_snapmk_accparse_pop( fd_snapmk_accparse_t * parse,
                        fd_frag_meta_t *       meta );

/* Implementation */

/* fd_snapmk_accparse_keep returns 1 if an account found in a disk
   partition should be copied into the snapshot being produced, 0
   otherwise. */

static inline int
fd_snapmk_accparse_keep_inner( fd_snapmk_accparse_t * parse ) {
  uint const root_generation    = parse->root_generation;
  uint const min_generation     = 0;
  int const  include_tombstones = 0;

  ulong hash      = fd_accdb_hash( parse->meta.pubkey, parse->acc_map_seed );
  ulong chain_idx = hash & parse->chain_mask;
  uint acc_idx = FD_VOLATILE_CONST( parse->acc_map[ chain_idx ] );

  while( acc_idx!=UINT_MAX ) {
    if( FD_UNLIKELY( (ulong)acc_idx>=parse->max_accounts ) ) {
      return 0;
    }

    fd_accdb_accmeta_t const * acc = &parse->acc_pool[ acc_idx ];
    uint  next_idx    = FD_VOLATILE_CONST( acc->map.next );
    uint  generation  = FD_VOLATILE_CONST( acc->key.generation );
    ulong offset_fork = FD_VOLATILE_CONST( acc->offset_fork );
    ulong lamports    = FD_VOLATILE_CONST( acc->lamports );

    if( FD_UNLIKELY( memcmp( acc->key.pubkey, parse->meta.pubkey, sizeof(parse->meta.pubkey) ) ) ) {
      goto next;
    }
    if( FD_UNLIKELY( ( generation<min_generation  ) |
                     ( generation>root_generation ) ) ) {
      goto next;
    }
    if( FD_UNLIKELY( !include_tombstones && !lamports ) ) {
      goto next;
    }
    ulong cur_off = offset_fork & FD_ACCDB_OFF_MASK;
    if( FD_UNLIKELY( cur_off!=parse->acc_file_off ) ) {
      goto next;
    }
    if( FD_UNLIKELY( fd_backup_visited_test( parse->visited_set, (ulong)acc_idx ) ) ) {
      return 0;
    }
    fd_backup_visited_insert( parse->visited_set, (ulong)acc_idx );
    parse->acc_idx = acc_idx;
    return 1;

next:
    acc_idx = next_idx;
  }

  return 0;
}

static inline int
fd_snapmk_accparse_keep( fd_snapmk_accparse_t * parse ) {
  ulong *       epoch_slot = parse->epoch_slot;
  ulong const * epoch      = parse->epoch;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *epoch_slot ) = FD_VOLATILE_CONST( *epoch );
  FD_HW_MFENCE();

  int keep = fd_snapmk_accparse_keep_inner( parse );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *epoch_slot ) = ULONG_MAX;
  return keep;
}

static inline void
fd_snapmk_accparse_push( fd_snapmk_accparse_t * parse,
                         uchar const *          data,
                         ulong                  data_sz,
                         ulong                  src_gaddr,
                         ulong                  src_off ) {
  parse->data            = data;
  parse->data_sz         = data_sz;
  parse->src_gaddr       = src_gaddr;
  parse->src_off         = src_off;
  parse->frag_base_gaddr = src_gaddr;
  parse->pf_cursor       = data;
  parse->input_active    = 1;
}

static inline fd_frag_meta_t *
fd_snapmk_accparse_pop( fd_snapmk_accparse_t * parse,
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

/* FIXME deslop */

static void
fd_snapmk_accparse_prestage( fd_snapmk_accparse_t * parse ) {
  if( FD_UNLIKELY( parse->ps_cnt ) ) return;
  /* Only batch at a clean account boundary with no straddle carry. */
  if( FD_UNLIKELY( parse->pub_pending || parse->acc_active || parse->meta_sz ) ) return;

  ulong const meta_sz = sizeof(fd_accdb_disk_meta_t);
  ulong * hash     = parse->ps_hash;
  ulong seed       = parse->acc_map_seed;
  uint  chain_mask = parse->chain_mask;
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
  }

  parse->ps_cnt        = (uint)n;
  parse->ps_base_gaddr = parse->frag_base_gaddr;
  parse->accounts_seen += n;
}

/* FIXME deslop */

static void
fd_snapmk_accparse_keep_batch( fd_snapmk_accparse_t * parse,
                               ulong const *          file_off,
                               ulong const *          hash,
                               uint *                 acc_idx,
                               ulong                  cnt ) {
  uint const *               acc_map      = parse->acc_map;
  fd_accdb_accmeta_t const * acc_pool     = parse->acc_pool;
  ulong                      max_accounts = parse->max_accounts;
  uint                       root_gen     = parse->root_generation;
  uint                       min_gen      = 0U;
  uint                       inc_tomb     = 0;

  uint matched[ FD_BACKUP_DISK_PARA ];
  for( ulong n=0UL; n<FD_BACKUP_DISK_PARA; n++ ) matched[ n ] = UINT_MAX;

  ulong *       epoch_slot = parse->epoch_slot;
  ulong const * epoch      = parse->epoch;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *epoch_slot ) = FD_VOLATILE_CONST( *epoch );
  FD_HW_MFENCE();

  /* lane[i]/cur[i]: compacted live-lane list, lane index and the chain
     node it sits on.  head[] was loaded (and prefetched) when the
     batch was prestaged, a full batch resolve ago. */
  uint  lane[ FD_BACKUP_DISK_PARA ];
  uint  cur [ FD_BACKUP_DISK_PARA ];

  ulong active_cnt = 0UL;
  for( ulong n=0UL; n<cnt; n++ ) {
    uint h    = FD_VOLATILE_CONST( acc_map[ hash[ n ] ] );
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
      ulong lam  = FD_VOLATILE_CONST( m->lamports       );
      uint hit  = ( gen>=min_gen )
                & ( gen<=root_gen )
                & ( inc_tomb | ( lam!=0UL ) )
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

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *epoch_slot ) = ULONG_MAX;

  for( ulong n=0UL; n<FD_BACKUP_DISK_PARA; n++ ) {
    uint  idx  = matched[ n ];
    uint  have = idx!=UINT_MAX;
    ulong safe = (ulong)( idx & ( 0U-have ) );
    uint  keep = have & (uint)!fd_backup_visited_test( parse->visited_set, safe );
    fd_backup_visited_insert_if( parse->visited_set, (int)keep, safe );
    acc_idx[ n ] = idx | ( keep-1U );
  }
}

static inline ulong
fd_snapmk_accparse_publish_batch( fd_snapmk_accparse_t *       parse,
                                  fd_backup_disk_batch_msg_t * batch,
                                  ulong *                      base_gaddr ) {
  fd_snapmk_accparse_prestage( parse ); /* no-op unless prestage empty */

  ulong n = (ulong)parse->ps_cnt;
  if( !n ) return 0UL;

  /* Move batch N out of the prestage buffer, then stage N+1 before
     resolving N so N+1's prefetches overlap N's chain walk below. */
  ulong hash    [ FD_BACKUP_DISK_PARA ];
  ulong file_off[ FD_BACKUP_DISK_PARA ];
  memcpy( hash,            parse->ps_hash,     n*sizeof(ulong)       );
  memcpy( file_off,        parse->ps_file_off, n*sizeof(ulong)       );
  memcpy( batch->frag_off, parse->ps_frag_off, n*sizeof(uint)        );
  memcpy( batch->pubkey,   parse->ps_pubkey,   n*sizeof(fd_pubkey_t) );
  *base_gaddr   = parse->ps_base_gaddr;
  parse->ps_cnt = 0U;

  fd_snapmk_accparse_prestage( parse );

  fd_snapmk_accparse_keep_batch( parse, file_off, hash, batch->acc_idx, n );
  for( ulong i=n; i<FD_BACKUP_DISK_PARA; i++ ) batch->acc_idx[ i ] = UINT_MAX;

  return n;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backup_fd_backup_disk_h */

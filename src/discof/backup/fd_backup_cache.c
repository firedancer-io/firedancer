#include "fd_backup_cache.h"
#include "fd_backup.h"

fd_backup_cache_t *
fd_backup_cache_init( fd_backup_cache_t *        backup,
                      uchar const * const        cache    [ FD_ACCDB_CACHE_CLASS_CNT ],
                      ulong const                cache_max[ FD_ACCDB_CACHE_CLASS_CNT ],
                      uint const *               acc_map,
                      fd_accdb_accmeta_t const * acc_pool,
                      ulong                      max_accounts,
                      ulong                      acc_map_seed,
                      ulong                      chain_mask ) {
  *backup = (fd_backup_cache_t) {
    .acc_map          = acc_map,
    .acc_pool         = acc_pool,
    .max_accounts = max_accounts,
    .acc_map_seed     = acc_map_seed,
    .chain_mask       = (uint)chain_mask,
    .cache_class      = 0UL,
    .cache_idx        = 0UL,
    .root_generation  = 0
  };
  for( ulong i=0UL; i<FD_ACCDB_CACHE_CLASS_CNT; i++ ) {
    backup->cache    [ i ] = cache    [ i ];
    backup->cache_max[ i ] = cache_max[ i ];
  }
  return backup;
}

fd_backup_cache_t *
fd_backup_cache_join( fd_backup_cache_t * backup,
                      fd_accdb_shmem_t *  accdb ) {
  ulong max_live_slots = accdb->max_live_slots;
  ulong max_accounts   = accdb->max_accounts;

  ulong chain_cnt = fd_ulong_pow2_up( (max_accounts>>1) + (max_accounts&1UL) );

  FD_SCRATCH_ALLOC_INIT( l, accdb );
  /*                       */FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_SHMEM_ALIGN,           sizeof(fd_accdb_shmem_t)                                );
  /*                       */FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_fork_shmem_t), max_live_slots*sizeof(fd_accdb_fork_shmem_t)            );
  /*                       */FD_SCRATCH_ALLOC_APPEND( l, descends_set_align(),           max_live_slots*descends_set_footprint( max_live_slots ) );
  void * _acc_map          = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                  chain_cnt*sizeof(uint)                                  );
  void * _acc_pool_ele     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_accmeta_t),    max_accounts*sizeof(fd_accdb_accmeta_t)             );

  uchar const * cache[ FD_ACCDB_CACHE_CLASS_CNT ];
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    cache[ c ] = (uchar const *)accdb + accdb->cache_region_off[ c ];
  }

  backup = fd_backup_cache_init(
      backup,
      cache,
      accdb->cache_class_max,
      _acc_map,
      _acc_pool_ele,  max_accounts,
      accdb->seed,
      chain_cnt-1UL
  );
  return backup;
}

static inline fd_accdb_cache_line_t *
cache_line( fd_backup_cache_t * backup,
            ulong               cls,
            ulong               idx ) {
  return (fd_accdb_cache_line_t *)( backup->cache[ cls ] + idx * fd_accdb_cache_slot_sz[ cls ] );
}

static void
filter_batch( fd_backup_cache_t * backup,
              fd_backup_cache_msg_t * frag );

fd_backup_cache_msg_t *
fd_backup_cache_scan( fd_backup_cache_t * backup,
                      fd_backup_cache_msg_t * frag ) {
  uint chain_mask = backup->chain_mask;

  ulong seed = backup->acc_map_seed;
  ulong cls  = backup->cache_class;
  if( FD_UNLIKELY( cls >= FD_ACCDB_CACHE_CLASS_CNT ) ) {
    return NULL;
  }

  /* Scan through cache lines (sequentially)

     This discovers any cached account (rooted or not), therefore may
     produce account indices that become invalid.  These are filtered
     out below. */

  long rem = (long)backup->cache_max[ cls ] - (long)backup->cache_idx;
  ulong idx = backup->cache_idx;
  if( FD_LIKELY( rem >= (long)FD_BACKUP_CACHE_PARA ) ) {
    /* fast path */
    for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++, idx++ ) {
      fd_accdb_cache_line_t const * line = cache_line( backup, cls, idx );
      frag->acc_idx[ i ] = line->acc_idx;
      fd_memcpy( frag->pubkey[ i ].uc, line->key.pubkey, sizeof(fd_pubkey_t) );
      backup->chain_idx[ i ] = fd_accdb_hash( line->key.pubkey, seed ) & chain_mask;
    }
  } else {
    /* slow path */
    for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++ ) {
      frag->acc_idx[ i ] = UINT_MAX;
      memset( frag->pubkey[ i ].uc, 0, sizeof(fd_pubkey_t) );
      backup->chain_idx[ i ] = UINT_MAX; /* deliberately not ULONG_MAX */
    }
    for( ulong i=0UL; rem--; i++, idx++ ) {
      fd_accdb_cache_line_t const * line = cache_line( backup, cls, idx );
      frag->acc_idx[ i ] = line->acc_idx;
      fd_memcpy( frag->pubkey[ i ].uc, line->key.pubkey, sizeof(fd_pubkey_t) );
      backup->chain_idx[ i ] = fd_accdb_hash( line->key.pubkey, seed ) & chain_mask;
    }
    if( FD_UNLIKELY( idx >= backup->cache_max[ cls ] ) ) {
      backup->cache_class++;
      idx = 0UL;
    }
  }
  backup->cache_idx = idx;

  /* Filter out account indices that cannot index acc_pool */

  for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++ ) {
    uint acc_idx = frag->acc_idx[ i ];
    if( (ulong)acc_idx>=backup->max_accounts ) {
      frag->acc_idx[ i ] = UINT_MAX;
      memset( frag->pubkey[ i ].uc, 0, sizeof(fd_pubkey_t) );
      backup->chain_idx[ i ] = UINT_MAX;
    }
  }

  /* Filter out freed/invisible and non-rooted accounts */

  filter_batch( backup, frag );
  return frag;
}

/* filter_batch is called with arbitrary acc_idx found in cache.

   Filter out acc_idx that:
   - are not rooted (generation too new)
   - have been freed since then (not visible in map) -- these are
     guaranteed to have not been rooted, since rooted acc_idx are stable
     while compaction and advance_root is disabled */

#define SET_NAME found_set
#define SET_MAX  FD_BACKUP_CACHE_PARA
#include "../../util/tmpl/fd_set.c"

static void
filter_batch( fd_backup_cache_t * backup,
              fd_backup_cache_msg_t * frag ) {
  fd_accdb_accmeta_t const * acc_pool = backup->acc_pool;
  uint const                 root_gen = backup->root_generation;

  /* filter out non-rooted accounts */
  static uint const dead_gen = (ulong)UINT_MAX;
  for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++ ) {
    uint         acc_idx = frag->acc_idx[ i ];
    uint const * gen = acc_idx!=UINT_MAX ? &acc_pool[ acc_idx ].key.generation : &dead_gen;
    _Bool rooted = FD_VOLATILE_CONST( *gen ) <= root_gen;
    fd_uint_store_if( !rooted, &frag->acc_idx[ i ], UINT_MAX );
  }

  /* filter out invisible accounts */
  found_set_t found[ found_set_word_cnt ];
  found_set_new( found );

  uint head[ FD_BACKUP_CACHE_PARA ];
  for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++ ) {
    head[ i ] = frag->acc_idx[ i ]!=UINT_MAX ? backup->acc_map[ backup->chain_idx[ i ] ] : UINT_MAX;
  }

  /* sentinel to assist with branchless code */
  static fd_accdb_accmeta_t const dead = {
    .map = { .next = UINT_MAX }
  };

  /* parallel walk map chains */
  for(;;) {

    /* check for matches */
    for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++ ) {
      found_set_insert_if( found, frag->acc_idx[ i ]==head[ i ], i );
    }

    /* convert acc_idx to pointers */
    fd_accdb_accmeta_t const * gather[ FD_BACKUP_CACHE_PARA ];
    for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++ ) {
      uint acc_idx = head[ i ];
      gather[ i ] = acc_idx!=UINT_MAX ? &acc_pool[ acc_idx ] : &dead;
    }

    /* wide gather */
    fd_accdb_accmeta_t * meta = backup->meta;
    for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++ ) {
      meta[ i ] = *gather[ i ];
    }

    /* next */
    for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++ ) {
      head[ i ] = meta[ i ].map.next;
    }

    /* done? */
    int done = 1;
    for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++ ) {
      if( head[ i ]!=UINT_MAX ) done = 0;
    }
    if( done ) break;

  }

  /* filter out dead elements */
  for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++ ) {
    if( FD_UNLIKELY( !found_set_test( found, i ) ) ) {
      frag->acc_idx[ i ] = UINT_MAX;
      memset( frag->pubkey[ i ].uc, 0, sizeof(fd_pubkey_t) );
    }
  }

}

int
fd_backup_cache_read( fd_backup_cache_t * ctx,
                      fd_pubkey_t const * pubkey,
                      uint                acc_idx,
                      ZSTD_inBuffer *     out,
                      ulong               out_max ) {
  FD_TEST( pubkey );

  if( FD_UNLIKELY( (ulong)acc_idx>=ctx->max_accounts ) ) {
    return FD_BACKUP_CACHE_ERR_MISS;
  }

  if( FD_UNLIKELY( out->size + sizeof(snap_acc_hdr_t) > out_max ) ) {
    return FD_BACKUP_CACHE_ERR_SPACE;
  }

  /* This is a partial copy of read_one_nocopy */
  fd_accdb_accmeta_t const * accmeta = &ctx->acc_pool[ acc_idx ];
  if( FD_UNLIKELY( memcmp( accmeta->key.pubkey, pubkey->uc, sizeof(fd_pubkey_t) ) ) ) {
    return FD_BACKUP_CACHE_ERR_MISS;
  }

  /// STEP 1.
  ///   Walk the hash chain at acc_map[hash(pubkey)] using the same
  ///   visibility test as fd_accdb_acquire_inner.  See that function
  ///   for the detailed safety argument under concurrent prepend.
  ulong hash = fd_accdb_hash( pubkey->uc, ctx->acc_map_seed ) & ctx->chain_mask;
  uint acc_idx2 = FD_VOLATILE_CONST( ctx->acc_map[ hash ] );
  _Bool found = 0;
  while( acc_idx2!=UINT_MAX ) {
    fd_accdb_accmeta_t const * candidate = &ctx->acc_pool[ acc_idx2 ];
    found |= acc_idx==acc_idx2;
    acc_idx2 = FD_VOLATILE_CONST( candidate->map.next );
  }
  if( !found ) return FD_BACKUP_CACHE_ERR_MISS;

  /// STEP 2.
  ///   Snapshot acc fields.  The acc element's metadata is effectively
  ///   immutable from the perspective of cross-fork readers (see the
  ///   comment block in fd_accdb.h about cross-fork reads). */
  uint  snap_es       = FD_VOLATILE_CONST( accmeta->executable_size );
  uint  snap_gen      = accmeta->key.generation;
  ulong snap_lamports = accmeta->lamports;
  uint  snap_cidx     = FD_VOLATILE_CONST( accmeta->cache_idx );
  ulong data_len      = (ulong)FD_ACCDB_SIZE_DATA( snap_es );
  int   executable    = FD_ACCDB_SIZE_EXEC( snap_es );
  ulong rec_sz        = sizeof(snap_acc_hdr_t) + fd_ulong_align_up( data_len, 8UL );
  ulong data_pad      = fd_ulong_align_up( data_len, 8UL ) - data_len;
  if( FD_UNLIKELY( out->size + rec_sz > out_max ) ) {
    return FD_BACKUP_CACHE_ERR_SPACE;
  }

  /// STEP 3.
  ///    Cache hit fast path with try-read-test (ABA) loop.  Same
  ///    primitives as cache_try_pin: re-check key.generation + pubkey
  ///    before and after the bulk copy, and bail to the disk path if the
  ///    line was claimed for eviction (refcnt ==
  ///    FD_ACCDB_EVICT_SENTINEL).  No CAS on refcnt, we never pin the
  ///    line.
  if( !FD_ACCDB_SIZE_CACHE_VALID( snap_es ) ) {
    return FD_BACKUP_CACHE_ERR_MISS;
  }
  if( snap_cidx==FD_ACCDB_ACC_CIDX_INVAL ) {
    return FD_BACKUP_CACHE_ERR_MISS;
  }

  ulong cls = FD_ACCDB_ACC_CIDX_CLASS( snap_cidx );
  ulong idx = FD_ACCDB_ACC_CIDX_IDX  ( snap_cidx );
  fd_accdb_cache_line_t * line = cache_line( ctx, cls, idx );

  snap_acc_hdr_t * hdr = (snap_acc_hdr_t *)( (ulong)out->src + out->size );
  memset( hdr, 0, sizeof(snap_acc_hdr_t) );
  memcpy( hdr->pubkey.uc, pubkey->uc, sizeof(fd_pubkey_t) );

  uint gen0 = FD_VOLATILE_CONST( line->key.generation );
  uint rc0  = FD_VOLATILE_CONST( line->refcnt );
  uint ai0  = FD_VOLATILE_CONST( line->acc_idx );
  if( FD_UNLIKELY( rc0==FD_ACCDB_EVICT_SENTINEL ) ) return FD_BACKUP_CACHE_ERR_MISS;
  if( FD_UNLIKELY( gen0!=snap_gen ) ) return FD_BACKUP_CACHE_ERR_MISS;
  if( FD_UNLIKELY( memcmp( line->key.pubkey, pubkey->uc, sizeof(fd_pubkey_t) ) ) ) return FD_BACKUP_CACHE_ERR_MISS;
  /* acc_idx==UINT_MAX is the "loading" sentinel set by cold_load_acc
     before the preadv2 fills the line.  CACHE_VALID can be observed
     set while the bytes are still stale, so fall to the disk path
     (which spins on offset_fork and reads from the file) rather
     than copying garbage. */
  if( FD_UNLIKELY( ai0==UINT_MAX ) ) return FD_BACKUP_CACHE_ERR_MISS;

  FD_COMPILER_MFENCE();
  memcpy( hdr->owner.uc, line->owner, 32UL );
  uchar * d = (uchar *)hdr + sizeof(snap_acc_hdr_t);
  memcpy( d, (uchar const *)(line+1UL), data_len );
  if( data_pad ) memset( d + data_len, 0, data_pad );
  FD_COMPILER_MFENCE();

  uint gen1 = FD_VOLATILE_CONST( line->key.generation );
  uint rc1  = FD_VOLATILE_CONST( line->refcnt );
  uint ai1  = FD_VOLATILE_CONST( line->acc_idx );
  if( FD_UNLIKELY( rc1==FD_ACCDB_EVICT_SENTINEL ) ) return FD_BACKUP_CACHE_ERR_MISS;
  if( FD_UNLIKELY( gen1!=snap_gen ) ) return FD_BACKUP_CACHE_ERR_MISS;
  if( FD_UNLIKELY( memcmp( line->key.pubkey, pubkey->uc, sizeof(fd_pubkey_t) ) ) ) return FD_BACKUP_CACHE_ERR_MISS;
  if( FD_UNLIKELY( ai1==UINT_MAX ) ) return FD_BACKUP_CACHE_ERR_MISS;

  hdr->lamports   = snap_lamports;
  hdr->executable = !!executable;
  hdr->data_len   = data_len;
  out->size += rec_sz;
  return FD_BACKUP_CACHE_SUCCESS;
}

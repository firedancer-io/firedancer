#include "fd_funk.h"

/* Provide the actual record map implementation */

#define POOL_NAME          fd_funk_rec_pool
#define POOL_ELE_T         fd_funk_rec_t
#define POOL_IDX_T         uint
#define POOL_NEXT          map_next
#define POOL_IMPL_STYLE    2
#include "../util/tmpl/fd_pool_para.c"

#define MAP_NAME              fd_funk_rec_map
#define MAP_ELE_T             fd_funk_rec_t
#define MAP_KEY_T             fd_funk_xid_key_pair_t
#define MAP_KEY               pair
#define MAP_KEY_EQ(k0,k1)     fd_funk_xid_key_pair_eq((k0),(k1))
#define MAP_KEY_HASH(k0,seed) fd_funk_xid_key_pair_hash((k0),(seed))
#define MAP_IDX_T             uint
#define MAP_NEXT              map_next
#define MAP_MEMO              map_hash
#define MAP_MAGIC             (0xf173da2ce77ecdb0UL) /* Firedancer rec db version 0 */
#define MAP_MEMOIZE           1
#define MAP_IMPL_STYLE        2
#include "../util/tmpl/fd_map_chain_para.c"

fd_funk_rec_t const *
fd_funk_rec_query_try( fd_funk_t *               funk,
                       fd_funk_txn_t const *     txn,
                       fd_funk_rec_key_t const * key,
                       fd_funk_rec_query_t *     query ) {
#ifdef FD_FUNK_HANDHOLDING
  if( FD_UNLIKELY( funk==NULL || key==NULL || query==NULL ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( txn && !fd_funk_txn_valid( funk, txn ) ) ) {
    return NULL;
  }
#endif

  fd_wksp_t * wksp          = fd_funk_wksp( funk );
  fd_funk_rec_map_t rec_map = fd_funk_rec_map( funk, wksp );
  fd_funk_xid_key_pair_t pair[1];
  if( txn == NULL ) {
    fd_funk_txn_xid_set_root( pair->xid );
  } else {
    fd_funk_txn_xid_copy( pair->xid, &txn->xid );
  }
  fd_funk_rec_key_copy( pair->key, key );
  for(;;) {
    int err = fd_funk_rec_map_query_try( &rec_map, pair, NULL, query );
    if( err == FD_MAP_SUCCESS )   break;
    if( err == FD_MAP_ERR_KEY )   return NULL;
    if( err == FD_MAP_ERR_AGAIN ) continue;
    FD_LOG_CRIT(( "query returned err %d", err ));
  }
  return fd_funk_rec_map_query_ele_const( query );
}

fd_funk_rec_t const *
fd_funk_rec_query_try_global( fd_funk_t *               funk,
                              fd_funk_txn_t const *     txn,
                              fd_funk_rec_key_t const * key,
                              fd_funk_txn_t const **    txn_out,
                              fd_funk_rec_query_t *     query ) {
#ifdef FD_FUNK_HANDHOLDING
  if( FD_UNLIKELY( funk==NULL || key==NULL || query==NULL ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( txn && !fd_funk_txn_valid( funk, txn ) ) ) {
    return NULL;
  }
#endif

  /* Look for the first element in the hash chain with the right
     record key. This takes advantage of the fact that elements with
     the same record key appear on the same hash chain in order of
     newest to oldest. */

  fd_wksp_t * wksp            = fd_funk_wksp( funk );
  fd_funk_rec_map_t rec_map   = fd_funk_rec_map( funk, wksp );
  fd_funk_txn_pool_t txn_pool = fd_funk_txn_pool( funk, wksp );

  fd_funk_xid_key_pair_t pair[1];
  if( txn == NULL ) {
    fd_funk_txn_xid_set_root( pair->xid );
  } else {
    fd_funk_txn_xid_copy( pair->xid, &txn->xid );
  }
  fd_funk_rec_key_copy( pair->key, key );
  ulong hash  = fd_funk_rec_map_key_hash( pair, rec_map.map->seed );
  ulong chain_idx = (hash & (rec_map.map->chain_cnt-1UL) );

  fd_funk_rec_map_shmem_private_chain_t * chain = (fd_funk_rec_map_shmem_private_chain_t *)(rec_map.map+1) + chain_idx;
  query->ele     = NULL;
  query->chain   = chain;
  query->ver_cnt = chain->ver_cnt; /* After unlock */

  for( fd_funk_rec_map_iter_t iter = fd_funk_rec_map_iter( &rec_map, chain_idx );
       !fd_funk_rec_map_iter_done( iter );
       iter = fd_funk_rec_map_iter_next( iter ) ) {
    fd_funk_rec_t const * ele = fd_funk_rec_map_iter_ele_const( iter );
    if( FD_LIKELY( hash == ele->map_hash ) && FD_LIKELY( fd_funk_rec_key_eq( key, ele->pair.key ) ) ) {

      /* For cur_txn in path from [txn] to [root] where root is NULL */

      for( fd_funk_txn_t const * cur_txn = txn; ; cur_txn = fd_funk_txn_parent( cur_txn, &txn_pool ) ) {
        /* If record ele is part of transaction cur_txn, we have a
           match. According to the property above, this will be the
           youngest descendent in the transaction stack. */

        int match = FD_UNLIKELY( cur_txn ) ? /* opt for root find (FIXME: eliminate branch with cmov into txn_xid_eq?) */
          fd_funk_txn_xid_eq( &cur_txn->xid, ele->pair.xid ) :
          fd_funk_txn_xid_eq_root( ele->pair.xid );

        if( FD_LIKELY( match ) ) {
          if( txn_out ) *txn_out = cur_txn;
          query->ele = ( FD_UNLIKELY( ele->flags & FD_FUNK_REC_FLAG_ERASE ) ? NULL :
                         (fd_funk_rec_t *)ele );
          return query->ele;
        }

        if( cur_txn == NULL ) break;
      }
    }
  }
  return NULL;
}

fd_funk_rec_t const *
fd_funk_rec_query_copy( fd_funk_t *               funk,
                        fd_funk_txn_t const *     txn,
                        fd_funk_rec_key_t const * key,
                        fd_valloc_t               valloc,
                        ulong *                   sz_out ) {
  *sz_out = ULONG_MAX;
  fd_funk_rec_map_t rec_map = fd_funk_rec_map( funk, fd_funk_wksp( funk ) );
  fd_funk_xid_key_pair_t pair[1];
  if( txn == NULL ) {
    fd_funk_txn_xid_set_root( pair->xid );
  } else {
    fd_funk_txn_xid_copy( pair->xid, &txn->xid );
  }
  fd_funk_rec_key_copy( pair->key, key );
  void * last_copy = NULL;
  ulong last_copy_sz = 0;
  for(;;) {
    fd_funk_rec_query_t query[1];
    int err = fd_funk_rec_map_query_try( &rec_map, pair, NULL, query );
    if( err == FD_MAP_ERR_KEY )   {
      if( last_copy ) fd_valloc_free( valloc, last_copy );
      return NULL;
    }
    if( err == FD_MAP_ERR_AGAIN ) continue;
    if( err != FD_MAP_SUCCESS )   FD_LOG_CRIT(( "query returned err %d", err ));
    fd_funk_rec_t const * rec = fd_funk_rec_map_query_ele_const( query );
    ulong sz = fd_funk_val_sz( rec );
    void * copy;
    if( sz <= last_copy_sz ) {
      copy = last_copy;
    } else {
      copy = last_copy = fd_valloc_malloc( valloc, 1, sz );
      last_copy_sz = sz;
    }
    memcpy( copy, fd_funk_val( rec, fd_funk_wksp( funk ) ), sz );
    *sz_out = sz;
    if( !fd_funk_rec_query_test( query ) ) return copy;
  }
}

int
fd_funk_rec_query_test( fd_funk_rec_query_t * query ) {
  return fd_funk_rec_map_query_test( query );
}

fd_funk_rec_t *
fd_funk_rec_prepare( fd_funk_t *               funk,
                     fd_funk_txn_t *           txn,
                     fd_funk_rec_key_t const * key,
                     fd_funk_rec_prepare_t *   prepare,
                     int *                     opt_err ) {
#ifdef FD_FUNK_HANDHOLDING
  if( FD_UNLIKELY( funk==NULL || key==NULL || prepare==NULL ) ) {
    fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_INVAL );
    return NULL;
  }
  if( FD_UNLIKELY( txn && !fd_funk_txn_valid( funk, txn ) ) ) {
    fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_INVAL );
    return NULL;
  }
#endif

  if( !txn ) { /* Modifying last published */
    if( FD_UNLIKELY( fd_funk_last_publish_is_frozen( funk ) ) ) {
      fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_FROZEN );
      return NULL;
    }
  } else {
    if( FD_UNLIKELY( fd_funk_txn_is_frozen( txn ) ) ) {
      fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_FROZEN );
      return NULL;
    }
  }

  prepare->funk = funk;
  prepare->wksp = fd_funk_wksp( funk );
  fd_funk_rec_pool_t rec_pool = fd_funk_rec_pool( funk, prepare->wksp );
  fd_funk_rec_t * rec = prepare->rec = fd_funk_rec_pool_acquire( &rec_pool, NULL, 1, opt_err );
  if( opt_err && *opt_err == FD_POOL_ERR_CORRUPT ) {
    FD_LOG_ERR(( "corrupt element returned from funk rec pool" ));
  }

  if( rec != NULL ) {
    if( txn == NULL ) {
      fd_funk_txn_xid_set_root( rec->pair.xid );
      rec->txn_cidx = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
      prepare->rec_head_idx = &funk->rec_head_idx;
      prepare->rec_tail_idx = &funk->rec_tail_idx;
      prepare->txn_lock     = &funk->lock;
    } else {
      fd_funk_txn_xid_copy( rec->pair.xid, &txn->xid );
      fd_funk_txn_pool_t txn_pool = fd_funk_txn_pool( funk, prepare->wksp );
      rec->txn_cidx = fd_funk_txn_cidx( (ulong)( txn - txn_pool.ele ) );
      prepare->rec_head_idx = &txn->rec_head_idx;
      prepare->rec_tail_idx = &txn->rec_tail_idx;
      prepare->txn_lock     = &txn->lock;
    }
    fd_funk_rec_key_copy( rec->pair.key, key );
    fd_funk_val_init( rec );
    rec->tag = 0;
    rec->flags = 0;
    rec->prev_idx = FD_FUNK_REC_IDX_NULL;
    rec->next_idx = FD_FUNK_REC_IDX_NULL;
  } else {
    fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_REC );
  }
  return rec;
}

void
fd_funk_rec_publish( fd_funk_rec_prepare_t * prepare ) {
  fd_funk_rec_t * rec = prepare->rec;
  uint * rec_head_idx = prepare->rec_head_idx;
  uint * rec_tail_idx = prepare->rec_tail_idx;
  fd_funk_rec_map_t rec_map = fd_funk_rec_map( prepare->funk, prepare->wksp );
  fd_funk_rec_pool_t rec_pool = fd_funk_rec_pool( prepare->funk, prepare->wksp );

  /* Lock the txn */
  while( FD_ATOMIC_CAS( prepare->txn_lock, 0, 1 ) ) FD_SPIN_PAUSE();

  uint rec_prev_idx;
  uint rec_idx  = (uint)( rec - rec_pool.ele );
  rec_prev_idx  = *rec_tail_idx;
  *rec_tail_idx = rec_idx;
  rec->prev_idx = rec_prev_idx;
  rec->next_idx = FD_FUNK_REC_IDX_NULL;
  if( fd_funk_rec_idx_is_null( rec_prev_idx ) ) {
    *rec_head_idx = rec_idx;
  } else {
    rec_pool.ele[ rec_prev_idx ].next_idx = rec_idx;
  }

  if( fd_funk_rec_map_insert( &rec_map, rec, FD_MAP_FLAG_BLOCKING ) ) {
    FD_LOG_CRIT(( "fd_funk_rec_map_insert failed" ));
  }

  FD_VOLATILE( *prepare->txn_lock ) = 0;
}

void
fd_funk_rec_cancel( fd_funk_rec_prepare_t * prepare ) {
  fd_funk_val_flush( prepare->rec, fd_funk_alloc( prepare->funk, prepare->wksp ), prepare->wksp );
  fd_funk_rec_pool_t rec_pool = fd_funk_rec_pool( prepare->funk, prepare->wksp );
  fd_funk_rec_pool_release( &rec_pool, prepare->rec, 1 );
}

fd_funk_rec_t *
fd_funk_rec_clone( fd_funk_t *               funk,
                   fd_funk_txn_t *           txn,
                   fd_funk_rec_key_t const * key,
                   fd_funk_rec_prepare_t *   prepare,
                   int *                     opt_err ) {
  fd_funk_rec_t * new_rec = fd_funk_rec_prepare( funk, txn, key, prepare, opt_err );
  if( !new_rec ) return NULL;

  for(;;) {
    fd_funk_rec_query_t query[1];
    fd_funk_rec_t const * old_rec = fd_funk_rec_query_try_global( funk, txn, key, NULL, query );
    if( !old_rec ) {
      fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_KEY );
      fd_funk_rec_cancel( prepare );
      return NULL;
    }

    fd_wksp_t * wksp = fd_funk_wksp( funk );
    ulong val_sz     = old_rec->val_sz;
    void * buf = fd_funk_val_truncate( new_rec, val_sz, fd_funk_alloc( funk, wksp ), wksp, opt_err );
    if( !buf ) {
      fd_funk_rec_cancel( prepare );
      return NULL;
    }
    memcpy( buf, fd_funk_val( old_rec, wksp ), val_sz );

    if( !fd_funk_rec_query_test( query ) ) {
      return new_rec;
    }
  }
}

int
fd_funk_rec_is_full( fd_funk_t * funk ) {
  fd_wksp_t * wksp            = fd_funk_wksp( funk );
  fd_funk_rec_pool_t rec_pool = fd_funk_rec_pool( funk, wksp );
  return fd_funk_rec_pool_is_empty( &rec_pool );
}

void
fd_funk_rec_hard_remove( fd_funk_t *               funk,
                         fd_funk_txn_t *           txn,
                         fd_funk_rec_key_t const * key ) {

  fd_wksp_t * wksp            = fd_funk_wksp( funk );
  fd_alloc_t * alloc          = fd_funk_alloc( funk, wksp );
  fd_funk_rec_map_t rec_map   = fd_funk_rec_map( funk, wksp );
  fd_funk_rec_pool_t rec_pool = fd_funk_rec_pool( funk, wksp );

  fd_funk_xid_key_pair_t pair[1];
  if( txn == NULL ) {
    fd_funk_txn_xid_set_root( pair->xid );
  } else {
    fd_funk_txn_xid_copy( pair->xid, &txn->xid );
  }
  fd_funk_rec_key_copy( pair->key, key );

  fd_funk_rec_pool_lock( &rec_pool, 1 );

  fd_funk_rec_t * rec = NULL;
  for(;;) {
    fd_funk_rec_map_query_t rec_query[1];
    int err = fd_funk_rec_map_remove( &rec_map, pair, NULL, rec_query, FD_MAP_FLAG_BLOCKING );
    if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
    if( err == FD_MAP_ERR_KEY ) {
      fd_funk_rec_pool_unlock( &rec_pool );
      return;
    }
    if( FD_UNLIKELY( err != FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "map corruption" ));
    rec = fd_funk_rec_map_query_ele( rec_query );
    break;
  }

  uint prev_idx = rec->prev_idx;
  uint next_idx = rec->next_idx;
  if( txn == NULL ) {
    if( fd_funk_rec_idx_is_null( prev_idx ) ) funk->rec_head_idx =                next_idx;
    else                                         rec_pool.ele[ prev_idx ].next_idx = next_idx;
    if( fd_funk_rec_idx_is_null( next_idx ) ) funk->rec_tail_idx =                prev_idx;
    else                                         rec_pool.ele[ next_idx ].prev_idx = prev_idx;
  } else {
    if( fd_funk_rec_idx_is_null( prev_idx ) ) txn->rec_head_idx =                next_idx;
    else                                         rec_pool.ele[ prev_idx ].next_idx = next_idx;
    if( fd_funk_rec_idx_is_null( next_idx ) ) txn->rec_tail_idx =                prev_idx;
    else                                         rec_pool.ele[ next_idx ].prev_idx = prev_idx;
  }
  fd_funk_rec_pool_unlock( &rec_pool );

  fd_funk_val_flush( rec, alloc, wksp );
  fd_funk_rec_pool_release( &rec_pool, rec, 1 );
}

int
fd_funk_rec_remove( fd_funk_t *               funk,
                    fd_funk_txn_t *           txn,
                    fd_funk_rec_key_t const * key,
                    fd_funk_rec_t **          rec_out,
                    ulong                     erase_data ) {
#ifdef FD_FUNK_HANDHOLDING
  if( FD_UNLIKELY( funk==NULL || key==NULL ) ) {
    return FD_FUNK_ERR_INVAL;
  }
  if( FD_UNLIKELY( txn && !fd_funk_txn_valid( funk, txn ) ) ) {
    return FD_FUNK_ERR_INVAL;
  }
#endif

  if( !txn ) { /* Modifying last published */
    if( FD_UNLIKELY( fd_funk_last_publish_is_frozen( funk ) ) ) {
      return FD_FUNK_ERR_FROZEN;
    }
  } else {
    if( FD_UNLIKELY( fd_funk_txn_is_frozen( txn ) ) ) {
      return FD_FUNK_ERR_FROZEN;
    }
  }

  fd_wksp_t * wksp          = fd_funk_wksp( funk );
  fd_funk_rec_map_t rec_map = fd_funk_rec_map( funk, wksp );
  fd_funk_xid_key_pair_t pair[1];
  if( txn == NULL ) {
    fd_funk_txn_xid_set_root( pair->xid );
  } else {
    fd_funk_txn_xid_copy( pair->xid, &txn->xid );
  }
  fd_funk_rec_key_copy( pair->key, key );
  fd_funk_rec_query_t query[ 1 ];
  for(;;) {
    int err = fd_funk_rec_map_query_try( &rec_map, pair, NULL, query );
    if( err == FD_MAP_SUCCESS )   break;
    if( err == FD_MAP_ERR_KEY )   return FD_FUNK_SUCCESS;
    if( err == FD_MAP_ERR_AGAIN ) continue;
    FD_LOG_CRIT(( "query returned err %d", err ));
  }

  fd_funk_rec_t * rec = fd_funk_rec_map_query_ele( query );
  if( rec_out ) *rec_out = rec;

  /* Access the flags atomically */
  ulong old_flags;
  for(;;) {
    old_flags = rec->flags;
    if( FD_UNLIKELY( old_flags & FD_FUNK_REC_FLAG_ERASE ) ) return FD_FUNK_SUCCESS;
    if( FD_ATOMIC_CAS( &rec->flags, old_flags, old_flags | FD_FUNK_REC_FLAG_ERASE ) == old_flags ) break;
  }

  /* Flush the value and leave a tombstone behind. In theory, this can
     lead to an unbounded number of records, but for application
     reasons, we need to remember what was deleted. */

  fd_funk_val_flush( rec, fd_funk_alloc( funk, wksp ), wksp );

  /* At this point, the 5 most significant bytes should store data about the
     transaction that the record was updated in. */

  fd_funk_rec_set_erase_data( rec, erase_data );

  return FD_FUNK_SUCCESS;
}

void
fd_funk_rec_set_erase_data( fd_funk_rec_t * rec, ulong erase_data ) {
  rec->flags |= ((erase_data & 0xFFFFFFFFFFUL) << (sizeof(unsigned long) * 8 - 40));
}

ulong
fd_funk_rec_get_erase_data( fd_funk_rec_t const * rec ) {
  return (rec->flags >> (sizeof(unsigned long) * 8 - 40)) & 0xFFFFFFFFFFUL;
}

int
fd_funk_rec_forget( fd_funk_t *      funk,
                    fd_funk_rec_t ** recs,
                    ulong            recs_cnt ) {
#ifdef FD_FUNK_HANDHOLDING
  if( FD_UNLIKELY( !funk ) ) return FD_FUNK_ERR_INVAL;
#endif

  fd_wksp_t * wksp            = fd_funk_wksp( funk );
  fd_alloc_t * alloc          = fd_funk_alloc( funk, wksp );
  fd_funk_rec_map_t rec_map   = fd_funk_rec_map( funk, wksp );
  fd_funk_rec_pool_t rec_pool = fd_funk_rec_pool( funk, wksp );

#ifdef FD_FUNK_HANDHOLDING
  ulong rec_max = funk->rec_max;
#endif

  for( ulong i = 0; i < recs_cnt; ++i ) {
    fd_funk_rec_t * rec = recs[i];

#ifdef FD_FUNK_HANDHOLDING
    ulong rec_idx = (ulong)(rec - rec_pool.ele);
    if( FD_UNLIKELY( (rec_idx>=rec_max) /* Out of map (incl NULL) */ | (rec!=(rec_pool.ele+rec_idx)) /* Bad alignment */ ) )
      return FD_FUNK_ERR_INVAL;
#endif

    ulong txn_idx = fd_funk_txn_idx( rec->txn_cidx );
    if( FD_UNLIKELY( !fd_funk_txn_idx_is_null( txn_idx ) || /* Must be published */
                     !( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) ) { /* Must be removed */
      return FD_FUNK_ERR_KEY;
    }

    for(;;) {
      fd_funk_rec_map_query_t rec_query[1];
      int err = fd_funk_rec_map_remove( &rec_map, fd_funk_rec_pair( rec ), NULL, rec_query, FD_MAP_FLAG_BLOCKING );
      if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
      if( err == FD_MAP_ERR_KEY ) return FD_FUNK_ERR_KEY;
      if( FD_UNLIKELY( err != FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "map corruption" ));
      if( rec != fd_funk_rec_map_query_ele( rec_query ) ) FD_LOG_CRIT(( "map corruption" ));
      break;
    }

    uint prev_idx = rec->prev_idx;
    uint next_idx = rec->next_idx;
    if( fd_funk_rec_idx_is_null( prev_idx ) ) funk->rec_head_idx =                next_idx;
    else                                         rec_pool.ele[ prev_idx ].next_idx = next_idx;
    if( fd_funk_rec_idx_is_null( next_idx ) ) funk->rec_tail_idx =                prev_idx;
    else                                         rec_pool.ele[ next_idx ].prev_idx = prev_idx;

    fd_funk_val_flush( rec, alloc, wksp );
    fd_funk_rec_pool_release( &rec_pool, rec, 1 );
  }

  return FD_FUNK_SUCCESS;
}

static void
fd_funk_all_iter_skip_nulls( fd_funk_all_iter_t * iter ) {
  if( iter->chain_idx == iter->chain_cnt ) return;
  while( fd_funk_rec_map_iter_done( iter->rec_map_iter ) ) {
    if( ++(iter->chain_idx) == iter->chain_cnt ) break;
    iter->rec_map_iter = fd_funk_rec_map_iter( &iter->rec_map, iter->chain_idx );
  }
}

void
fd_funk_all_iter_new( fd_funk_t * funk, fd_funk_all_iter_t * iter ) {
  fd_wksp_t * wksp   = fd_funk_wksp( funk );
  iter->rec_map      = fd_funk_rec_map( funk, wksp );
  iter->chain_cnt    = fd_funk_rec_map_chain_cnt( &iter->rec_map );
  iter->chain_idx    = 0;
  iter->rec_map_iter = fd_funk_rec_map_iter( &iter->rec_map, 0 );
  fd_funk_all_iter_skip_nulls( iter );
}

int
fd_funk_all_iter_done( fd_funk_all_iter_t * iter ) {
  return ( iter->chain_idx == iter->chain_cnt );
}

void
fd_funk_all_iter_next( fd_funk_all_iter_t * iter ) {
  iter->rec_map_iter = fd_funk_rec_map_iter_next( iter->rec_map_iter );
  fd_funk_all_iter_skip_nulls( iter );
}

fd_funk_rec_t const *
fd_funk_all_iter_ele_const( fd_funk_all_iter_t * iter ) {
  return fd_funk_rec_map_iter_ele_const( iter->rec_map_iter );
}

fd_funk_rec_t *
fd_funk_all_iter_ele( fd_funk_all_iter_t * iter ) {
  return fd_funk_rec_map_iter_ele( iter->rec_map_iter );
}

#ifdef FD_FUNK_HANDHOLDING
int
fd_funk_rec_verify( fd_funk_t * funk ) {
  fd_wksp_t *           wksp     = fd_funk_wksp( funk );          /* Previously verified */
  fd_funk_txn_map_t  txn_map  = fd_funk_txn_map( funk, wksp ); /* Previously verified */
  fd_funk_rec_map_t  rec_map  = fd_funk_rec_map( funk, wksp ); /* Previously verified */
  fd_funk_txn_pool_t txn_pool = fd_funk_txn_pool( funk, wksp ); /* Previously verified */
  fd_funk_rec_pool_t rec_pool = fd_funk_rec_pool( funk, wksp ); /* Previously verified */
  ulong                 txn_max  = funk->txn_max;                 /* Previously verified */
  ulong                 rec_max  = funk->rec_max;                 /* Previously verified */

  /* At this point, txn_map has been extensively verified */

# define TEST(c) do {                                                                           \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return FD_FUNK_ERR_INVAL; } \
  } while(0)

  TEST( !fd_funk_rec_map_verify( &rec_map ) );
  TEST( !fd_funk_rec_pool_verify( &rec_pool ) );

  /* Iterate over all records in use */

  fd_funk_all_iter_t iter[1];
  for( fd_funk_all_iter_new( funk, iter ); !fd_funk_all_iter_done( iter ); fd_funk_all_iter_next( iter ) ) {
    fd_funk_rec_t const * rec = fd_funk_all_iter_ele_const( iter );

    /* Make sure every record either links up with the last published
       transaction or an in-prep transaction and the flags are sane. */

    fd_funk_txn_xid_t const * txn_xid = fd_funk_rec_xid( rec );
    ulong                        txn_idx = fd_funk_txn_idx( rec->txn_cidx );

    if( fd_funk_txn_idx_is_null( txn_idx ) ) { /* This is a record from the last published transaction */

      TEST( fd_funk_txn_xid_eq_root( txn_xid ) );

    } else { /* This is a record from an in-prep transaction */

      TEST( txn_idx<txn_max );
      fd_funk_txn_t const * txn = fd_funk_txn_query( txn_xid, &txn_map );
      TEST( txn );
      TEST( txn==(txn_pool.ele+txn_idx) );

    }
  }

  /* Clear record tags and then verify the forward and reverse linkage */

  for( ulong rec_idx=0UL; rec_idx<rec_max; rec_idx++ ) rec_pool.ele[ rec_idx ].tag = 0U;

  do {
    ulong txn_idx = FD_FUNK_TXN_IDX_NULL;
    uint rec_idx = funk->rec_head_idx;
    while( !fd_funk_rec_idx_is_null( rec_idx ) ) {
      TEST( (rec_idx<rec_max) && (fd_funk_txn_idx( rec_pool.ele[ rec_idx ].txn_cidx )==txn_idx) && rec_pool.ele[ rec_idx ].tag==0U );
      rec_pool.ele[ rec_idx ].tag = 1U;
      fd_funk_rec_query_t query[1];
      fd_funk_rec_t const * rec2 = fd_funk_rec_query_try_global( funk, NULL, rec_pool.ele[ rec_idx ].pair.key, NULL, query );
      if( FD_UNLIKELY( rec_pool.ele[ rec_idx ].flags & FD_FUNK_REC_FLAG_ERASE ) )
        TEST( rec2 == NULL );
      else
        TEST( rec2 = rec_pool.ele + rec_idx );
      uint next_idx = rec_pool.ele[ rec_idx ].next_idx;
      if( !fd_funk_rec_idx_is_null( next_idx ) ) TEST( rec_pool.ele[ next_idx ].prev_idx==rec_idx );
      rec_idx = next_idx;
    }
    fd_funk_txn_all_iter_t txn_iter[1];
    for( fd_funk_txn_all_iter_new( funk, txn_iter ); !fd_funk_txn_all_iter_done( txn_iter ); fd_funk_txn_all_iter_next( txn_iter ) ) {
      fd_funk_txn_t const * txn = fd_funk_txn_all_iter_ele_const( txn_iter );

      ulong txn_idx = (ulong)(txn-txn_pool.ele);
      uint rec_idx = txn->rec_head_idx;
      while( !fd_funk_rec_idx_is_null( rec_idx ) ) {
        TEST( (rec_idx<rec_max) && (fd_funk_txn_idx( rec_pool.ele[ rec_idx ].txn_cidx )==txn_idx) && rec_pool.ele[ rec_idx ].tag==0U );
        rec_pool.ele[ rec_idx ].tag = 1U;
        fd_funk_rec_query_t query[1];
        fd_funk_rec_t const * rec2 = fd_funk_rec_query_try_global( funk, txn, rec_pool.ele[ rec_idx ].pair.key, NULL, query );
        if( FD_UNLIKELY( rec_pool.ele[ rec_idx ].flags & FD_FUNK_REC_FLAG_ERASE ) )
          TEST( rec2 == NULL );
        else
          TEST( rec2 = rec_pool.ele + rec_idx );
        uint next_idx = rec_pool.ele[ rec_idx ].next_idx;
        if( !fd_funk_rec_idx_is_null( next_idx ) ) TEST( rec_pool.ele[ next_idx ].prev_idx==rec_idx );
        rec_idx = next_idx;
      }
    }
  } while(0);

  do {
    ulong txn_idx = FD_FUNK_TXN_IDX_NULL;
    uint rec_idx = funk->rec_tail_idx;
    while( !fd_funk_rec_idx_is_null( rec_idx ) ) {
      TEST( (rec_idx<rec_max) && (fd_funk_txn_idx( rec_pool.ele[ rec_idx ].txn_cidx )==txn_idx) && rec_pool.ele[ rec_idx ].tag==1U );
      rec_pool.ele[ rec_idx ].tag = 2U;
      uint prev_idx = rec_pool.ele[ rec_idx ].prev_idx;
      if( !fd_funk_rec_idx_is_null( prev_idx ) ) TEST( rec_pool.ele[ prev_idx ].next_idx==rec_idx );
      rec_idx = prev_idx;
    }

    fd_funk_txn_all_iter_t txn_iter[1];
    for( fd_funk_txn_all_iter_new( funk, txn_iter ); !fd_funk_txn_all_iter_done( txn_iter ); fd_funk_txn_all_iter_next( txn_iter ) ) {
      fd_funk_txn_t const * txn = fd_funk_txn_all_iter_ele_const( txn_iter );

      uint txn_idx = (uint)(txn-txn_pool.ele);
      uint rec_idx = txn->rec_tail_idx;
      while( !fd_funk_rec_idx_is_null( rec_idx ) ) {
        TEST( (rec_idx<rec_max) && (fd_funk_txn_idx( rec_pool.ele[ rec_idx ].txn_cidx )==txn_idx) && rec_pool.ele[ rec_idx ].tag==1U );
        rec_pool.ele[ rec_idx ].tag = 2U;
        uint prev_idx = rec_pool.ele[ rec_idx ].prev_idx;
        if( !fd_funk_rec_idx_is_null( prev_idx ) ) TEST( rec_pool.ele[ prev_idx ].next_idx==rec_idx );
        rec_idx = prev_idx;
      }
    }
  } while(0);

# undef TEST

  return FD_FUNK_SUCCESS;
}
#endif

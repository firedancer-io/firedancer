#include "fd_funkier.h"

/* Provide the actual record map implementation */

#define POOL_NAME          fd_funkier_rec_pool
#define POOL_ELE_T         fd_funkier_rec_t
#define POOL_IDX_T         uint
#define POOL_NEXT          map_next
#define POOL_IMPL_STYLE    2
#include "../util/tmpl/fd_pool_para.c"

#define MAP_NAME              fd_funkier_rec_map
#define MAP_ELE_T             fd_funkier_rec_t
#define MAP_KEY_T             fd_funkier_xid_key_pair_t
#define MAP_KEY               pair
#define MAP_KEY_EQ(k0,k1)     fd_funkier_xid_key_pair_eq((k0),(k1))
#define MAP_KEY_HASH(k0,seed) fd_funkier_xid_key_pair_hash((k0),(seed))
#define MAP_NEXT              map_next
#define MAP_MEMO              map_hash
#define MAP_MAGIC             (0xf173da2ce77ecdb0UL) /* Firedancer rec db version 0 */
#define MAP_MEMOIZE           1
#define MAP_IMPL_STYLE        2
#include "../util/tmpl/fd_map_para.c"

fd_funkier_rec_t const *
fd_funkier_rec_query_try( fd_funkier_t *               funk,
                          fd_funkier_txn_t const *     txn,
                          fd_funkier_rec_key_t const * key,
                          fd_funkier_rec_query_t *     query ) {
#ifdef FD_FUNKIER_HANDHOLDING
  if( FD_UNLIKELY( funk==NULL || key==NULL || query==NULL ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( txn && !fd_funkier_txn_valid( funk, txn ) ) ) {
    return NULL;
  }
#endif

  fd_wksp_t * wksp = fd_funkier_wksp( funk );
  fd_funkier_rec_map_t rec_map = fd_funkier_rec_map( funk, wksp );
  fd_funkier_xid_key_pair_t pair[1];
  if( txn == NULL ) {
    fd_funkier_txn_xid_set_root( pair->xid );
  } else {
    fd_funkier_txn_xid_copy( pair->xid, &txn->xid );
  }
  fd_funkier_rec_key_copy( pair->key, key );
  for(;;) {
    int err = fd_funkier_rec_map_query_try( &rec_map, pair, NULL, query );
    if( err == FD_MAP_SUCCESS )   break;
    if( err == FD_MAP_ERR_KEY )   return NULL;
    if( err == FD_MAP_ERR_AGAIN ) continue;
    FD_LOG_CRIT(( "query returned err %d", err ));
  }
  return fd_funkier_rec_map_query_ele_const( query );
}

fd_funkier_rec_t const *
fd_funkier_rec_query_try_global( fd_funkier_t *               funk,
                                 fd_funkier_txn_t const *     txn,
                                 fd_funkier_rec_key_t const * key,
                                 fd_funkier_txn_t const **    txn_out,
                                 fd_funkier_rec_query_t *     query ) {
#ifdef FD_FUNKIER_HANDHOLDING
  if( FD_UNLIKELY( funk==NULL || key==NULL || query==NULL ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( txn && !fd_funkier_txn_valid( funk, txn ) ) ) {
    return NULL;
  }
#endif

  /* Look for the first element in the hash chain with the right
     record key. This takes advantage of the fact that elements with
     the same record key appear on the same hash chain in order of
     newest to oldest. */

  fd_wksp_t * wksp = fd_funkier_wksp( funk );
  fd_funkier_rec_map_t rec_map = fd_funkier_rec_map( funk, wksp );
  fd_funkier_txn_pool_t txn_pool = fd_funkier_txn_pool( funk, wksp );

  fd_funkier_xid_key_pair_t pair[1];
  if( txn == NULL ) {
    fd_funkier_txn_xid_set_root( pair->xid );
  } else {
    fd_funkier_txn_xid_copy( pair->xid, &txn->xid );
  }
  fd_funkier_rec_key_copy( pair->key, key );
  ulong hash  = fd_funkier_rec_map_key_hash( pair, rec_map.map->seed );
  ulong chain_idx = (hash & (rec_map.map->chain_cnt-1UL) );
  if( fd_funkier_rec_map_iter_lock( &rec_map, &chain_idx, 1, FD_MAP_FLAG_BLOCKING) ) {
    FD_LOG_CRIT(( "failed to lock hash chain" ));
  }

  fd_funkier_rec_map_shmem_private_chain_t * chain = (fd_funkier_rec_map_shmem_private_chain_t *)(rec_map.map+1) + chain_idx;
  query->ele     = NULL;
  query->chain   = chain;
  query->ver_cnt = chain->ver_cnt + (1UL<<43U); /* After unlock */

  for( fd_funkier_rec_map_iter_t iter = fd_funkier_rec_map_iter( &rec_map, chain_idx );
       !fd_funkier_rec_map_iter_done( iter );
       iter = fd_funkier_rec_map_iter_next( iter ) ) {
    fd_funkier_rec_t const * ele = fd_funkier_rec_map_iter_ele_const( iter );
    if( FD_LIKELY( hash == ele->map_hash ) && FD_LIKELY( fd_funkier_rec_key_eq( key, ele->pair.key ) ) ) {

      /* For cur_txn in path from [txn] to [root] where root is NULL */

      for( fd_funkier_txn_t const * cur_txn = txn; ; cur_txn = fd_funkier_txn_parent( cur_txn, &txn_pool ) ) {
        /* If record ele is part of transaction cur_txn, we have a
           match. According to the property above, this will be the
           youngest descendent in the transaction stack. */

        int match = FD_UNLIKELY( cur_txn ) ? /* opt for root find (FIXME: eliminate branch with cmov into txn_xid_eq?) */
          fd_funkier_txn_xid_eq( &cur_txn->xid, ele->pair.xid ) :
          fd_funkier_txn_xid_eq_root( ele->pair.xid );

        if( FD_LIKELY( match ) ) {
          if( txn_out ) *txn_out = cur_txn;
          query->ele = ( FD_UNLIKELY( ele->flags & FD_FUNKIER_REC_FLAG_ERASE ) ? NULL :
                         (fd_funkier_rec_t *)ele );
          fd_funkier_rec_map_iter_unlock( &rec_map, &chain_idx, 1 );
          return query->ele;
        }

        if( cur_txn == NULL ) break;
      }
    }
  }
  fd_funkier_rec_map_iter_unlock( &rec_map, &chain_idx, 1 );
  return NULL;
}

int
fd_funkier_rec_query_test( fd_funkier_rec_query_t * query ) {
  return fd_funkier_rec_map_query_test( query );
}

fd_funkier_rec_t *
fd_funkier_rec_prepare( fd_funkier_t *               funk,
                        fd_funkier_txn_t *           txn,
                        fd_funkier_rec_key_t const * key,
                        fd_funkier_rec_prepare_t *   prepare,
                        int *                        opt_err ) {
#ifdef FD_FUNKIER_HANDHOLDING
  if( FD_UNLIKELY( funk==NULL || key==NULL || prepare==NULL ) ) {
    fd_int_store_if( !!opt_err, opt_err, FD_FUNKIER_ERR_INVAL );
    return NULL;
  }
  if( FD_UNLIKELY( txn && !fd_funkier_txn_valid( funk, txn ) ) ) {
    fd_int_store_if( !!opt_err, opt_err, FD_FUNKIER_ERR_INVAL );
    return NULL;
  }
#endif

  if( !txn ) { /* Modifying last published */
    if( FD_UNLIKELY( fd_funkier_last_publish_is_frozen( funk ) ) ) {
      fd_int_store_if( !!opt_err, opt_err, FD_FUNKIER_ERR_FROZEN );
      return NULL;
    }
  } else {
    if( FD_UNLIKELY( fd_funkier_txn_is_frozen( txn ) ) ) {
      fd_int_store_if( !!opt_err, opt_err, FD_FUNKIER_ERR_FROZEN );
      return NULL;
    }
  }

  fd_wksp_t * wksp = fd_funkier_wksp( funk );
  prepare->rec_map = fd_funkier_rec_map( funk, wksp );
  prepare->rec_pool = fd_funkier_rec_pool( funk, wksp );
  fd_funkier_rec_t * rec = prepare->rec = fd_funkier_rec_pool_acquire( &prepare->rec_pool, NULL, 1, opt_err );
  if( rec != NULL ) {
    if( txn == NULL ) {
      fd_funkier_txn_xid_set_root( rec->pair.xid );
      rec->txn_cidx = fd_funkier_txn_cidx( FD_FUNKIER_TXN_IDX_NULL );
      prepare->rec_head_idx = &funk->rec_head_idx;
      prepare->rec_tail_idx = &funk->rec_tail_idx;
    } else {
      fd_funkier_txn_xid_copy( rec->pair.xid, &txn->xid );
      fd_funkier_txn_pool_t txn_pool = fd_funkier_txn_pool( funk, wksp );
      rec->txn_cidx = fd_funkier_txn_cidx( (ulong)( txn - txn_pool.ele ) );
      prepare->rec_head_idx = &txn->rec_head_idx;
      prepare->rec_tail_idx = &txn->rec_tail_idx;
    }
    fd_funkier_rec_key_copy( rec->pair.key, key );
    fd_funkier_val_init( rec );
    rec->tag = 0;
    rec->flags = 0;
    rec->prev_idx = FD_FUNKIER_REC_IDX_NULL;
    rec->next_idx = FD_FUNKIER_REC_IDX_NULL;
  } else {
    fd_int_store_if( !!opt_err, opt_err, FD_FUNKIER_ERR_REC );
  }
  return rec;
}

void
fd_funkier_rec_publish( fd_funkier_rec_prepare_t * prepare ) {
  fd_funkier_rec_t * rec = prepare->rec;
  ulong * rec_head_idx = prepare->rec_head_idx;
  ulong * rec_tail_idx = prepare->rec_tail_idx;
  /* Use the tail idx to establish an order even if there is concurrency */
  ulong rec_prev_idx;
  ulong rec_idx = (ulong)( rec - prepare->rec_pool.ele );
  for(;;) {
    rec_prev_idx = *rec_tail_idx;
    if( FD_ATOMIC_CAS( rec_tail_idx, rec_prev_idx, rec_idx ) == rec_prev_idx ) break;
  }
  rec->prev_idx = rec_prev_idx;
  if( fd_funkier_rec_idx_is_null( rec_prev_idx ) ) {
    *rec_head_idx = rec_idx;
  } else {
    prepare->rec_pool.ele[ rec_prev_idx ].next_idx = rec_idx;
  }

  if( fd_funkier_rec_map_insert( &prepare->rec_map, rec, FD_MAP_FLAG_BLOCKING ) ) {
    FD_LOG_CRIT(( "fd_funkier_rec_map_insert failed" ));
  }
}

void
fd_funkier_rec_cancel( fd_funkier_rec_prepare_t * prepare ) {
  fd_funkier_rec_pool_release( &prepare->rec_pool, prepare->rec, 1 );
}

int
fd_funkier_rec_is_full( fd_funkier_t * funk ) {
  fd_wksp_t * wksp = fd_funkier_wksp( funk );
  fd_funkier_rec_pool_t rec_pool = fd_funkier_rec_pool( funk, wksp );
  return fd_funkier_rec_pool_is_empty( &rec_pool );
}

int
fd_funkier_rec_remove( fd_funkier_t *               funk,
                       fd_funkier_txn_t *           txn,
                       fd_funkier_rec_key_t const * key,
                       fd_funkier_rec_t **          rec_out,
                       ulong                        erase_data ) {
#ifdef FD_FUNKIER_HANDHOLDING
  if( FD_UNLIKELY( funk==NULL || key==NULL ) ) {
    return FD_FUNKIER_ERR_INVAL;
  }
  if( FD_UNLIKELY( txn && !fd_funkier_txn_valid( funk, txn ) ) ) {
    return FD_FUNKIER_ERR_INVAL;
  }
#endif

  if( !txn ) { /* Modifying last published */
    if( FD_UNLIKELY( fd_funkier_last_publish_is_frozen( funk ) ) ) {
      return FD_FUNKIER_ERR_FROZEN;
    }
  } else {
    if( FD_UNLIKELY( fd_funkier_txn_is_frozen( txn ) ) ) {
      return FD_FUNKIER_ERR_FROZEN;
    }
  }

  fd_wksp_t * wksp = fd_funkier_wksp( funk );
  fd_funkier_rec_map_t rec_map = fd_funkier_rec_map( funk, wksp );
  fd_funkier_xid_key_pair_t pair[1];
  if( txn == NULL ) {
    fd_funkier_txn_xid_set_root( pair->xid );
  } else {
    fd_funkier_txn_xid_copy( pair->xid, &txn->xid );
  }
  fd_funkier_rec_key_copy( pair->key, key );
  fd_funkier_rec_query_t query[ 1 ];
  for(;;) {
    int err = fd_funkier_rec_map_query_try( &rec_map, pair, NULL, query );
    if( err == FD_MAP_SUCCESS )   break;
    if( err == FD_MAP_ERR_KEY )   return FD_FUNKIER_SUCCESS;
    if( err == FD_MAP_ERR_AGAIN ) continue;
    FD_LOG_CRIT(( "query returned err %d", err ));
  }

  fd_funkier_rec_t * rec = fd_funkier_rec_map_query_ele( query );
  if( rec_out ) *rec_out = rec;

  /* Access the flags atomically */
  ulong old_flags;
  for(;;) {
    old_flags = rec->flags;
    if( FD_UNLIKELY( old_flags & FD_FUNKIER_REC_FLAG_ERASE ) ) return FD_FUNKIER_SUCCESS;
    if( FD_ATOMIC_CAS( &rec->flags, old_flags, old_flags | FD_FUNKIER_REC_FLAG_ERASE ) == old_flags ) break;
  }

  /* Flush the value and leave a tombstone behind. In theory, this can
     lead to an unbounded number of records, but for application
     reasons, we need to remember what was deleted. */

  fd_funkier_val_flush( rec, fd_funkier_alloc( funk, wksp ), wksp );

  /* At this point, the 5 most significant bytes should store data about the
     transaction that the record was updated in. */

  fd_funkier_rec_set_erase_data( rec, erase_data );

  return FD_FUNKIER_SUCCESS;
}

void
fd_funkier_rec_set_erase_data( fd_funkier_rec_t * rec, ulong erase_data ) {
  rec->flags |= ((erase_data & 0xFFFFFFFFFFUL) << (sizeof(unsigned long) * 8 - 40));
}

ulong
fd_funkier_rec_get_erase_data( fd_funkier_rec_t const * rec ) {
  return (rec->flags >> (sizeof(unsigned long) * 8 - 40)) & 0xFFFFFFFFFFUL;
}

static void
fd_funkier_all_iter_skip_nulls( fd_funkier_all_iter_t * iter ) {
  if( iter->chain_idx == iter->chain_cnt ) return;
  while( fd_funkier_rec_map_iter_done( iter->rec_map_iter ) ) {
    if( ++(iter->chain_idx) == iter->chain_cnt ) break;
    iter->rec_map_iter = fd_funkier_rec_map_iter( &iter->rec_map, iter->chain_idx );
  }
}

void
fd_funkier_all_iter_new( fd_funkier_t * funk, fd_funkier_all_iter_t * iter ) {
  fd_wksp_t * wksp = fd_funkier_wksp( funk );
  iter->rec_map = fd_funkier_rec_map( funk, wksp );
  iter->chain_cnt = fd_funkier_rec_map_chain_cnt( &iter->rec_map );
  iter->chain_idx = 0;
  iter->rec_map_iter = fd_funkier_rec_map_iter( &iter->rec_map, 0 );
  fd_funkier_all_iter_skip_nulls( iter );
}

int
fd_funkier_all_iter_done( fd_funkier_all_iter_t * iter ) {
  return ( iter->chain_idx == iter->chain_cnt );
}

void
fd_funkier_all_iter_next( fd_funkier_all_iter_t * iter ) {
  iter->rec_map_iter = fd_funkier_rec_map_iter_next( iter->rec_map_iter );
  fd_funkier_all_iter_skip_nulls( iter );
}

fd_funkier_rec_t const *
fd_funkier_all_iter_ele_const( fd_funkier_all_iter_t * iter ) {
  return fd_funkier_rec_map_iter_ele_const( iter->rec_map_iter );
}

#ifdef FD_FUNKIER_HANDHOLDING
int
fd_funkier_rec_verify( fd_funkier_t * funk ) {
  fd_wksp_t *           wksp     = fd_funkier_wksp( funk );          /* Previously verified */
  fd_funkier_txn_map_t  txn_map  = fd_funkier_txn_map( funk, wksp ); /* Previously verified */
  fd_funkier_rec_map_t  rec_map  = fd_funkier_rec_map( funk, wksp ); /* Previously verified */
  fd_funkier_txn_pool_t txn_pool = fd_funkier_txn_pool( funk, wksp ); /* Previously verified */
  fd_funkier_rec_pool_t rec_pool = fd_funkier_rec_pool( funk, wksp ); /* Previously verified */
  ulong                 txn_max  = funk->txn_max;                 /* Previously verified */
  ulong                 rec_max  = funk->rec_max;                 /* Previously verified */

  /* At this point, txn_map has been extensively verified */

# define TEST(c) do {                                                                           \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return FD_FUNKIER_ERR_INVAL; } \
  } while(0)

  TEST( !fd_funkier_rec_map_verify( &rec_map ) );
  TEST( !fd_funkier_rec_pool_verify( &rec_pool ) );

  /* Iterate over all records in use */

  fd_funkier_all_iter_t iter[1];
  for( fd_funkier_all_iter_new( funk, iter ); !fd_funkier_all_iter_done( iter ); fd_funkier_all_iter_next( iter ) ) {
    fd_funkier_rec_t const * rec = fd_funkier_all_iter_ele_const( iter );

    /* Make sure every record either links up with the last published
       transaction or an in-prep transaction and the flags are sane. */

    fd_funkier_txn_xid_t const * txn_xid = fd_funkier_rec_xid( rec );
    ulong                        txn_idx = fd_funkier_txn_idx( rec->txn_cidx );

    if( fd_funkier_txn_idx_is_null( txn_idx ) ) { /* This is a record from the last published transaction */

      TEST( fd_funkier_txn_xid_eq_root( txn_xid ) );

    } else { /* This is a record from an in-prep transaction */

      TEST( txn_idx<txn_max );
      fd_funkier_txn_t const * txn = fd_funkier_txn_query( txn_xid, &txn_map );
      TEST( txn );
      TEST( txn==(txn_pool.ele+txn_idx) );

    }
  }

  /* Clear record tags and then verify the forward and reverse linkage */

  for( ulong rec_idx=0UL; rec_idx<rec_max; rec_idx++ ) rec_pool.ele[ rec_idx ].tag = 0U;

  do {
    ulong cnt = 0UL;

    ulong txn_idx = FD_FUNKIER_TXN_IDX_NULL;
    ulong rec_idx = funk->rec_head_idx;
    while( !fd_funkier_rec_idx_is_null( rec_idx ) ) {
      TEST( (rec_idx<rec_max) && (fd_funkier_txn_idx( rec_pool.ele[ rec_idx ].txn_cidx )==txn_idx) && rec_pool.ele[ rec_idx ].tag==0U );
      rec_pool.ele[ rec_idx ].tag = 1U;
      cnt++;
      fd_funkier_rec_query_t query[1];
      fd_funkier_rec_t const * rec2 = fd_funkier_rec_query_try_global( funk, NULL, rec_pool.ele[ rec_idx ].pair.key, NULL, query );
      if( FD_UNLIKELY( rec_pool.ele[ rec_idx ].flags & FD_FUNKIER_REC_FLAG_ERASE ) )
        TEST( rec2 == NULL );
      else
        TEST( rec2 = rec_pool.ele + rec_idx );
      ulong next_idx = rec_pool.ele[ rec_idx ].next_idx;
      if( !fd_funkier_rec_idx_is_null( next_idx ) ) TEST( rec_pool.ele[ next_idx ].prev_idx==rec_idx );
      rec_idx = next_idx;
    }
    fd_funkier_txn_all_iter_t txn_iter[1];
    for( fd_funkier_txn_all_iter_new( funk, txn_iter ); !fd_funkier_txn_all_iter_done( txn_iter ); fd_funkier_txn_all_iter_next( txn_iter ) ) {
      fd_funkier_txn_t const * txn = fd_funkier_txn_all_iter_ele_const( txn_iter );

      ulong txn_idx = (ulong)(txn-txn_pool.ele);
      ulong rec_idx = txn->rec_head_idx;
      while( !fd_funkier_rec_idx_is_null( rec_idx ) ) {
        TEST( (rec_idx<rec_max) && (fd_funkier_txn_idx( rec_pool.ele[ rec_idx ].txn_cidx )==txn_idx) && rec_pool.ele[ rec_idx ].tag==0U );
        rec_pool.ele[ rec_idx ].tag = 1U;
        cnt++;
        fd_funkier_rec_query_t query[1];
        fd_funkier_rec_t const * rec2 = fd_funkier_rec_query_try_global( funk, txn, rec_pool.ele[ rec_idx ].pair.key, NULL, query );
        if( FD_UNLIKELY( rec_pool.ele[ rec_idx ].flags & FD_FUNKIER_REC_FLAG_ERASE ) )
          TEST( rec2 == NULL );
        else
          TEST( rec2 = rec_pool.ele + rec_idx );
        ulong next_idx = rec_pool.ele[ rec_idx ].next_idx;
        if( !fd_funkier_rec_idx_is_null( next_idx ) ) TEST( rec_pool.ele[ next_idx ].prev_idx==rec_idx );
        rec_idx = next_idx;
      }
    }
  } while(0);

  do {
    ulong cnt = 0UL;

    ulong txn_idx = FD_FUNKIER_TXN_IDX_NULL;
    ulong rec_idx = funk->rec_tail_idx;
    while( !fd_funkier_rec_idx_is_null( rec_idx ) ) {
      TEST( (rec_idx<rec_max) && (fd_funkier_txn_idx( rec_pool.ele[ rec_idx ].txn_cidx )==txn_idx) && rec_pool.ele[ rec_idx ].tag==1U );
      rec_pool.ele[ rec_idx ].tag = 2U;
      cnt++;
      ulong prev_idx = rec_pool.ele[ rec_idx ].prev_idx;
      if( !fd_funkier_rec_idx_is_null( prev_idx ) ) TEST( rec_pool.ele[ prev_idx ].next_idx==rec_idx );
      rec_idx = prev_idx;
    }

    fd_funkier_txn_all_iter_t txn_iter[1];
    for( fd_funkier_txn_all_iter_new( funk, txn_iter ); !fd_funkier_txn_all_iter_done( txn_iter ); fd_funkier_txn_all_iter_next( txn_iter ) ) {
      fd_funkier_txn_t const * txn = fd_funkier_txn_all_iter_ele_const( txn_iter );

      ulong txn_idx = (ulong)(txn-txn_pool.ele);
      ulong rec_idx = txn->rec_tail_idx;
      while( !fd_funkier_rec_idx_is_null( rec_idx ) ) {
        TEST( (rec_idx<rec_max) && (fd_funkier_txn_idx( rec_pool.ele[ rec_idx ].txn_cidx )==txn_idx) && rec_pool.ele[ rec_idx ].tag==1U );
        rec_pool.ele[ rec_idx ].tag = 2U;
        cnt++;
        ulong prev_idx = rec_pool.ele[ rec_idx ].prev_idx;
        if( !fd_funkier_rec_idx_is_null( prev_idx ) ) TEST( rec_pool.ele[ prev_idx ].next_idx==rec_idx );
        rec_idx = prev_idx;
      }
    }
  } while(0);

# undef TEST

  return FD_FUNKIER_SUCCESS;
}
#endif

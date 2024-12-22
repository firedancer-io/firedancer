#include "fd_funk.h"

/* Provide the actual record map implementation */

#define MAP_NAME              fd_funk_rec_map
#define MAP_T                 fd_funk_rec_t
#define MAP_KEY_T             fd_funk_xid_key_pair_t
#define MAP_KEY               pair
#define MAP_KEY_EQ(k0,k1)     fd_funk_xid_key_pair_eq((k0),(k1))
#define MAP_KEY_HASH(k0,seed) fd_funk_xid_key_pair_hash((k0),(seed))
#define MAP_KEY_COPY(kd,ks)   fd_funk_xid_key_pair_copy((kd),(ks))
#define MAP_NEXT              map_next
#define MAP_HASH              map_hash
#define MAP_MAGIC             (0xf173da2ce77ecdb0UL) /* Firedancer rec db version 0 */
#define MAP_IMPL_STYLE        2
#define MAP_MEMOIZE           1
#include "../util/tmpl/fd_map_giant.c"

FD_FN_PURE ulong
fd_funk_rec_map_list_idx( fd_funk_rec_t const * join,
                          fd_funk_xid_key_pair_t const * key ) {
    fd_funk_rec_map_private_t const * map = fd_funk_rec_map_private_const( join );
    return (fd_funk_xid_key_pair_hash( key, map->seed )) & (map->list_cnt-1UL);
}

void
fd_funk_rec_map_set_key_cnt( fd_funk_rec_t * join, ulong key_cnt ) {
  fd_funk_rec_map_private_t * map = fd_funk_rec_map_private( join );
  map->key_cnt = key_cnt;
}

fd_funk_rec_t const *
fd_funk_rec_query( fd_funk_t *               funk,
                   fd_funk_txn_t const *     txn,
                   fd_funk_rec_key_t const * key ) {

  if( FD_UNLIKELY( (!funk) | (!key) ) ) return NULL;

  fd_funk_xid_key_pair_t pair[1]; fd_funk_xid_key_pair_init( pair, txn ? fd_funk_txn_xid( txn ) : fd_funk_root( funk ), key );

  return fd_funk_rec_map_query_const( fd_funk_rec_map( funk, fd_funk_wksp( funk ) ), pair, NULL );
}

fd_funk_rec_t const *
fd_funk_rec_query_global( fd_funk_t *               funk,
                          fd_funk_txn_t const *     txn,
                          fd_funk_rec_key_t const * key,
                          fd_funk_txn_t const **    txn_out ) {

  if( FD_UNLIKELY( (!funk) | (!key) ) ) return NULL;

  fd_wksp_t * wksp = fd_funk_wksp( funk );

  fd_funk_rec_t * rec_map = fd_funk_rec_map( funk, wksp );

  if( txn ) { /* Query txn and its in-prep ancestors */

    fd_funk_txn_t * txn_map = fd_funk_txn_map( funk, wksp );

    ulong txn_max = funk->txn_max;

    ulong txn_idx = (ulong)(txn - txn_map);

    if( FD_UNLIKELY( (txn_idx>=txn_max) /* Out of map (incl NULL) */ | (txn!=(txn_map+txn_idx)) /* Bad alignment */ ) )
      return NULL;

    /* TODO: const correct and/or fortify? */
    do {
      fd_funk_xid_key_pair_t pair[1]; fd_funk_xid_key_pair_init( pair, fd_funk_txn_xid( txn ), key );
      fd_funk_rec_t const * rec = fd_funk_rec_map_query_const( rec_map, pair, NULL );
      if( FD_LIKELY( rec ) ) {
        if( FD_UNLIKELY(NULL != txn_out  ) ) {
          *txn_out = txn;
        }
        return rec;
      }
      txn = fd_funk_txn_parent( (fd_funk_txn_t *)txn, txn_map );
    } while( FD_UNLIKELY( txn ) );

  }

  /* Query the last published transaction */

  fd_funk_xid_key_pair_t pair[1]; fd_funk_xid_key_pair_init( pair, fd_funk_root( funk ), key );
  return fd_funk_rec_map_query_const( rec_map, pair, NULL );
}

void *
fd_funk_rec_query_safe( fd_funk_t *               funk,
                        fd_funk_rec_key_t const * key,
                        fd_valloc_t               valloc,
                        ulong *                   result_len ) {
  return fd_funk_rec_query_xid_safe( funk, key, fd_funk_root( funk ), valloc, result_len );
}

void *
fd_funk_rec_query_xid_safe( fd_funk_t *               funk,
                            fd_funk_rec_key_t const * key,
                            fd_funk_txn_xid_t const * xid,
                            fd_valloc_t               valloc,
                            ulong *                   result_len ) {
  fd_wksp_t * wksp = fd_funk_wksp( funk );
  fd_funk_rec_t * rec_map = fd_funk_rec_map( funk, wksp );

  fd_funk_xid_key_pair_t pair[1];
  fd_funk_xid_key_pair_init( pair, xid, key );

  void * result = NULL;
  ulong  alloc_len = 0;
  *result_len = 0;
  for(;;) {
    ulong lock_start;
    for(;;) {
      lock_start = funk->write_lock;
      if( FD_LIKELY(!(lock_start&1UL)) ) break;
      /* Funk is currently write locked */
      FD_SPIN_PAUSE();
    }
    FD_COMPILER_MFENCE();

    fd_funk_rec_t const * rec = fd_funk_rec_map_query_safe( rec_map, pair, NULL );
    if( FD_UNLIKELY( rec == NULL ) ) {
      FD_COMPILER_MFENCE();
      if( lock_start == funk->write_lock ) return NULL;
    } else {
      uint val_sz = rec->val_sz;
      if( val_sz ) {
        if( result == NULL ) {
          result = fd_valloc_malloc( valloc, FD_FUNK_VAL_ALIGN, val_sz );
          alloc_len = val_sz;
        } else if ( val_sz > alloc_len ) {
          fd_valloc_free( valloc, result );
          result = fd_valloc_malloc( valloc, FD_FUNK_VAL_ALIGN, val_sz );
          alloc_len = val_sz;
        }
        fd_memcpy( result, fd_wksp_laddr_fast( wksp, rec->val_gaddr ), val_sz );
      }
      *result_len = val_sz;
      FD_COMPILER_MFENCE();
      if( lock_start == funk->write_lock ) return result;
    }

    /* else try again */
    FD_SPIN_PAUSE();
  }
}

int
fd_funk_rec_test( fd_funk_t *           funk,
                  fd_funk_rec_t const * rec ) {

  if( FD_UNLIKELY( !funk ) ) return FD_FUNK_ERR_INVAL;

  fd_wksp_t * wksp = fd_funk_wksp( funk );

  fd_funk_rec_t * rec_map = fd_funk_rec_map( funk, wksp );

  ulong rec_max = funk->rec_max;

  ulong rec_idx = (ulong)(rec - rec_map);

  if( FD_UNLIKELY( (rec_idx>=rec_max) /* Out of map (incl NULL) */ | (rec!=(rec_map+rec_idx)) /* Bad alignment */ ) )
    return FD_FUNK_ERR_INVAL;

  if( FD_UNLIKELY( rec!=fd_funk_rec_map_query_const( rec_map, fd_funk_rec_pair( rec ), NULL ) ) ) return FD_FUNK_ERR_KEY;

  ulong txn_idx = fd_funk_txn_idx( rec->txn_cidx );

  if( FD_UNLIKELY( fd_funk_txn_idx_is_null( txn_idx ) ) ) { /* Rec in last published, opt for lots recs */

    if( FD_UNLIKELY( fd_funk_last_publish_is_frozen( funk ) ) ) return FD_FUNK_ERR_FROZEN;

  } else { /* Rec in in-prep */

    fd_funk_txn_t * txn_map = fd_funk_txn_map( funk, wksp );
    ulong           txn_max = funk->txn_max;

    if( FD_UNLIKELY( txn_idx>=txn_max ) ) return FD_FUNK_ERR_XID; /* TODO: consider LOG_CRIT here? */

    if( FD_UNLIKELY( fd_funk_txn_is_frozen( &txn_map[ txn_idx ] ) ) ) return FD_FUNK_ERR_FROZEN;

  }

  return FD_FUNK_SUCCESS;
}

fd_funk_rec_t *
fd_funk_rec_modify( fd_funk_t *           funk,
                    fd_funk_rec_t const * rec ) {
  if( FD_UNLIKELY( (!funk) | (!rec) ) )
    return NULL;
  fd_funk_check_write( funk );

  fd_wksp_t * wksp = fd_funk_wksp( funk );

  fd_funk_rec_t * rec_map = fd_funk_rec_map( funk, wksp );

  ulong rec_max = funk->rec_max;

  ulong rec_idx = (ulong)(rec - rec_map);

  if( FD_UNLIKELY( (rec_idx>=rec_max) /* Out of map (incl NULL) */ | (rec!=(rec_map+rec_idx)) /* Bad alignment */ ) )
    return NULL;

  if( FD_UNLIKELY( rec!=fd_funk_rec_map_query_const( rec_map, fd_funk_rec_pair( rec ), NULL ) ) )
    return NULL; /* Not live */

  ulong txn_idx = fd_funk_txn_idx( rec->txn_cidx );

  if( fd_funk_txn_idx_is_null( txn_idx ) ) { /* Modifying last published transaction */

    if( FD_UNLIKELY( fd_funk_last_publish_is_frozen( funk ) ) )
      return NULL;

  } else { /* Modifying an in-prep transaction */
    fd_funk_txn_t * txn_map = fd_funk_txn_map( funk, wksp );

    ulong txn_max = funk->txn_max;

    if( FD_UNLIKELY( txn_idx>=txn_max ) ) FD_LOG_CRIT(( "memory corruption detected (bad idx)" ));

    if( FD_UNLIKELY( fd_funk_txn_is_frozen( &txn_map[ txn_idx ] ) ) )
      return NULL;
  }

  return (fd_funk_rec_t *)rec;
}

FD_FN_PURE int
fd_funk_rec_is_modified( fd_funk_t *           funk,
                         fd_funk_rec_t const * rec ) {

  if( FD_UNLIKELY( (!funk) | (!rec) ) ) return 0;

  fd_wksp_t * wksp = fd_funk_wksp( funk );

  fd_funk_rec_t * rec_map = fd_funk_rec_map( funk, wksp );
  ulong rec_max = funk->rec_max;
  ulong rec_idx = (ulong)(rec - rec_map);
  if( FD_UNLIKELY( (rec_idx>=rec_max) /* Out of map (incl NULL) */ | (rec!=(rec_map+rec_idx)) /* Bad alignment */ ) )
    FD_LOG_CRIT(( "memory corruption detected (bad idx)" ));

  ulong txn_idx = fd_funk_txn_idx( rec->txn_cidx );
  if( fd_funk_txn_idx_is_null( txn_idx ) )
    return -1;
  fd_funk_txn_t * txn_map = fd_funk_txn_map( funk, wksp );
  ulong txn_max = funk->txn_max;
  if( FD_UNLIKELY( txn_idx>=txn_max ) )
    FD_LOG_CRIT(( "memory corruption detected (bad idx)" ));
  fd_funk_txn_t * txn = txn_map + txn_idx;

  void * val = fd_funk_val( rec, wksp );

  do {
    /* Go to the parent transaction */
    fd_funk_xid_key_pair_t pair[1];
    txn_idx = fd_funk_txn_idx( txn->parent_cidx );
    if ( fd_funk_txn_idx_is_null( txn_idx ) ) {
      txn = NULL;
      fd_funk_xid_key_pair_init( pair, fd_funk_root( funk ), rec->pair.key );
    } else {
      txn = txn_map + txn_idx;
      fd_funk_xid_key_pair_init( pair, fd_funk_txn_xid( txn ), rec->pair.key );
    }

    fd_funk_rec_t const * rec2 = fd_funk_rec_map_query_const( rec_map, pair, NULL );
    if ( rec2 ) {
      if ( rec->val_sz != rec2->val_sz )
        return 1;
      void * val2 = fd_funk_val( rec2, wksp );
      return memcmp(val, val2, rec->val_sz) != 0;
    }
  } while (txn);

  return 1;
}

fd_funk_rec_t const *
fd_funk_rec_insert( fd_funk_t *               funk,
                    fd_funk_txn_t *           txn,
                    fd_funk_rec_key_t const * key,
                    int *                     opt_err ) {

  if( FD_UNLIKELY( (!funk) |     /* NULL funk */
                   (!key ) ) ) { /* NULL key */
    fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_INVAL );
    return NULL;
  }
  fd_funk_check_write( funk );

  fd_wksp_t * wksp = fd_funk_wksp( funk );

  fd_funk_rec_t * rec_map = fd_funk_rec_map( funk, wksp );

  ulong rec_max = funk->rec_max;

  if( FD_UNLIKELY( fd_funk_rec_map_is_full( rec_map ) ) ) {
    fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_REC );
    return NULL;
  }

  ulong                  txn_idx;
  ulong *                _rec_head_idx;
  ulong *                _rec_tail_idx;
  fd_funk_xid_key_pair_t pair[1];

  if( !txn ) { /* Modifying last published */

    if( FD_UNLIKELY( fd_funk_last_publish_is_frozen( funk ) ) ) {
      fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_FROZEN );
      return NULL;
    }

    txn_idx       = FD_FUNK_TXN_IDX_NULL;
    _rec_head_idx = &funk->rec_head_idx;
    _rec_tail_idx = &funk->rec_tail_idx;

    fd_funk_xid_key_pair_init( pair, fd_funk_root( funk ), key );

    fd_funk_rec_t * rec = fd_funk_rec_map_query( rec_map, pair, NULL );

    if( FD_UNLIKELY( rec ) ) { /* Already a record present */

      /* However, if the record is marked for erasure, reset the flag and
         return the record. */
      if( rec->flags & FD_FUNK_REC_FLAG_ERASE ) {
        rec->flags &= ~FD_FUNK_REC_FLAG_ERASE;
        return rec;
      }

      fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_KEY );
      return NULL;
    }

  } else { /* Modifying in-prep */

    fd_funk_txn_t * txn_map = fd_funk_txn_map( funk, wksp );

    ulong txn_max = funk->txn_max;

    txn_idx       = (ulong)(txn - txn_map);
    _rec_head_idx = &txn->rec_head_idx;
    _rec_tail_idx = &txn->rec_tail_idx;

    if( FD_UNLIKELY( (txn_idx>=txn_max) /* Out of map (incl NULL) */ | (txn!=(txn_map+txn_idx)) /* Bad alignment */ ) ) {
      fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_INVAL );
      return NULL;
    }

    if( FD_UNLIKELY( !fd_funk_txn_map_query( txn_map, fd_funk_txn_xid( txn ), NULL ) ) ) {
      fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_INVAL );
      return NULL;
    }

    if( FD_UNLIKELY( fd_funk_txn_is_frozen( txn ) ) ) {
      fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_FROZEN );
      return NULL;
    }

    fd_funk_xid_key_pair_init( pair, fd_funk_txn_xid( txn ), key );

    fd_funk_rec_t * rec = fd_funk_rec_map_query( rec_map, pair, NULL );

    if( FD_UNLIKELY( rec ) ) { /* Already a record present */

      /* The user is trying insert a record update on top of
         a pre-existing of record update.  We fail with ERR_KEY to
         prevent accidentally discarding any previous updates
         unintentionally. */

      if( FD_UNLIKELY( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) {
        rec->flags &= ~FD_FUNK_REC_FLAG_ERASE;
        return rec;
      }

      fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_KEY );
      return NULL;

    }

  }

  fd_funk_rec_t * rec     = fd_funk_rec_map_insert( rec_map, pair );
  ulong           rec_idx = (ulong)(rec - rec_map);
  if( FD_UNLIKELY( rec_idx>=rec_max ) ) FD_LOG_CRIT(( "memory corruption detected (bad idx)" ));

  ulong rec_prev_idx = *_rec_tail_idx;

  int first_born = fd_funk_rec_idx_is_null( rec_prev_idx );
  if( FD_UNLIKELY( !first_born ) ) {
    if( FD_UNLIKELY( rec_prev_idx>=rec_max ) )
      FD_LOG_CRIT(( "memory corruption detected (bad_idx)" ));
    if( FD_UNLIKELY( fd_funk_txn_idx( rec_map[ rec_prev_idx ].txn_cidx )!=txn_idx  ) )
      FD_LOG_CRIT(( "memory corruption detected (mismatch)" ));
  }

  rec->prev_idx = rec_prev_idx;
  rec->next_idx = FD_FUNK_REC_IDX_NULL;
  rec->txn_cidx = fd_funk_txn_cidx( txn_idx );
  rec->tag      = 0U;
  rec->flags    = 0UL;

  if( first_born ) *_rec_head_idx                   = rec_idx;
  else             rec_map[ rec_prev_idx ].next_idx = rec_idx;

  *_rec_tail_idx = rec_idx;

  fd_funk_val_init( rec );
  fd_funk_part_init( rec );

  fd_int_store_if( !!opt_err, opt_err, FD_FUNK_SUCCESS );
  return rec;
}

int
fd_funk_rec_remove( fd_funk_t *     funk,
                    fd_funk_rec_t * rec,
                    ulong           erase_data ) {

  if( FD_UNLIKELY( !funk ) ) return FD_FUNK_ERR_INVAL;
  fd_funk_check_write( funk );

  fd_wksp_t * wksp = fd_funk_wksp( funk );

  fd_funk_rec_t * rec_map = fd_funk_rec_map( funk, wksp );

  ulong rec_max = funk->rec_max;

  ulong rec_idx = (ulong)(rec - rec_map);

  if( FD_UNLIKELY( (rec_idx>=rec_max) /* Out of map (incl NULL) */ | (rec!=(rec_map+rec_idx)) /* Bad alignment */ ) )
    return FD_FUNK_ERR_INVAL;

  if( FD_UNLIKELY( rec!=fd_funk_rec_map_query_const( rec_map, fd_funk_rec_pair( rec ), NULL ) ) ) return FD_FUNK_ERR_KEY;

  ulong txn_idx = fd_funk_txn_idx( rec->txn_cidx );

  if( FD_UNLIKELY( fd_funk_txn_idx_is_null( txn_idx ) ) ) { /* Removing from last published, opt for lots recs, rand remove */

    if( FD_UNLIKELY( fd_funk_last_publish_is_frozen( funk ) ) ) return FD_FUNK_ERR_FROZEN;

  } else {

    fd_funk_txn_t * txn_map = fd_funk_txn_map( funk, wksp );
    ulong           txn_max = funk->txn_max;

    if( FD_UNLIKELY( txn_idx>=txn_max ) ) FD_LOG_CRIT(( "memory corruption detected (bad idx)" ));

    if( FD_UNLIKELY( fd_funk_txn_is_frozen( &txn_map[ txn_idx ] ) ) ) return FD_FUNK_ERR_FROZEN;
  }

  /* If this was already marked for erase, we are done (we already
     flushed the value when it was first marked for erase) */

  if( FD_UNLIKELY( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) return FD_FUNK_SUCCESS;

  /* Flush the value and leave a tombstone behind. In theory, this can
     lead to an unbounded number of records, but for application
     reasons, we need to remember what was deleted. */

  fd_funk_val_flush( rec, fd_funk_alloc( funk, wksp ), wksp );
  fd_funk_part_set_intern( fd_funk_get_partvec( funk, wksp ), rec_map, rec, FD_FUNK_PART_NULL );
  rec->flags |= FD_FUNK_REC_FLAG_ERASE;

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

fd_funk_rec_t *
fd_funk_rec_write_prepare( fd_funk_t *               funk,
                           fd_funk_txn_t *           txn,
                           fd_funk_rec_key_t const * key,
                           ulong                     min_val_size,
                           int                       do_create,
                           fd_funk_rec_t const     * irec,
                           int *                     opt_err ) {

  fd_wksp_t * wksp = fd_funk_wksp( funk );

  fd_funk_rec_t * rec = NULL;
  fd_funk_rec_t const * rec_con = NULL;
  if ( FD_LIKELY (NULL == irec ) )
    rec_con = fd_funk_rec_query_global( funk, txn, key, NULL );
  else
    rec_con = irec;

  /* We are able to handle tombstones in this case because we treat an erased
     record as not exisitng. */

  if ( FD_UNLIKELY( rec_con && !(rec_con->flags & FD_FUNK_REC_FLAG_ERASE) ) ) {
    /* We have an incarnation of the record */
    if ( txn == fd_funk_rec_txn( rec_con,  fd_funk_txn_map( funk, wksp ) ) ) {
      /* The record is already in the right transaction */
      rec = fd_funk_rec_modify( funk, rec_con );
      if ( !rec ) {
        fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ERR_FROZEN );
        return NULL;
      }

    } else {
      /* Copy the record into the transaction */
      rec = fd_funk_rec_modify( funk, fd_funk_rec_insert( funk, txn, key, opt_err ) );
      if ( !rec )
        return NULL;
      rec = fd_funk_val_copy( rec, fd_funk_val_const(rec_con, wksp), fd_funk_val_sz(rec_con),
        fd_ulong_max( fd_funk_val_sz(rec_con), min_val_size ), fd_funk_alloc( funk, wksp ), wksp, opt_err );
      if ( !rec ) {
        return NULL;
      }
    }

  } else {
    if (!do_create) {
      if( opt_err ) *opt_err = FD_FUNK_ERR_KEY;
      return NULL;
    }

    /* Create a new record */
    rec = fd_funk_rec_modify( funk, fd_funk_rec_insert( funk, txn, key, opt_err ) );
    if ( !rec )
      return NULL;
  }

  /* Grow the record to the right size */
  rec->flags &= ~FD_FUNK_REC_FLAG_ERASE;
  if ( fd_funk_val_sz( rec ) < min_val_size ) {
    if( funk->speed_load )
      rec = fd_funk_val_speed_load( funk, rec, min_val_size, wksp, opt_err );
    else
      rec = fd_funk_val_truncate( rec, min_val_size, fd_funk_alloc( funk, wksp ), wksp, opt_err );
  }

  return rec;
}

int
fd_funk_rec_verify( fd_funk_t * funk ) {
  fd_wksp_t *     wksp    = fd_funk_wksp( funk );          /* Previously verified */
  fd_funk_txn_t * txn_map = fd_funk_txn_map( funk, wksp ); /* Previously verified */
  fd_funk_rec_t * rec_map = fd_funk_rec_map( funk, wksp ); /* Previously verified */
  ulong           txn_max = funk->txn_max;                 /* Previously verified */
  ulong           rec_max = funk->rec_max;                 /* Previously verified */

  /* At this point, txn_map has been extensively verified */

# define TEST(c) do {                                                                           \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return FD_FUNK_ERR_INVAL; } \
  } while(0)

  TEST( !fd_funk_rec_map_verify( rec_map ) );

  /* Iterate over all records in use */

  for( fd_funk_rec_map_iter_t iter = fd_funk_rec_map_iter_init( rec_map );
       !fd_funk_rec_map_iter_done( rec_map, iter );
       iter = fd_funk_rec_map_iter_next( rec_map, iter ) ) {
    fd_funk_rec_t * rec = fd_funk_rec_map_iter_ele( rec_map, iter );

    /* Make sure every record either links up with the last published
       transaction or an in-prep transaction and the flags are sane. */

    fd_funk_txn_xid_t const * txn_xid = fd_funk_rec_xid( rec );
    ulong                     txn_idx = fd_funk_txn_idx( rec->txn_cidx );

    if( fd_funk_txn_idx_is_null( txn_idx ) ) { /* This is a record from the last published transaction */

      TEST( fd_funk_txn_xid_eq_root( txn_xid ) );

    } else { /* This is a record from an in-prep transaction */

      TEST( txn_idx<txn_max );
      fd_funk_txn_t const * txn = fd_funk_txn_map_query_const( txn_map, txn_xid, NULL );
      TEST( txn );
      TEST( txn==(txn_map+txn_idx) );

    }
  }

  /* Clear record tags and then verify the forward and reverse linkage */

  for( ulong rec_idx=0UL; rec_idx<rec_max; rec_idx++ ) rec_map[ rec_idx ].tag = 0U;

  ulong rec_cnt = fd_funk_rec_map_key_cnt( rec_map );

  do {
    ulong cnt = 0UL;

    ulong txn_idx = FD_FUNK_TXN_IDX_NULL;
    ulong rec_idx = funk->rec_head_idx;
    while( !fd_funk_rec_idx_is_null( rec_idx ) ) {
      TEST( (rec_idx<rec_max) && (fd_funk_txn_idx( rec_map[ rec_idx ].txn_cidx )==txn_idx) && rec_map[ rec_idx ].tag==0U );
      rec_map[ rec_idx ].tag = 1U;
      cnt++;
      ulong next_idx = rec_map[ rec_idx ].next_idx;
      if( !fd_funk_rec_idx_is_null( next_idx ) ) TEST( rec_map[ next_idx ].prev_idx==rec_idx );
      rec_idx = next_idx;
    }
    for( fd_funk_txn_map_iter_t iter = fd_funk_txn_map_iter_init( txn_map );
         !fd_funk_txn_map_iter_done( txn_map, iter );
         iter = fd_funk_txn_map_iter_next( txn_map, iter ) ) {
      fd_funk_txn_t * txn = fd_funk_txn_map_iter_ele( txn_map, iter );

      ulong txn_idx = (ulong)(txn-txn_map);
      ulong rec_idx = txn->rec_head_idx;
      while( !fd_funk_rec_idx_is_null( rec_idx ) ) {
        TEST( (rec_idx<rec_max) && (fd_funk_txn_idx( rec_map[ rec_idx ].txn_cidx )==txn_idx) && rec_map[ rec_idx ].tag==0U );
        rec_map[ rec_idx ].tag = 1U;
        cnt++;
        ulong next_idx = rec_map[ rec_idx ].next_idx;
        if( !fd_funk_rec_idx_is_null( next_idx ) ) TEST( rec_map[ next_idx ].prev_idx==rec_idx );
        rec_idx = next_idx;
      }
    }

    TEST( cnt==rec_cnt );
  } while(0);

  do {
    ulong cnt = 0UL;

    ulong txn_idx = FD_FUNK_TXN_IDX_NULL;
    ulong rec_idx = funk->rec_tail_idx;
    while( !fd_funk_rec_idx_is_null( rec_idx ) ) {
      TEST( (rec_idx<rec_max) && (fd_funk_txn_idx( rec_map[ rec_idx ].txn_cidx )==txn_idx) && rec_map[ rec_idx ].tag==1U );
      rec_map[ rec_idx ].tag = 2U;
      cnt++;
      ulong prev_idx = rec_map[ rec_idx ].prev_idx;
      if( !fd_funk_rec_idx_is_null( prev_idx ) ) TEST( rec_map[ prev_idx ].next_idx==rec_idx );
      rec_idx = prev_idx;
    }

    for( fd_funk_txn_map_iter_t iter = fd_funk_txn_map_iter_init( txn_map );
         !fd_funk_txn_map_iter_done( txn_map, iter );
         iter = fd_funk_txn_map_iter_next( txn_map, iter ) ) {
      fd_funk_txn_t * txn = fd_funk_txn_map_iter_ele( txn_map, iter );

      ulong txn_idx = (ulong)(txn-txn_map);
      ulong rec_idx = txn->rec_tail_idx;
      while( !fd_funk_rec_idx_is_null( rec_idx ) ) {
        TEST( (rec_idx<rec_max) && (fd_funk_txn_idx( rec_map[ rec_idx ].txn_cidx )==txn_idx) && rec_map[ rec_idx ].tag==1U );
        rec_map[ rec_idx ].tag = 2U;
        cnt++;
        ulong prev_idx = rec_map[ rec_idx ].prev_idx;
        if( !fd_funk_rec_idx_is_null( prev_idx ) ) TEST( rec_map[ prev_idx ].next_idx==rec_idx );
        rec_idx = prev_idx;
      }
    }

    TEST( cnt==rec_cnt );
  } while(0);

# undef TEST

  return FD_FUNK_SUCCESS;
}

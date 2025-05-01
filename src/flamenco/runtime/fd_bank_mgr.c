#include "fd_bank_mgr.h"

#define FD_BANK_MGR_BLOCK_HASH_QUEUE           (0)
#define FD_BANK_MGR_BLOCK_HASH_QUEUE_FOOTPRINT (50000UL)
#define FD_BANK_MGR_BLOCK_HASH_QUEUE_ALIGN     (1024UL)

static inline fd_funk_rec_key_t
fd_bank_mgr_cache_key( ulong entry_id ) {
  fd_funk_rec_key_t id;
  memcpy( id.uc, &entry_id, sizeof(ulong) );
  memset( id.uc + sizeof(ulong), 0, sizeof(fd_funk_rec_key_t) - sizeof(ulong) );

  id.uc[ FD_FUNK_REC_KEY_FOOTPRINT - 1 ] = FD_FUNK_KEY_TYPE_BANK_MGR;

  return id;
}

void *
fd_bank_mgr_new( void * mem ) {
  return mem;
}

fd_bank_mgr_t *
fd_bank_mgr_join( void * mem, fd_funk_t * funk, fd_funk_txn_t * funk_txn ) {

  /* TODO: Check alignment */

  fd_bank_mgr_t * bank_mgr = (fd_bank_mgr_t * )mem;

  bank_mgr->funk     = funk;
  bank_mgr->funk_txn = funk_txn;
  memset( &bank_mgr->prepare, 0, sizeof(fd_funk_rec_prepare_t) );

  return bank_mgr;
}

fd_block_hash_queue_global_t *
fd_bank_mgr_block_hash_queue_query( fd_bank_mgr_t * bank_mgr ) {

  /* A query from the bank manager is a simple read-only wrapper over
     fd_funk_rec_query_try_global. This will return the value from the
     funk record that can live anywhere in the funk txn tree. */
  fd_funk_rec_query_t query = {0};
  fd_funk_rec_key_t   key   = fd_bank_mgr_cache_key( FD_BANK_MGR_BLOCK_HASH_QUEUE );

  fd_funk_rec_t const * rec = fd_funk_rec_query_try_global( bank_mgr->funk,
                                                            bank_mgr->funk_txn,
                                                            &key,
                                                            NULL,
                                                            &query );

  if( FD_UNLIKELY( !rec ) ) {
    FD_LOG_ERR( ( "Could not find block hash queue" ) );
    return NULL;
  }

  return (fd_block_hash_queue_global_t *)fd_ulong_align_up( (ulong)fd_funk_val( rec, fd_funk_wksp( bank_mgr->funk ) ), FD_BANK_MGR_BLOCK_HASH_QUEUE_ALIGN );
}

fd_block_hash_queue_global_t *
fd_bank_mgr_block_hash_queue_modify( fd_bank_mgr_t * bank_mgr ) {
  /* We first try to query the current iteration of the record if it
     exists in the current transaction. If it exists in the current
     funk transaction, then we can assume that the record was modified
     in the current transaction. */
  memset( &bank_mgr->prepare, 0, sizeof(fd_funk_rec_prepare_t) );
  fd_funk_rec_query_t   query   = {0};
  fd_funk_rec_key_t     key     = fd_bank_mgr_cache_key( FD_BANK_MGR_BLOCK_HASH_QUEUE );
  fd_funk_txn_t const * txn_out = NULL;
  fd_funk_rec_t const * rec     = fd_funk_rec_query_try_global( bank_mgr->funk,
                                                                bank_mgr->funk_txn,
                                                                &key,
                                                                &txn_out,
                                                                &query );

  uchar * old_data = !!rec ? fd_funk_val( rec, fd_funk_wksp( bank_mgr->funk ) ) : NULL;

  fd_funk_rec_t * in_prep_rec = fd_funk_rec_prepare( bank_mgr->funk, bank_mgr->funk_txn, &key, &bank_mgr->prepare, NULL );
  if( FD_UNLIKELY( !in_prep_rec ) ) {
    FD_LOG_ERR(( "Could not clone block hash queue" ));
  }

  /* TODO: Replace new_val_sz with a closely bounded macro. */
  int     err      = 0;
  uchar * new_data = fd_funk_val_truncate( in_prep_rec,
                                           FD_BANK_MGR_BLOCK_HASH_QUEUE_FOOTPRINT,
                                           fd_funk_alloc( bank_mgr->funk ),
                                           fd_funk_wksp( bank_mgr->funk ),
                                           &err );

  if( FD_UNLIKELY( err ) ) {
  FD_LOG_ERR(( "Could not resize block hash queue %d", err ));
  }

  uchar * new_data_start = (uchar*)fd_ulong_align_up( (ulong)new_data, FD_BANK_MGR_BLOCK_HASH_QUEUE_ALIGN );

  if( rec ) {
    uchar * old_data_start = (uchar*)fd_ulong_align_up( (ulong)old_data, FD_BANK_MGR_BLOCK_HASH_QUEUE_ALIGN );
    fd_memcpy( new_data_start, old_data_start, FD_BANK_MGR_BLOCK_HASH_QUEUE_FOOTPRINT - ((ulong)new_data_start - (ulong)new_data) );
  }

  /* If the record already exists in the current funk transaction,
     remove it at this point. */
  if( txn_out == bank_mgr->funk_txn ) {
    fd_funk_rec_hard_remove( bank_mgr->funk, bank_mgr->funk_txn, &key );
  }

  return (fd_block_hash_queue_global_t *)new_data_start;
}

int
fd_bank_mgr_block_hash_queue_save( fd_bank_mgr_t * bank_mgr ) {
  /* Publish the record into the current funk transaction and clear the
     now stale funk record prepare. */
  fd_funk_rec_publish( bank_mgr->funk, &bank_mgr->prepare );
  fd_memset( &bank_mgr->prepare, 0, sizeof(fd_funk_rec_prepare_t) );
  return 0;
}

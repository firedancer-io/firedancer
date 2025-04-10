#include "fd_bank_mgr.h"

static inline fd_funk_rec_key_t
fd_bank_mgr_key( ulong member_id ) {
  fd_funk_rec_key_t id;
  memcpy( id.uc, &member_id, sizeof(ulong) );
  id.c[ FD_FUNK_REC_KEY_FOOTPRINT - 1 ] = FD_FUNK_KEY_TYPE_ELF_CACHE;
  return id;
}

int
fd_bank_mgr_create_entry( fd_funk_t *     funk,
                          fd_funk_txn_t * funk_txn,
                          ulong           entry_id,
                          uchar *         entry_data,
                          ulong           entry_data_sz ) {

  int err = FD_FUNK_SUCCESS;

  fd_funk_rec_key_t     rec_key = fd_bank_mgr_key( entry_id );
  fd_funk_rec_prepare_t prepare[1];
  fd_funk_rec_t *       rec     = fd_funk_rec_prepare( funk, funk_txn, &rec_key, prepare, &err );
  if( FD_UNLIKELY( !rec || err!=FD_FUNK_SUCCESS ) ) {
    FD_LOG_ERR(( "fd_funk_rec_prepare() failed" ));
  }

  fd_wksp_t *  wksp     = fd_funk_wksp( funk );
  fd_alloc_t * alloc    = fd_funk_alloc( funk, wksp );
  uchar *      rec_data = fd_funk_val_truncate( rec, entry_data_sz, alloc, wksp, &err );
  if( FD_UNLIKELY( !rec_data || err!=FD_FUNK_SUCCESS ) ) {
    FD_LOG_ERR(( "fd_funk_val_truncate() failed" ));
  }

  memcpy( rec_data, entry_data, entry_data_sz );

  fd_funk_rec_publish( prepare );
  return 0;
}

int
fd_bank_mgr_entry_query_const( fd_funk_t *     funk,
                               fd_funk_txn_t * funk_txn,
                               ulong           entry_id,
                               uchar const * * out_entry_data,
                               ulong *         out_entry_data_sz ) {

  fd_funk_rec_key_t rec_key = fd_bank_mgr_key( entry_id );

  for(;;) {
    fd_funk_rec_query_t   query[1];
    fd_funk_rec_t const * rec = fd_funk_rec_query_try_global( funk, funk_txn, &rec_key, NULL, query );

    if( FD_UNLIKELY( !rec || !!( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) ) {
      if( fd_funk_rec_query_test( query ) == FD_FUNK_SUCCESS ) {
        return -1;
      } else {
        continue;
      }
    }

    void const * data = fd_funk_val_const( rec, fd_funk_wksp( funk ) );

    /* This test is actually too early. It should happen after the
       data is actually consumed. This is fine however, because this
       is only accessed in a multithreaded/unsafe way during transaction
       execution when all members of the bank manager are read-only. */
    if( FD_LIKELY( fd_funk_rec_query_test( query ) == FD_FUNK_SUCCESS ) ) {
      *out_entry_data     = (uchar const *)data;
      *out_entry_data_sz  = fd_funk_val_sz( rec );
      return 0;
    }

    /* Try again */
  }
  return -1;
}

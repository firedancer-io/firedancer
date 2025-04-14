#include "fd_bank_mgr.h"

static inline fd_funk_rec_key_t
fd_bank_mgr_key( ulong member_id ) {
  fd_funk_rec_key_t id = {0};
  memcpy( id.uc, &member_id, sizeof(ulong) );
  id.c[ FD_FUNK_REC_KEY_FOOTPRINT - 1 ] = FD_FUNK_KEY_TYPE_BANK_MGR;
  return id;
}

static inline int FD_FN_UNUSED
fd_bank_mgr_prepare_is_new_rec( fd_bank_mgr_prepare_t * prepare ) {
  return prepare->prepare->rec == NULL;
}

int
fd_bank_mgr_prepare_entry(fd_funk_t *             funk,
                          fd_funk_txn_t *         funk_txn,
                          ulong                   entry_id,
                          ulong                   sz,
                          fd_bank_mgr_prepare_t * prepare ) {

  int err = FD_FUNK_SUCCESS;

  fd_funk_rec_key_t     rec_key = fd_bank_mgr_key( entry_id );

  fd_funk_rec_t const * rec       = fd_funk_rec_query_try( funk, funk_txn, &rec_key, prepare->query );
  fd_wksp_t *           funk_wksp = fd_funk_wksp( funk );
  fd_funk_rec_t *       mod_rec   = NULL;

  if( rec ) {
    fd_funk_rec_t * mod_rec = fd_funk_rec_modify_prepare( funk, funk_txn, &rec_key, prepare->query );
    if( FD_UNLIKELY( !mod_rec ) ) {
      FD_LOG_ERR(( "fd_funk_rec_modify_prepare() failed" ));
    }
    prepare->data = fd_funk_val( mod_rec, fd_funk_wksp( funk ) );

  } else {

    /* If the record is not found in the current funk transaction, check
      the ancestor transactions. */
    fd_funk_rec_t const * ancestor_rec = fd_funk_rec_query_try_global( funk,
                                                                      funk_txn,
                                                                      &rec_key,
                                                                      NULL,
                                                                      prepare->query );

    if( FD_LIKELY( ancestor_rec ) ) {
      /* The case where the record was modified in a previous txn. This
        is the most expected case as we only expect to modify the bank
        at the end of a slot and we generally don't add new members to
        the bank except at boot up. */
      FD_LOG_WARNING(("CLONING HERE"));
      mod_rec = fd_funk_rec_clone( funk,
                                  funk_txn,
                                  &rec_key,
                                  prepare->prepare,
                                  &err );
    }

    FD_LOG_WARNING(("PREPARING HERE"));
    /* The case where this record does not exist at all yet. */
    mod_rec = fd_funk_rec_prepare( funk,
                                   funk_txn,
                                   &rec_key,
                                   prepare->prepare,
                                   &err );
    FD_TEST( mod_rec );
  }

  if( FD_UNLIKELY( err ) ) {
    if( prepare->prepare->rec ) {
      fd_funk_rec_cancel( prepare->prepare );
    }
    return err;
  }
  /* If we are able to successfully prepare a record, then we will try
     to grow the record if this is needed. In most cases this will be a
     no-op as the record will be sized adequately. */
  prepare->data = fd_funk_val_truncate( mod_rec,
                                        sz,
                                        fd_funk_alloc( funk, funk_wksp ),
                                        funk_wksp,
                                        &err );
  FD_TEST( prepare->data );
  if( FD_UNLIKELY( err ) ) {
    if( prepare->prepare->rec ) {
      fd_funk_rec_cancel( prepare->prepare );
    }
    return err;
  }

  /* Only assign the entry id to the bank_mgr prepare if it was
     successful. */
  prepare->entry_id = entry_id;
  FD_LOG_WARNING(("PREP SUCCESS"));
  return FD_BANK_MGR_SUCCESS;

}

int
fd_bank_mgr_publish_entry( fd_bank_mgr_prepare_t * prepare ) {

  if( FD_UNLIKELY( !prepare->data ) ) {
    FD_LOG_ERR(( "fd_bank_mgr_publish_entry() failed, no data" ));
  }

  if( !prepare->prepare->rec ) {
    /* If the fields of the funk rec prepare are not set, that means
       we just need to modify the record that exists in the current
       funk transaction. */
    FD_LOG_WARNING(("ENTER HERE EXISTS"));
    fd_funk_rec_modify_publish( prepare->query );
  } else {
    /* This means that the current record doesn't exist but there is an
       in-prepare publish of the record and it needs to be published. */
    FD_LOG_WARNING(("ENTER HERE DNE"));
    fd_funk_rec_publish( prepare->prepare );
  }
  return FD_BANK_MGR_SUCCESS;
}

int
fd_bank_mgr_entry_query_const( fd_funk_t *     funk,
                               fd_funk_txn_t * funk_txn,
                               ulong           entry_id,
                               uchar * *       out_entry_data,
                               ulong *         out_entry_data_sz ) {

  fd_funk_rec_key_t rec_key = fd_bank_mgr_key( entry_id );

  for(;;) {
    fd_funk_rec_query_t   query[1];
    fd_funk_rec_t const * rec = fd_funk_rec_query_try_global( funk, funk_txn, &rec_key, NULL, query );
    FD_TEST( !!rec );

    if( FD_UNLIKELY( !rec || !!( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) ) {
      if( fd_funk_rec_query_test( query ) == FD_FUNK_SUCCESS ) {
        FD_LOG_WARNING(("Failed here"));
        return FD_BANK_MGR_FAILURE;
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
      *out_entry_data     = (uchar *)data;
      *out_entry_data_sz  = fd_funk_val_sz( rec );
      return FD_BANK_MGR_SUCCESS;
    }

    /* Try again */
  }
  FD_LOG_WARNING(("Failed here 2"));
  return FD_BANK_MGR_FAILURE;
}

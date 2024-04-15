#include "fd_borrowed_account.h"
#include "fd_acc_mgr.h"

fd_borrowed_account_t *
fd_borrowed_account_init( void * ptr ) {
  if( FD_UNLIKELY( !ptr ) ) {
    FD_LOG_WARNING(( "NULL ptr" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ptr, alignof(fd_borrowed_account_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned ptr" ));
    return NULL;
  }

  memset(ptr, 0, FD_BORROWED_ACCOUNT_FOOTPRINT);

  fd_borrowed_account_t * ret = (fd_borrowed_account_t *)ptr;
  ret->starting_dlen     = ULONG_MAX;
  ret->starting_lamports = ULONG_MAX;

  FD_COMPILER_MFENCE();
  ret->magic = FD_BORROWED_ACCOUNT_MAGIC;
  FD_COMPILER_MFENCE();

  return ret;
}

void *
fd_borrowed_account_resize( fd_borrowed_account_t * borrowed_account,
                            void *                  buf,
                            ulong                   dlen ) {
  // TODO: Check for max accounts size?
  uchar * new_raw_data = (uchar *)buf;

  ulong old_sz = sizeof(fd_account_meta_t)+borrowed_account->meta->dlen;
  ulong new_sz = sizeof(fd_account_meta_t)+dlen;
  fd_memcpy( new_raw_data, borrowed_account->const_meta, old_sz );
  fd_memset( new_raw_data+old_sz, 0, new_sz-old_sz );

  fd_account_meta_t * meta = borrowed_account->meta;
  uint is_changed = borrowed_account->meta != borrowed_account->orig_meta;

  borrowed_account->const_meta = borrowed_account->meta = (fd_account_meta_t *)new_raw_data;
  borrowed_account->const_data = borrowed_account->data = new_raw_data + sizeof(fd_account_meta_t);
  borrowed_account->meta->dlen = dlen;

  if( is_changed ) {
    return meta;
  }

  return NULL;
}

fd_borrowed_account_t *
fd_borrowed_account_make_modifiable( fd_borrowed_account_t * borrowed_account,
                                     void * buf ) {
  uchar * new_raw_data = (uchar *)buf;
  if( borrowed_account->data != NULL ) {
    FD_LOG_ERR(( "borrowed account is already modifiable" ));
  }

  ulong dlen = ( borrowed_account->const_meta != NULL ) ? borrowed_account->const_meta->dlen : 0;

  if( borrowed_account->const_meta != NULL ) {
    fd_memcpy( new_raw_data, (uchar *)borrowed_account->const_meta,  sizeof(fd_account_meta_t)+dlen );
  } else {
    /* Account did not exist, set up metadata */
    fd_account_meta_init( (fd_account_meta_t *)new_raw_data );
  }

  borrowed_account->const_meta = borrowed_account->meta = (fd_account_meta_t *)new_raw_data;
  borrowed_account->const_data = borrowed_account->data = new_raw_data + sizeof(fd_account_meta_t);
  borrowed_account->meta->dlen = dlen;

  return borrowed_account;
}

void *
fd_borrowed_account_restore( fd_borrowed_account_t * borrowed_account ) {
  fd_account_meta_t * meta = borrowed_account->meta;
  uint is_changed = meta != borrowed_account->orig_meta;

  borrowed_account->const_meta = borrowed_account->orig_meta;
  borrowed_account->const_data = borrowed_account->orig_data;
  borrowed_account->const_rec = borrowed_account->orig_rec;

  if( is_changed ) {
    return meta;
  }

  return NULL;
}

void *
fd_borrowed_account_destroy( fd_borrowed_account_t * borrowed_account ) {
  return borrowed_account->meta;
}

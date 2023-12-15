#include "fd_borrowed_account.h"

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

void
fd_borrowed_account_resize( fd_borrowed_account_t * borrowed_account,
                            ulong dlen,
                            fd_valloc_t valloc ) {
  // TODO: Check for max accounts size?
  uchar * new_raw_data = fd_valloc_malloc( valloc, 8, sizeof(fd_account_meta_t)+dlen );

  ulong old_sz = sizeof(fd_account_meta_t)+borrowed_account->meta->dlen;
  ulong new_sz = sizeof(fd_account_meta_t)+dlen;

  fd_memcpy( new_raw_data, (uchar *)borrowed_account->meta,  sizeof(fd_account_meta_t)+borrowed_account->meta->dlen );
  fd_memset( new_raw_data+old_sz, 0, new_sz-old_sz );

  uint is_changed = borrowed_account->data != borrowed_account->orig_data;
  if( is_changed ) {
    fd_valloc_free( valloc, borrowed_account->meta );
  }

  borrowed_account->const_meta = borrowed_account->meta = (fd_account_meta_t *)new_raw_data;
  borrowed_account->const_data = borrowed_account->data = new_raw_data + sizeof(fd_account_meta_t);
  borrowed_account->meta->dlen = dlen;
}

void
fd_borrowed_account_restore( fd_borrowed_account_t * borrowed_account,
                             fd_valloc_t valloc ) {
  uint is_changed = borrowed_account->data != borrowed_account->orig_data;
  if( is_changed ) {
    fd_valloc_free( valloc, borrowed_account->meta );
  }

  borrowed_account->const_meta = borrowed_account->orig_meta;
  borrowed_account->const_data = borrowed_account->orig_data;
  borrowed_account->const_rec  = borrowed_account->orig_rec;
}

void
fd_borrowed_account_destroy( fd_borrowed_account_t * borrowed_account,
                             fd_valloc_t valloc ) {
  uint is_changed = borrowed_account->data != borrowed_account->orig_data;
  if( is_changed ) {
    fd_valloc_free( valloc, borrowed_account->meta );
  }
}

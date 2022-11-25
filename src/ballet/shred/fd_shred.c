#include "fd_shred.h"

fd_shred_t const *
fd_shred_parse( uchar const * buf ) {
  fd_shred_t const * shred = (fd_shred_t *)buf;
  /* Validate shred type */
  uchar shred_type = fd_shred_type( shred->variant );
  if( FD_UNLIKELY( shred_type!=FD_SHRED_TYPE_MERKLE_DATA &&
                   shred_type!=FD_SHRED_TYPE_MERKLE_CODE &&
                   shred->variant!=0xa5 /*FD_SHRED_TYPE_LEGACY_DATA*/ &&
                   shred->variant!=0x5a /*FD_SHRED_TYPE_LEGACY_CODE*/ ) ) {
    return NULL;
  }
  return shred;
}

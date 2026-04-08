#ifndef HEADER_fd_src_flamenco_runtime_fd_acc_mgr_h
#define HEADER_fd_src_flamenco_runtime_fd_acc_mgr_h

/* fd_acc_mgr provides APIs for the Solana account database. */

#include "../types/fd_types_custom.h"

#if defined(__AVX__)
#include "../../util/simd/fd_avx.h"
#endif

/* FD_ACC_TOT_SZ_MAX is the size limit of a Solana account in the firedancer
   client. This means that it includes the max size of the account (10MiB)
   and the associated metadata. */

#define FD_ACC_TOT_SZ_MAX (FD_RUNTIME_ACC_SZ_MAX + sizeof(fd_account_meta_t))

FD_PROTOTYPES_BEGIN

/* Account Management APIs **************************************************/

/* The following account management APIs are helpers for fd_account_meta_t creation,
   existence, and retrieval from funk */

static inline fd_account_meta_t *
fd_account_meta_init( fd_account_meta_t * m ) {
  fd_memset( m, 0, sizeof(fd_account_meta_t) );
  return m;
}

/* fd_account_meta_exists checks if the account in a funk record exists or was
   deleted.  Handles NULL input safely.  Returns 0 if the account was
   deleted (zero lamports, empty data, zero owner).  Otherwise, returns
   1. */

static inline int
fd_account_meta_exists( fd_account_meta_t const * m ) {

  if( !m ) return 0;

# if defined(__AVX2__)
  wl_t o = wl_ldu( m->owner );
  int has_owner = !_mm256_testz_si256( o, o );
# else
  int has_owner = 0;
  for( ulong i=0UL; i<32UL; i++ )
    has_owner |= m->owner[i];
  has_owner = !!has_owner;
# endif

  return ((m->lamports > 0UL) |
          (m->dlen     > 0UL) |
          (has_owner        ) );

}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_acc_mgr_h */

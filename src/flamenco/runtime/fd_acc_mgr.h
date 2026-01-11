#ifndef HEADER_fd_src_flamenco_runtime_fd_acc_mgr_h
#define HEADER_fd_src_flamenco_runtime_fd_acc_mgr_h

/* fd_acc_mgr provides APIs for the Solana account database. */

#include "fd_txn_account.h"

#if FD_HAS_AVX
#include "../../util/simd/fd_avx.h"
#endif

/* FD_ACC_MGR_{SUCCESS,ERR{...}} are account management specific error codes.
   To be stored in an int. */

#define FD_ACC_MGR_SUCCESS             (0)
#define FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT (-1)

#define FD_ACC_NONCE_SZ_MAX (80UL)     /* 80 bytes */

/* FD_ACC_TOT_SZ_MAX is the size limit of a Solana account in the firedancer
   client. This means that it includes the max size of the account (10MiB)
   and the associated metadata. */

#define FD_ACC_TOT_SZ_MAX       (FD_RUNTIME_ACC_SZ_MAX + sizeof(fd_account_meta_t))

#define FD_ACC_NONCE_TOT_SZ_MAX (FD_ACC_NONCE_SZ_MAX + sizeof(fd_account_meta_t))

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

# if FD_HAS_AVX
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

/* Account meta helpers */
static inline void *
fd_account_meta_get_data( fd_account_meta_t * m ) {
  return ((uchar *) m) + sizeof(fd_account_meta_t);
}

static inline void const *
fd_account_meta_get_data_const( fd_account_meta_t const * m ) {
  return ((uchar const *) m) + sizeof(fd_account_meta_t);
}

static inline ulong
fd_account_meta_get_record_sz( fd_account_meta_t const * m ) {
  return sizeof(fd_account_meta_t) + m->dlen;
}

/* Funk key handling **************************************************/

/* fd_acc_funk_key returns a fd_funk database key given an account
   address. */

FD_FN_PURE static inline fd_funk_rec_key_t
fd_funk_acc_key( fd_pubkey_t const * pubkey ) {
  fd_funk_rec_key_t key = {0};
  memcpy( key.uc, pubkey, sizeof(fd_pubkey_t) );
  return key;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_acc_mgr_h */

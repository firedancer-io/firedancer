#include "ag_hist_file.h"

#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/sha256/fd_sha256.h"

#define SIG_SZ (64UL)

void
ag_hist_file_sign_msg( uchar const * body,
                       ulong         body_sz,
                       uchar         out[ static FD_KEYGUARD_VOTOR_HIST_MSG_SZ ] ) {
  fd_memcpy( out, FD_KEYGUARD_VOTOR_HIST_PREFIX, FD_KEYGUARD_VOTOR_HIST_PREFIX_SZ );
  fd_sha256_hash( body, body_sz, out+FD_KEYGUARD_VOTOR_HIST_PREFIX_SZ );
}

long
ag_hist_file_ser( ag_hist_t const *   hist,
                  fd_pubkey_t const * identity,
                  long                now_secs,
                  ag_hist_sign_fn *   sign_fn,
                  void *              sign_ctx,
                  uchar *             buf,
                  ulong               buf_max ) {
  if( FD_UNLIKELY( buf_max<AG_HIST_FILE_HDR_SZ+SIG_SZ ) ) return -1L;

  /* ag_hist_ser writes nothing when hist is invalid or the room left
     between the header and the signature is too small */
  ulong hist_sz;
  if( FD_UNLIKELY( ag_hist_ser( hist, buf+AG_HIST_FILE_HDR_SZ, buf_max-AG_HIST_FILE_HDR_SZ-SIG_SZ, &hist_sz ) ) ) return -1L;

  FD_STORE( uint, buf,      AG_HIST_FILE_MAGIC   );
  FD_STORE( uint, buf+4UL,  AG_HIST_FILE_VERSION );
  fd_memcpy( buf+8UL, identity->uc, 32UL );
  FD_STORE( long, buf+40UL, now_secs );

  ulong body_sz = AG_HIST_FILE_HDR_SZ+hist_sz;
  sign_fn( sign_ctx, buf+body_sz, buf, body_sz );
  return (long)( body_sz+SIG_SZ );
}

int
ag_hist_file_de( uchar const *       buf,
                 ulong               buf_sz,
                 fd_pubkey_t const * identity,
                 ag_hist_t *         out,
                 long *              opt_timestamp ) {
  if( FD_UNLIKELY( buf_sz<AG_HIST_FILE_HDR_SZ+SIG_SZ || buf_sz>AG_HIST_FILE_MAX ) ) return -1;
  ulong body_sz = buf_sz-SIG_SZ;

  if( FD_UNLIKELY( FD_LOAD( uint, buf     )!=AG_HIST_FILE_MAGIC   ) ) return -1;
  if( FD_UNLIKELY( FD_LOAD( uint, buf+4UL )!=AG_HIST_FILE_VERSION ) ) return -1;
  if( FD_UNLIKELY( !fd_memeq( buf+8UL, identity->uc, 32UL )      ) ) return -1;
  long timestamp = FD_LOAD( long, buf+40UL );

  ag_hist_t hist[ 1 ];
  if( FD_UNLIKELY( ag_hist_de( buf+AG_HIST_FILE_HDR_SZ, body_sz-AG_HIST_FILE_HDR_SZ, hist ) ) ) return -1;

  uchar       msg[ FD_KEYGUARD_VOTOR_HIST_MSG_SZ ];
  fd_sha512_t sha[ 1 ];
  ag_hist_file_sign_msg( buf, body_sz, msg );
  if( FD_UNLIKELY( FD_ED25519_SUCCESS!=fd_ed25519_verify( msg, sizeof(msg), buf+body_sz, identity->uc, sha ) ) ) return -1;

  *out = *hist;
  if( opt_timestamp ) *opt_timestamp = timestamp;
  return 0;
}

#undef SIG_SZ

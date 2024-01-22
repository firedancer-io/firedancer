#include "fd_remote_signer.h"

void *
fd_remote_signer_new( void *           shmem,
                      fd_frag_meta_t * request_mcache,
                      uchar *          request_data,
                      fd_frag_meta_t * response_mcache,
                      uchar *          response_data ) {
  fd_remote_signer_t * signer = (fd_remote_signer_t*)shmem;
  signer->request = request_mcache;
  signer->request_seq = 0UL;
  signer->request_data = request_data;
  signer->response = response_mcache;
  signer->response_seq = 0UL;
  signer->response_data = response_data;
  return shmem;
}

void
fd_remote_signer_sign_leader( fd_remote_signer_t * signer,
                              uchar *              signature,
                              uchar const *        merkle_root ) {
  fd_memcpy( signer->request_data, merkle_root, 32UL );

  fd_mcache_publish( signer->request, 128UL, signer->request_seq, 0UL, 0UL, 32UL, 0UL, 0UL, 0UL );
  signer->request_seq = fd_seq_inc( signer->request_seq, 1UL );

  fd_frag_meta_t meta;
  fd_frag_meta_t const * mline;
  ulong seq_found;
  long seq_diff;
  ulong poll_max = ULONG_MAX;
  FD_MCACHE_WAIT( &meta, mline, seq_found, seq_diff, poll_max, signer->response, 128UL, signer->response_seq );
  if( FD_UNLIKELY( !poll_max ) ) FD_LOG_ERR(( "sign request timed out while polling" ));
  if( FD_UNLIKELY( seq_diff ) ) FD_LOG_ERR(( "sign request was overrun while polling" ));

  fd_memcpy( signature, signer->response_data, 64UL );

  seq_found = fd_frag_meta_seq_query( mline );
  if( FD_UNLIKELY( fd_seq_ne( seq_found, signer->response_seq ) ) ) FD_LOG_ERR(( "sign request was overrun while reading" ));
  signer->response_seq = fd_seq_inc( signer->response_seq, 1UL );
}

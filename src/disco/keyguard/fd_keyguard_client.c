#include "fd_keyguard_client.h"

void *
fd_keyguard_client_new( void *         shmem,
                      fd_frag_meta_t * request_mcache,
                      uchar *          request_data,
                      fd_frag_meta_t * response_mcache,
                      uchar *          response_data ) {
  fd_keyguard_client_t * client = (fd_keyguard_client_t*)shmem;
  client->request      = request_mcache;
  client->request_seq  = 0UL;
  client->request_data = request_data;

  client->response      = response_mcache;
  client->response_seq  = 0UL;
  client->response_data = response_data;
  return shmem;
}

void
fd_keyguard_client_sign( fd_keyguard_client_t * client,
                         uchar *                signature,
                         uchar const *          sign_data,
                         ulong                  sign_data_len ) {
  fd_memcpy( client->request_data, sign_data, sign_data_len );

  fd_mcache_publish( client->request, 128UL, client->request_seq, 0UL, 0UL, sign_data_len, 0UL, 0UL, 0UL );
  client->request_seq = fd_seq_inc( client->request_seq, 1UL );

  fd_frag_meta_t meta;
  fd_frag_meta_t const * mline;
  ulong seq_found;
  long seq_diff;
  ulong poll_max = ULONG_MAX;
  FD_MCACHE_WAIT( &meta, mline, seq_found, seq_diff, poll_max, client->response, 128UL, client->response_seq );
  if( FD_UNLIKELY( !poll_max ) ) FD_LOG_ERR(( "sign request timed out while polling" ));
  if( FD_UNLIKELY( seq_diff ) ) FD_LOG_ERR(( "sign request was overrun while polling" ));

  fd_memcpy( signature, client->response_data, 64UL );

  seq_found = fd_frag_meta_seq_query( mline );
  if( FD_UNLIKELY( fd_seq_ne( seq_found, client->response_seq ) ) ) FD_LOG_ERR(( "sign request was overrun while reading" ));
  client->response_seq = fd_seq_inc( client->response_seq, 1UL );
}

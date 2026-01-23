#include "fd_keyguard_client.h"

#include "../../discof/send/fd_send_tile.h"
#include "../../tango/mcache/fd_mcache.h"
#include "../../tango/dcache/fd_dcache.h"

void *
fd_keyguard_client_new( void *           shmem,
                        fd_frag_meta_t * request_mcache,
                        uchar *          request_dcache,
                        fd_frag_meta_t * response_mcache,
                        uchar *          response_dcache,
                        ulong            request_mtu ) {
  fd_keyguard_client_t * client = (fd_keyguard_client_t*)shmem;

  client->request        = request_mcache;
  client->request_depth  = fd_mcache_depth( request_mcache );
  client->request_seq    = 0UL;
  client->request_mem    = fd_wksp_containing( request_dcache );
  client->request_chunk0 = fd_dcache_compact_chunk0( client->request_mem, request_dcache );
  client->request_wmark  = fd_dcache_compact_wmark( client->request_mem, request_dcache, request_mtu );
  client->request_chunk  = client->request_chunk0;
  client->request_mtu    = request_mtu;

  client->response        = response_mcache;
  client->response_depth  = fd_mcache_depth( response_mcache );
  client->response_seq    = 0UL;
  client->response_mem    = fd_wksp_containing( response_dcache );
  client->response_chunk0 = fd_dcache_compact_chunk0( client->response_mem, response_dcache );
  client->response_wmark  = fd_dcache_compact_wmark( client->response_mem, response_dcache, 64UL );

  return shmem;
}

void
fd_keyguard_client_sign( fd_keyguard_client_t * client,
                         uchar *                signature,
                         uchar const *          sign_data,
                         ulong                  sign_data_len,
                         int                    sign_type ) {
  FD_TEST( sign_data_len<=client->request_mtu );

  uchar * dst = fd_chunk_to_laddr( client->request_mem, client->request_chunk );
  fd_memcpy( dst, sign_data, sign_data_len );

  ulong sig = (ulong)(uint)sign_type;
  fd_mcache_publish( client->request, client->request_depth, client->request_seq, sig, client->request_chunk, sign_data_len, 0UL, 0UL, 0UL );
  client->request_seq   = fd_seq_inc( client->request_seq, 1UL );
  client->request_chunk = fd_dcache_compact_next( client->request_chunk, sign_data_len, client->request_chunk0, client->request_wmark );

  fd_frag_meta_t meta;
  fd_frag_meta_t const * mline;
  ulong seq_found;
  long seq_diff;
  ulong poll_max = ULONG_MAX;
  FD_MCACHE_WAIT( &meta, mline, seq_found, seq_diff, poll_max, client->response, client->response_depth, client->response_seq );
  if( FD_UNLIKELY( !poll_max ) ) FD_LOG_ERR(( "sign request timed out while polling" ));
  if( FD_UNLIKELY( seq_diff ) ) FD_LOG_ERR(( "sign request was overrun while polling" ));

  /* Chunk is in shared memory and might be be written to by an
     attacking tile after we validate it, so load once. */
  ulong chunk = FD_VOLATILE_CONST( mline->chunk );
  FD_TEST( chunk>=client->response_chunk0 && chunk<=client->response_wmark );

  uchar * src = fd_chunk_to_laddr( client->response_mem, chunk );
  fd_memcpy( signature, src, 64UL );

  seq_found = fd_frag_meta_seq_query( mline );
  if( FD_UNLIKELY( fd_seq_ne( seq_found, client->response_seq ) ) ) FD_LOG_ERR(( "sign request was overrun while reading" ));
  client->response_seq = fd_seq_inc( client->response_seq, 1UL );
}

void
fd_keyguard_client_vote_txn_sign( fd_keyguard_client_t * client,
                                  uchar *                signatures[ static 2UL ],
                                  uchar const *          pubkeys[ static 2UL ],
                                  uchar                  pubkeys_cnt,
                                  uchar const *          sign_data,
                                  ulong                  sign_data_len ) {
    FD_CRIT( sign_data_len+pubkeys_cnt*32UL <= client->request_mtu, "the request is too large and will not fit in the mtu" );
    FD_CRIT( pubkeys_cnt==1UL || pubkeys_cnt==2UL, "there can be 1 or 2 signers on an outgoing vote trasnaction" );

    fd_send_sign_request_t * request = fd_chunk_to_laddr( client->request_mem, client->request_chunk );
    request->requested_signers_cnt = pubkeys_cnt;
    if( pubkeys_cnt>=1UL )fd_memcpy( request->requested_signers_pubkeys[0], pubkeys[ 0UL ], 32UL );
    if( pubkeys_cnt==2UL )fd_memcpy( request->requested_signers_pubkeys[1], pubkeys[ 1UL ], 32UL );

    request->message_sz = sign_data_len;
    memcpy( request->message, sign_data, sign_data_len );

    fd_mcache_publish( client->request, client->request_depth, client->request_seq, 0UL, client->request_chunk, sizeof(fd_send_sign_request_t), 0UL, 0UL, 0UL );
    client->request_seq   = fd_seq_inc( client->request_seq, 1UL );
    client->request_chunk = fd_dcache_compact_next( client->request_chunk, sign_data_len, client->request_chunk0, client->request_wmark );

    fd_frag_meta_t meta;
    fd_frag_meta_t const * mline;
    ulong seq_found;
    long seq_diff;
    ulong poll_max = ULONG_MAX;
    FD_MCACHE_WAIT( &meta, mline, seq_found, seq_diff, poll_max, client->response, client->response_depth, client->response_seq );
    if( FD_UNLIKELY( !poll_max ) ) FD_LOG_ERR(( "sign request timed out while polling" ));
    if( FD_UNLIKELY( seq_diff ) ) FD_LOG_ERR(( "sign request was overrun while polling" ));

    /* Chunk is in shared memory and might be be written to by an
       attacking tile after we validate it, so load once. */
    ulong chunk = FD_VOLATILE_CONST( mline->chunk );
    FD_TEST( chunk>=client->response_chunk0 && chunk<=client->response_wmark );

    fd_sign_send_response_t * response = fd_chunk_to_laddr( client->response_mem, chunk );
    if( pubkeys_cnt>=1UL ) memcpy( signatures[0], response->signatures[0], 64UL );
    if( pubkeys_cnt==2UL ) memcpy( signatures[1], response->signatures[1], 64UL );

    seq_found = fd_frag_meta_seq_query( mline );
    if( FD_UNLIKELY( fd_seq_ne( seq_found, client->response_seq ) ) ) FD_LOG_ERR(( "sign request was overrun while reading" ));
    client->response_seq = fd_seq_inc( client->response_seq, 1UL );
}

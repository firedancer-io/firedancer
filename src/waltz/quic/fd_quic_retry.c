#include "fd_quic_common.h"
#include "fd_quic_retry_private.h"
#include "crypto/fd_quic_crypto_suites.h"
#include "fd_quic_conn_id.h"
#include "fd_quic_enum.h"
#include "fd_quic_private.h"
#include "../../ballet/aes/fd_aes_gcm.h"
#include <assert.h>

FD_STATIC_ASSERT( FD_QUIC_RETRY_LOCAL_SZ==
                  FD_QUIC_MAX_FOOTPRINT(retry_hdr) +
                  sizeof(fd_quic_retry_token_t) +
                  FD_QUIC_CRYPTO_TAG_SZ,
                  layout );

ulong
fd_quic_retry_pseudo(
    uchar                     out[ FD_QUIC_RETRY_MAX_PSEUDO_SZ ],
    void const *              retry_pkt,
    ulong                     retry_pkt_sz,
    fd_quic_conn_id_t const * orig_dst_conn_id ) {

  if( FD_UNLIKELY( retry_pkt_sz <= FD_QUIC_CRYPTO_TAG_SZ ||
                   retry_pkt_sz >  FD_QUIC_RETRY_MAX_SZ ) ) {
    return FD_QUIC_PARSE_FAIL;
  }

  /* Retry Pseudo-Packet {
      ODCID Length (8),
      Original Destination Connection ID (0..160),
      Header Form (1) = 1,
      Fixed Bit (1) = 1,
      Long Packet Type (2) = 3,
      Unused (4),
      Version (32),
      DCID Len (8),
      Destination Connection ID (0..160),
      SCID Len (8),
      Source Connection ID (0..160),
      Retry Token (..),
  } */

  uchar * cur_ptr = out;

  cur_ptr[0] = (uchar)orig_dst_conn_id->sz;
  cur_ptr += 1;

  memcpy( cur_ptr, orig_dst_conn_id->conn_id, FD_QUIC_MAX_CONN_ID_SZ ); /* oversz is safe */
  cur_ptr += orig_dst_conn_id->sz;

  ulong stripped_retry_sz = retry_pkt_sz - FD_QUIC_CRYPTO_TAG_SZ;  /* >0 */
  fd_memcpy( cur_ptr, retry_pkt, stripped_retry_sz );
  cur_ptr += stripped_retry_sz;

  return (ulong)cur_ptr - (ulong)out;
}

ulong
fd_quic_retry_create(
    uchar                     retry[FD_QUIC_RETRY_LOCAL_SZ], /* out */
    fd_quic_pkt_t const *     pkt,
    fd_rng_t *                rng,
    uchar const               retry_secret[ FD_QUIC_RETRY_SECRET_SZ ],
    uchar const               retry_iv[ FD_QUIC_RETRY_IV_SZ ],
    fd_quic_conn_id_t const * orig_dst_conn_id,
    fd_quic_conn_id_t const * new_conn_id,
    ulong                     wallclock /* ns since unix epoch */
) {

  uchar * out_ptr  = retry;
  ulong   out_free = FD_QUIC_RETRY_LOCAL_SZ;

  /* Craft a new Retry packet */

  fd_quic_retry_hdr_t retry_hdr[1] = {{
    .h0              = 0xf0,
    .version         = 1,
    .dst_conn_id_len = pkt->long_hdr->src_conn_id_len,
    // .dst_conn_id (initialized below)
    .src_conn_id_len = new_conn_id->sz,
    // .src_conn_id (initialized below)
  }};
  memcpy( retry_hdr->dst_conn_id, pkt->long_hdr->src_conn_id, FD_QUIC_MAX_CONN_ID_SZ );
  memcpy( retry_hdr->src_conn_id, &new_conn_id->conn_id,      FD_QUIC_MAX_CONN_ID_SZ );
  ulong rc = fd_quic_encode_retry_hdr( retry, FD_QUIC_RETRY_LOCAL_SZ, retry_hdr );
  assert( rc!=FD_QUIC_PARSE_FAIL );
  if( FD_UNLIKELY( rc==FD_QUIC_PARSE_FAIL ) ) FD_LOG_CRIT(( "fd_quic_encode_retry_hdr failed" ));
  out_ptr  += rc;
  out_free -= rc;

  /* Craft a new retry token */

  fd_quic_retry_token_t * retry_token = fd_type_pun( out_ptr );
  assert( out_free >= sizeof(fd_quic_retry_token_t) );

  uint   src_ip4_addr = FD_LOAD( uint, pkt->ip4->saddr_c );  /* net order */
  ushort src_udp_port = (ushort)fd_ushort_bswap( (ushort)pkt->udp->net_sport );
  ulong  expire_at    = wallclock + FD_QUIC_RETRY_TOKEN_LIFETIME * (ulong)1e9;

  fd_quic_retry_data_new( &retry_token->data, rng );
  fd_quic_retry_data_set_ip4( &retry_token->data, src_ip4_addr );
  retry_token->data.udp_port   = (ushort)src_udp_port;
  retry_token->data.expire_comp = expire_at >> FD_QUIC_RETRY_EXPIRE_SHIFT;

  retry_token->data.odcid_sz = orig_dst_conn_id->sz;
  retry_token->data.rscid_sz = new_conn_id->sz;
  memcpy( retry_token->data.odcid, orig_dst_conn_id->conn_id, FD_QUIC_MAX_CONN_ID_SZ ); /* oversz copy ok */
  memcpy( retry_token->data.rscid, new_conn_id->conn_id,      FD_QUIC_MAX_CONN_ID_SZ ); /* practically always FD_QUIC_CONN_ID_SZ */

  /* Create the inner integrity tag (non-standard) */

  fd_aes_gcm_t aes_gcm[1];
  fd_quic_retry_token_sign( retry_token, aes_gcm, retry_secret, retry_iv );
  memset( aes_gcm, 0, sizeof(fd_aes_gcm_t) );

  out_ptr  += sizeof(fd_quic_retry_token_t);
  out_free -= sizeof(fd_quic_retry_token_t);

# if FD_QUIC_DISABLE_CRYPTO

  memset( out_ptr, 0, FD_QUIC_CRYPTO_TAG_SZ );
  out_ptr  += FD_QUIC_CRYPTO_TAG_SZ;
  out_free -= FD_QUIC_CRYPTO_TAG_SZ;

# else

  /* Create the outer integrity tag (standard) */

  ulong retry_unsigned_sz = (ulong)out_ptr - (ulong)retry;

  uchar retry_pseudo_buf[ FD_QUIC_RETRY_MAX_PSEUDO_SZ ];
  ulong retry_pseudo_sz = fd_quic_retry_pseudo( retry_pseudo_buf, retry, retry_unsigned_sz + FD_QUIC_CRYPTO_TAG_SZ, orig_dst_conn_id );
  if( FD_UNLIKELY( retry_pseudo_sz==FD_QUIC_PARSE_FAIL ) ) FD_LOG_ERR(( "fd_quic_retry_pseudo_hdr failed" ));
  fd_quic_retry_integrity_tag_sign( aes_gcm, retry_pseudo_buf, retry_pseudo_sz, out_ptr );
  out_ptr  += FD_QUIC_CRYPTO_TAG_SZ;
  out_free -= FD_QUIC_CRYPTO_TAG_SZ;

# endif /* FD_QUIC_DISABLE_CRYPTO */

  assert( (ulong)out_ptr - (ulong)retry <= FD_QUIC_RETRY_LOCAL_SZ );
  ulong retry_sz = (ulong)out_ptr - (ulong)retry;
  return retry_sz;
}

int
fd_quic_retry_server_verify(
    fd_quic_pkt_t const *     pkt,
    fd_quic_initial_t const * initial,
    fd_quic_conn_id_t *       orig_dst_conn_id, /* out */
    fd_quic_conn_id_t *       retry_src_conn_id, /* out */
    uchar const               retry_secret[ FD_QUIC_RETRY_SECRET_SZ ],
    uchar const               retry_iv[ FD_QUIC_RETRY_IV_SZ ],
    ulong                     now
) {

  /* We told the client to retry with a DCID chosen by us, and we
     always use conn IDs of the same size */
  if( FD_UNLIKELY( initial->dst_conn_id_len != FD_QUIC_CONN_ID_SZ ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "Retry with weird dst conn ID sz, rejecting" )); )
    return FD_QUIC_FAILED;
  }

  /* fd_quic always uses retry tokens of the same size */
  if( FD_UNLIKELY( initial->token_len != sizeof(fd_quic_retry_token_t) ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "Retry with weird token sz, rejecting" )); )
    return FD_QUIC_FAILED;
  }

  fd_quic_retry_token_t const * retry_token = fd_type_pun_const( initial->token );
  if( FD_UNLIKELY( ( retry_token->data.odcid_sz >  FD_QUIC_MAX_CONN_ID_SZ ) |
                   ( retry_token->data.rscid_sz != FD_QUIC_CONN_ID_SZ )  ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "Retry token with invalid ODCID or RSCID, rejecting" )); )
    return FD_QUIC_FAILED;
  }

  fd_aes_gcm_t aes_gcm[1];
  int vfy_res = fd_quic_retry_token_verify( retry_token, aes_gcm, retry_secret, retry_iv );
  memset( aes_gcm, 0, sizeof(fd_aes_gcm_t) );

  uint  pkt_ip4       = FD_LOAD( uint, pkt->ip4->saddr_c               );
  uint  retry_ip4     = FD_LOAD( uint, retry_token->data.ip6_addr + 12 );
  int   is_ip4        = 0==memcmp( retry_token->data.ip6_addr, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff", 12 );
  uint  pkt_port      = fd_ushort_bswap( (ushort)pkt->udp->net_sport );
  uint  retry_port    = retry_token->data.udp_port;
  ulong expire_at     = retry_token->data.expire_comp << FD_QUIC_RETRY_EXPIRE_SHIFT;
  ulong expire_before = now + FD_QUIC_RETRY_TOKEN_LIFETIME * (ulong)1e9;

  int is_match =
    vfy_res == FD_QUIC_SUCCESS &&
    is_ip4                     &&
    pkt_ip4  == retry_ip4      &&
    pkt_port == retry_port     &&
    now < expire_at            &&
    expire_at < expire_before; /* token was issued in the future */

  FD_DEBUG(
    if( vfy_res!=FD_QUIC_SUCCESS        ) FD_LOG_DEBUG(( "Invalid Retry Token" ));
    else if( now >= expire_at           ) FD_LOG_DEBUG(( "Expired Retry Token" ));
    else if( expire_at >= expire_before ) FD_LOG_WARNING(( "Retry Token issued in the future" ));
    else if( !is_match                  ) FD_LOG_DEBUG(( "Foreign Retry Token" ));
  )

  orig_dst_conn_id->sz  = (uchar)retry_token->data.odcid_sz;
  retry_src_conn_id->sz = (uchar)retry_token->data.rscid_sz;
  memcpy( orig_dst_conn_id->conn_id,  retry_token->data.odcid, FD_QUIC_MAX_CONN_ID_SZ ); /* oversz copy ok */
  memcpy( retry_src_conn_id->conn_id, retry_token->data.rscid, FD_QUIC_MAX_CONN_ID_SZ ); /* oversz copy ok */

  return is_match ? FD_QUIC_SUCCESS : FD_QUIC_FAILED;
}

int
fd_quic_retry_client_verify( uchar const * const       retry_ptr,
                             ulong         const       retry_sz,
                             fd_quic_conn_id_t const * orig_dst_conn_id,
                             fd_quic_conn_id_t *       src_conn_id, /* out */
                             uchar const **            token,
                             ulong *                   token_sz ) {

  uchar const * cur_ptr = retry_ptr;
  ulong         cur_sz  = retry_sz;

  /* Consume retry header */

  fd_quic_retry_hdr_t retry_hdr[1] = {{0}};
  ulong decode_rc = fd_quic_decode_retry_hdr( retry_hdr, cur_ptr, cur_sz );
  if( FD_UNLIKELY( decode_rc == FD_QUIC_PARSE_FAIL ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "fd_quic_decode_retry failed" )); )
    return FD_QUIC_FAILED;
  }
  cur_ptr += decode_rc;
  cur_sz  -= decode_rc;

  if( FD_UNLIKELY( retry_hdr->src_conn_id_len == 0 ) ) {
    /* something is horribly broken or some attack - ignore packet */
    FD_DEBUG( FD_LOG_DEBUG(( "Missing source conn ID" )); )
    return FD_QUIC_FAILED;
  }

  /* Consume retry token
     > A client MUST discard a Retry packet with a zero-length Retry Token field. */

  if( FD_UNLIKELY( cur_sz <= FD_QUIC_CRYPTO_TAG_SZ ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "Retry packet is too small" )); )
    return FD_QUIC_FAILED;
  }
  uchar const * retry_token    = cur_ptr;
  ulong         retry_token_sz = cur_sz - FD_QUIC_CRYPTO_TAG_SZ;
  if( FD_UNLIKELY( retry_token_sz > FD_QUIC_RETRY_MAX_TOKEN_SZ ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "Retry token is too long (%lu bytes)", retry_token_sz )); )
    return FD_QUIC_FAILED;
  }

  cur_ptr += retry_token_sz;
  cur_sz  -= retry_token_sz;

  /* Consume retry integrity tag */

  uchar const * retry_tag = cur_ptr;
  assert( cur_sz==FD_QUIC_CRYPTO_TAG_SZ );
  cur_ptr += FD_QUIC_CRYPTO_TAG_SZ;
  cur_sz  -= FD_QUIC_CRYPTO_TAG_SZ;

  /* Construct Retry Pseudo Header required to validate Retry Integrity
     Tag.  TODO This could be made more efficient using streaming
     AES-GCM. */

  uchar retry_pseudo_buf[ FD_QUIC_RETRY_MAX_PSEUDO_SZ ];
  ulong retry_pseudo_sz = fd_quic_retry_pseudo( retry_pseudo_buf, retry_ptr, retry_sz, orig_dst_conn_id );
  if( FD_UNLIKELY( retry_pseudo_sz==FD_QUIC_PARSE_FAIL ) ) FD_LOG_ERR(( "fd_quic_retry_pseudo_hdr failed" ));

# if FD_QUIC_DISABLE_CRYPTO

  (void)retry_tag;  /* skip verification */

# else

  /* Validate the retry integrity tag

     Retry packets (see Section 17.2.5 of [QUIC-TRANSPORT]) carry a Retry Integrity Tag that
     provides two properties: it allows the discarding of packets that have accidentally been
     corrupted by the network, and only an entity that observes an Initial packet can send a valid
     Retry packet.*/
  fd_aes_gcm_t aes_gcm[1];
  int rc = fd_quic_retry_integrity_tag_verify( aes_gcm, retry_pseudo_buf, retry_pseudo_sz, retry_tag );
  if( FD_UNLIKELY( rc == FD_QUIC_FAILED ) ) {
    /* Clients MUST discard Retry packets that have a Retry Integrity Tag that
       cannot be validated */
    FD_DEBUG( FD_LOG_DEBUG(( "Invalid retry integrity tag" )); )
    return FD_QUIC_FAILED;
  }

# endif

  /* Set out params */

  src_conn_id[0].sz = retry_hdr->src_conn_id_len;
  memcpy( src_conn_id[0].conn_id, retry_hdr->src_conn_id, FD_QUIC_MAX_CONN_ID_SZ ); /* oversz copy ok */

  *token    = retry_token;
  *token_sz = retry_token_sz;

  return FD_QUIC_SUCCESS;
}

#include "fd_quic_tx_buf.h"
#include "fd_quic.h"
#include "crypto/fd_quic_crypto_suites.h"
#include "templ/fd_quic_parse_util.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"

/* Note on notation:
   We borrow 'OSI layers' to make the code easier to read:
   - L3: IPv4 header
   - L4: UDP header
   - L5: QUIC header
   - L7: QUIC payloads */

/* fd_quic_tx_l5_hdr encodes an unencrypted QUIC packet header
   including the packet number.  Returns the non-zero header byte size
   on success, or zero if insufficient space was available. */

static ulong
fd_quic_tx_l5_hdr(
    fd_quic_conn_t const * conn,
    uchar *                hdr,
    ulong                  hdr_max,
    uint                   enc_level,
    ulong                  pktnum,
    ulong *                out_pkt_len_off
) {
  *out_pkt_len_off = 0UL;

  ulong const dcid_sz   = conn->peer_cids[ 0 ].sz;
  uint  const pktnum_sz = 4U;
  if( FD_LIKELY( enc_level==fd_quic_enc_level_appdata_id ) ) {
    /* optimize for app traffic */
    ulong const dcid_off   = 1UL;
    ulong const pktnum_off = dcid_off   + dcid_sz;
    ulong const hdr_sz     = pktnum_off + pktnum_sz;
    if( FD_UNLIKELY( hdr_sz>hdr_max ) ) return 0UL;

    uint const spin           = 0U;
    uint const key_phase      = 0U;
    uint const pktnum_sz_comp = pktnum_sz-1U;
    hdr[ 0 ] = fd_quic_one_rtt_h0(
      spin,
      key_phase,
      pktnum_sz_comp
    );
    fd_memcpy( hdr+dcid_off, conn->peer_cids[ 0 ].conn_id, dcid_sz );
    FD_STORE( uint, hdr+pktnum_off, fd_uint_bswap( (uint)pktnum ) );

    return hdr_sz;
  }

  ulong const scid_sz    = FD_QUIC_CONN_ID_SZ;
  ulong const pkt_len_sz = 2UL; /* Length field always 2 byte varint encoded */

  /* Long header offsets */
  ulong const version_off  = 1UL;
  ulong const dcid_len_off = version_off  + 4UL;
  ulong const dcid_off     = dcid_len_off + 1UL;
  ulong const scid_len_off = dcid_off     + dcid_sz;
  ulong const scid_off     = scid_len_off + 1UL;
  ulong const long_hdr_sz  = scid_off     + scid_sz;
  if( FD_UNLIKELY( long_hdr_sz>hdr_max ) ) return 0UL;

  FD_STORE( uint, hdr+version_off, fd_uint_bswap( 1U ) ); /* QUIC v1 */

  hdr[ dcid_len_off ] = (uchar)dcid_sz;
  fd_memcpy( hdr+dcid_off, conn->peer_cids[ 0 ].conn_id, dcid_sz );

  hdr[ scid_len_off ] = (uchar)scid_sz;
  FD_STORE( ulong, hdr+scid_off, conn->our_conn_id );

  if( enc_level==fd_quic_enc_level_initial_id ) {

    ulong const token_len     = conn->token_len;
    ulong const token_len_off = long_hdr_sz;
    ulong const token_len_sz  = fd_quic_varint_min_sz_unsafe( token_len );
    ulong const token_off     = token_len_off + token_len_sz;
    ulong const pkt_len_off   = token_off     + token_len;
    ulong const pktnum_off    = pkt_len_off   + pkt_len_sz;
    ulong const hdr_sz        = pktnum_off    + pktnum_sz;
    if( FD_UNLIKELY( hdr_sz>hdr_max ) ) return 0UL;

    fd_quic_varint_encode( hdr+token_len_off, token_len );
    if( token_len ) {
      fd_memcpy( hdr+token_off, conn->token, token_len );
    }
    FD_STORE( ushort, hdr+pkt_len_off, fd_ushort_bswap( 0x4000 )     );
    FD_STORE( uint,   hdr+pktnum_off,  fd_uint_bswap( (uint)pktnum ) );

    *out_pkt_len_off = pkt_len_off;
    return hdr_sz;

  } else if( enc_level==fd_quic_enc_level_handshake_id ) {

    ulong const pkt_len_off   = long_hdr_sz;
    ulong const pktnum_off    = pkt_len_off + pkt_len_sz;
    ulong const hdr_sz        = pktnum_off  + pktnum_sz;
    if( FD_UNLIKELY( hdr_sz>hdr_max ) ) return 0UL;

    FD_STORE( ushort, hdr+pkt_len_off, fd_ushort_bswap( 0x4000 )     );
    FD_STORE( uint,   hdr+pktnum_off,  fd_uint_bswap( (uint)pktnum ) );

    *out_pkt_len_off = pkt_len_off;
    return hdr_sz;

  } else {

    /* Unsupported packet type */
    return ULONG_MAX;

  }
}

fd_quic_tx_buf_t *
fd_quic_tx_buf_init( fd_quic_tx_buf_t * tx_buf,
                     uchar *            buf,
                     ulong              buf_sz,
                     fd_quic_conn_t *   conn,
                     uint               enc_level,
                     ulong              pktnum ) {
  ulong const l3_sz  = sizeof(fd_ip4_hdr_t); /* no options */
  ulong const l4_sz  = sizeof(fd_udp_hdr_t);
  ulong const l5_off = l3_sz+l4_sz;
  if( FD_UNLIKELY( l5_off>buf_sz ) ) return NULL;

  ulong       pkt_len_off;
  uchar *     buf_end = buf+buf_sz;
  uchar *     l5      = buf+l5_off;
  ulong const l5_max  = (ulong)buf_end - (ulong)l5;
  ulong const l5_sz   = fd_quic_tx_l5_hdr( conn, l5, l5_max, enc_level, pktnum, &pkt_len_off );
  ulong const hdr_sz  = l3_sz + l4_sz + l5_sz;
  ulong const mac_sz  = FD_QUIC_CRYPTO_TAG_SZ;

  /* Abort early if no space remains for payload */
  if( FD_UNLIKELY( hdr_sz+mac_sz >= buf_sz ) ) return NULL;

  memset( tx_buf, 0, sizeof(fd_quic_tx_buf_t) );
  tx_buf->buf0        = buf;
  tx_buf->buf1        = buf+buf_sz;
  tx_buf->frame0      = buf+hdr_sz;
  tx_buf->frame1      = tx_buf->buf1 - mac_sz;
  tx_buf->frame_next  = tx_buf->frame0;
  tx_buf->conn        = conn;
  tx_buf->pkt_len_off = (ushort)pkt_len_off;
  tx_buf->enc_level   = (uchar)enc_level;
  tx_buf->pktnum      = pktnum;

  return tx_buf;
}

static void
fd_quic_tx_net_hdrs( fd_quic_conn_t * conn,
                     uchar            l3l4[ 28 ],
                     ulong            dgram_sz,
                     uint             src_ip4,
                     uint             dst_ip4,
                     ushort           src_port,
                     ushort           dst_port  ) {
  fd_quic_t * quic = conn->quic;
  uint dscp = quic->config.net.dscp;

  ushort const ipv4_id = conn->ipv4_id;
  conn->ipv4_id = (ushort)( ipv4_id+1 );

  fd_ip4_hdr_t ip4 = {
    .verihl       = FD_IP4_VERIHL( 4,5 ),
    .tos          = (uchar)( dscp<<2 ),
    .net_tot_len  = fd_ushort_bswap( (ushort)( 28+dgram_sz ) ),
    .net_id       = fd_ushort_bswap( (ushort)ipv4_id ),
    .net_frag_off = fd_ushort_bswap( FD_IP4_HDR_FRAG_OFF_DF ),
    .ttl          = 64, /* FIXME make configurable */
    .protocol     = FD_IP4_HDR_PROTOCOL_UDP,
    .check        = 0U,
    .saddr        = src_ip4,
    .daddr        = dst_ip4
  };
  ip4.check = fd_ip4_hdr_check_fast( &ip4 );

  fd_udp_hdr_t udp = {
    .net_sport = fd_ushort_bswap( src_port ),
    .net_dport = fd_ushort_bswap( dst_port ),
    .net_len   = fd_ushort_bswap( (ushort)( 8+dgram_sz ) ),
    .check     = 0
  };
  memcpy( l3l4,    &ip4, 20 );
  memcpy( l3l4+20, &udp,  8 );
}

ulong
fd_quic_tx_buf_fini( fd_quic_tx_buf_t * tx_buf,
                     uint               src_ip4,
                     uint               dst_ip4,
                     ushort             src_port,
                     ushort             dst_port ) {
  fd_quic_conn_t * const conn = tx_buf->conn;

  /* Net headers */
  uchar * const buf0      = tx_buf->buf0;
  uchar * const l3        = buf0;
  ulong   const l3_sz     = sizeof(fd_ip4_hdr_t);
  ulong   const l4_sz     = sizeof(fd_udp_hdr_t);

  /* QUIC header */
  ulong   const l5_off    = l3_sz+l4_sz;
  uchar * const l5        = buf0+l5_off;
  ulong   const l5_max    = (ulong)tx_buf->buf1 - (ulong)l5;
  uchar * const frame0    = tx_buf->frame0;
  ulong   const frames_sz = (ulong)tx_buf->frame_next - (ulong)frame0;
  ulong   const l5_sz     = (ulong)frame0 - (ulong)l5;

  uint const enc_level     = tx_buf->enc_level;
  uint const key_phase_upd = !!conn->key_update;

  fd_quic_crypto_keys_t const * hp_keys;
  fd_quic_crypto_keys_t const * pkt_keys;
  hp_keys  = &conn->keys[ enc_level ][ 1 ];
  pkt_keys = key_phase_upd ? &conn->new_keys[ 1 ] : hp_keys;
  /* Note that 'hp_keys' is misleading here: Even though the crypto_keys
     object changes after key renegotiation, the actual AES header
     protection key never changes (hp_keys->hp_key is constant for the
     lifetime of a connection). */

  ulong dgram_sz = l5_max;
  int crypt_ok = fd_quic_crypto_encrypt(
      l5,       &dgram_sz,  /* output */
      l5,       l5_sz,      /* header */
      frame0,   frames_sz,  /* payload */
      pkt_keys, hp_keys,    /* keys */
      tx_buf->pktnum
  );
  if( FD_UNLIKELY( crypt_ok!=FD_QUIC_SUCCESS ) ) return NULL;

  fd_quic_tx_net_hdrs( conn, l3, dgram_sz,
                       src_ip4,  dst_ip4,
                       src_port, dst_port );

  return dgram_sz;
}

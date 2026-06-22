#include "fd_slow_crypto.h"
#include "fd_slow_pkt.h"
#include "../../ballet/aes/fd_aes_gcm.h"
#include "../../util/log/fd_log.h"
#include <string.h>

/* https://www.rfc-editor.org/rfc/rfc9001.html#section-5.3

   > The key and IV for the packet are computed as described in
   > Section 5.1. The nonce, N, is formed by combining the packet
   > protection IV with the packet number. The 62 bits of the
   > reconstructed QUIC packet number in network byte order are
   > left-padded with zeros to the size of the IV. The exclusive OR of
   > the padded packet number and the IV forms the AEAD nonce. */

static uchar *
fd_slow_pkt_nonce( uchar       nonce [ FD_SLOW_IV_SZ ],
                   uchar const pkt_iv[ FD_SLOW_IV_SZ ],
                   ulong       pktnum ) {
  memcpy( nonce, pkt_iv, 4 );
  ulong hi = FD_LOAD( ulong, pkt_iv+4 );
  FD_STORE( ulong, nonce+4, hi ^ fd_ulong_bswap( pktnum & 0x3fffffffffffffffUL ) );
  return nonce;
}

/* Header protection
   https://www.rfc-editor.org/rfc/rfc9001.html#name-header-protection

   > The ciphertext of the packet is sampled and used as input to an
   > encryption algorithm. (single block AES-128-ECB)
   > ...
   > The output of this algorithm is a 5-byte mask that is applied to
   > the protected header fields using exclusive OR.
   >
   >   # pn_offset is the start of the Packet Number field.
   >   sample_offset = pn_offset + 4
   >   sample = packet[sample_offset..sample_offset+sample_length]
   >   mask = header_protection(hp_key, sample)
   >   pn_length = (packet[0] & 0x03) + 1
   >   if (packet[0] & 0x80) == 0x80:
   >     # Long header: 4 bits masked
   >     packet[0] ^= mask[0] & 0x0f
   >   else:
   >     # Short header: 5 bits masked
   >     packet[0] ^= mask[0] & 0x1f
   >   packet[pn_offset:pn_offset+pn_length] ^= mask[1:1+pn_length] */

static void
fd_slow_pkt_hdr_encrypt( uchar *       p,
                         uchar const * c,
                         ulong         c_sz,
                         ulong         pktnum_off,
                         uchar const   hp_key[ FD_SLOW_KEY_SZ ] ) {
  int   hdr_form  = fd_slow_h0_hdr_form  ( p[ 0 ] );   /* in [0,1] */
  ulong pktnum_sz = fd_slow_h0_pktnum_len( p[ 0 ] )+1; /* in [1,4] */

  uchar const * sample = p + pktnum_off + 4;
  FD_DCHECK_CRIT( (ulong)sample+16UL <= (ulong)( c+c_sz ), "bounds check" );

  /* FIXME can we reuse key expansion from AEAD here? */
  fd_aes_key_t ecb[1];
  fd_aes_set_encrypt_key( hp_key, 128, ecb );
  uchar mask[ FD_AES_BLOCK_SZ ];
  fd_aes_encrypt( sample, mask, ecb );

  /* encrypt header byte 0 */
  p[ 0 ] ^= mask[ 0 ] & ( hdr_form?0x0f:0x1f );
  /* encrypt compressed packet number */
  uint keep    = UINT_MAX >> (( 4UL-pktnum_sz )*8UL);
  uint pn_mask = FD_LOAD( uint, mask+1 ) & keep;
  uint pn      = FD_LOAD( uint, p+pktnum_off );
  FD_STORE( uint, p+pktnum_off, pn ^ pn_mask );
}

ulong
fd_slow_pkt_encrypt( uchar const * pkt,
                     ulong         pkt_sz,
                     uchar *       out,
                     ulong         out_max,
                     ulong         hdr_sz,
                     ulong         pktnum,
                     uchar const   hp_key [ FD_SLOW_KEY_SZ ],
                     uchar const   pkt_key[ FD_SLOW_KEY_SZ ],
                     uchar const   pkt_iv [ FD_SLOW_IV_SZ  ] ) {

  ulong out_sz = pkt_sz + FD_SLOW_TAG_SZ;
  if( FD_UNLIKELY( hdr_sz < 5 ||
                   hdr_sz + 1 > pkt_sz ||
                   out_sz > out_max ) ) {
    return 0UL;
  }

  memmove( out, pkt, hdr_sz );

  ulong pktnum_sz  = fd_slow_h0_pktnum_len( out[ 0 ] )+1; /* in [1,4] */
  ulong pktnum_off = hdr_sz - pktnum_sz;
  if( FD_UNLIKELY( pktnum_off+20UL > pkt_sz ) ) {
    return 0UL; /* cannot take pkt protection sample */
  }
  FD_DCHECK_CRIT( pktnum_sz              <  hdr_sz, "bounds check" );
  FD_DCHECK_CRIT( pktnum_off + pktnum_sz <= hdr_sz, "bounds check" );

  /* Header protection (involution) */

  fd_slow_pkt_hdr_encrypt( out, pkt, pkt_sz, pktnum_off, hp_key );

  /* Payload protection
     https://www.rfc-editor.org/rfc/rfc9001.html#section-5.3

     > The associated data, A, for the AEAD is the contents of the QUIC
     > header, starting from the first byte of either the short or long
     > header, up to and including the unprotected packet number.
     >
     > The input plaintext, P, for the AEAD is the payload of the QUIC
     > packet, as described in RFC 9000.
     >
     > The output ciphertext, C, of the AEAD is transmitted in place of
     > P. */

  uchar nonce[ FD_SLOW_IV_SZ ];
  fd_slow_pkt_nonce( nonce, pkt_iv, pktnum );
  fd_aes_gcm_t  aead[1];
  uchar *       c    = out    + hdr_sz;
  ulong         c_sz = pkt_sz - hdr_sz;
  uchar *       mac  = c      + c_sz;
  uchar const * p    = pkt    + hdr_sz;
  ulong         p_sz = pkt_sz - hdr_sz;
  uchar const * a    = out; /* or pkt */
  ulong         a_sz = hdr_sz;
  fd_aes_128_gcm_init( aead, pkt_key, nonce );
  fd_aes_gcm_encrypt( aead, c, p, p_sz, a, a_sz, mac );

  return out_sz;
}

ulong
fd_slow_pkt_decrypt_hdr( uchar *     pkt,
                         ulong       pkt_sz,
                         ulong       pktnum_off,
                         uchar const hp_key[ FD_SLOW_KEY_SZ ] ) {
  if( FD_UNLIKELY( pkt_sz < FD_SLOW_TAG_SZ ||
                   pktnum_off+20 >= pkt_sz ) ) {
    return 0UL;
  }

  ulong pktnum_sz = fd_slow_h0_pktnum_len( pkt[ 0 ] )+1; /* in [1,4] */
  fd_slow_pkt_hdr_encrypt( pkt, pkt, pkt_sz, pktnum_off, hp_key );
  return pktnum_off + pktnum_sz;
}

ulong
fd_slow_pkt_decrypt( uchar *     pkt,
                     ulong       pkt_sz,
                     ulong       pktnum_off,
                     ulong       pktnum,
                     uchar const pkt_key[ FD_SLOW_KEY_SZ ],
                     uchar const pkt_iv [ FD_SLOW_IV_SZ  ] ) {

  ulong pktnum_sz = fd_slow_h0_pktnum_len( pkt[ 0 ] )+1; /* in [1,4] */
  ulong hdr_sz    = pktnum_off + pktnum_sz;
  if( FD_UNLIKELY( hdr_sz+FD_SLOW_TAG_SZ > pkt_sz ) ) return 0UL;

  uchar nonce[ FD_SLOW_IV_SZ ];
  fd_slow_pkt_nonce( nonce, pkt_iv, pktnum );
  fd_aes_gcm_t  aead[1];
  uchar *       c    = pkt    + hdr_sz;
  ulong         c_sz = pkt_sz - hdr_sz;
  uchar *       mac  = c      + c_sz;
  uchar const * a    = pkt; /* or pkt */
  ulong         a_sz = hdr_sz;
  fd_aes_128_gcm_init( aead, pkt_key, nonce );
  int ok = fd_aes_gcm_decrypt( aead, c, c, c_sz, a, a_sz, mac );

  return ok ? pkt_sz - FD_SLOW_TAG_SZ : 0UL;
}

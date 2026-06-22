#ifndef HEADER_fd_src_waltz_slow_fd_slow_crypto_h
#define HEADER_fd_src_waltz_slow_fd_slow_crypto_h

/* fd_slow_crypto.h deals with QUIC packet encryption. */

#include "fd_slow_key.h"

#define FD_SLOW_TAG_SZ 16

FD_PROTOTYPES_BEGIN

/**
 * fd_slow_pkt_encrypt encrypts a QUIC packet.
 *
 * Encryption grows the size of the packet because it appends a MAC tag.
 * Encryption is optionally in-place.  Uses AES-128-GCM.
 *
 * @param pkt      Points to unencrypted QUIC packet
 * @param pkt_sz   Unencrypted QUIC packet size
 * @param out      Points to encrypted QUIC packet out buffer
 * @param out_max  Out buffer capacity (encryption grows the packet)
 * @param hdr_sz   QUIC packet header size
 * @param pktnum   Packet number (must not be reused)
 * @param hp_key   Header protection key
 * @param pkt_key  Packet protection key
 * @param pkt_iv   Packet protection IV
 * @return         Encrypted packet size, or 0 on failure (e.g.
 *                 insufficient pkt_max or tiny pkt_sz)
 *
 * @note pkt and out should either be separate buffers or the same
         (pkt==out, out_max>pkt_sz).  Partial overlap is U.B.
 */

ulong
fd_slow_pkt_encrypt( uchar const * pkt,
                     ulong         pkt_sz,
                     uchar *       out,
                     ulong         out_max,
                     ulong         hdr_sz,
                     ulong         pktnum,
                     uchar const   hp_key [ FD_SLOW_KEY_SZ ],
                     uchar const   pkt_key[ FD_SLOW_KEY_SZ ],
                     uchar const   pkt_iv [ FD_SLOW_IV_SZ  ] );

/**
 * fd_slow_pkt_decrypt_hdr decrypts the a QUIC packet header in-place.
 *
 * @param pkt        Points to encrypted QUIC packet
 * @param pkt_sz     Encrypted packet size
 * @param pktnum_off Offset of packet number from start of QUIC packet
 * @param hp_key     Header protection key
 * @return           Header size, or 0 on failure
 *
 * @note This function reads bytes past the packet header
 */

ulong
fd_slow_pkt_decrypt_hdr( uchar *     pkt,
                         ulong       pkt_sz,
                         ulong       pktnum_off,
                         uchar const hp_key[ FD_SLOW_KEY_SZ ] );

/**
 * fd_slow_pkt_decrypt decrypts a QUIC packet in-place.
 *
 * Decryption slightly shrinks the packet size (drops the MAC tag).
 * Assumes header is already decrypted.  Uses AES-128-GCM.
 *
 * @param pkt        Points to partially-encrypted QUIC packet
 * @param pkt_sz     Encrypted packet size
 * @param pktnum_off Offset of packet number from start of QUIC packet
 * @param pktnum     Recovered packet number
 * @param pkt_key    Packet protection key
 * @param pkt_iv     Packet protection IV
 * @return           Decrypted packet size, or 0 on failure
 *
 * @note pkt_{key,iv} are chosen according to the Key Phase bit
 */

ulong
fd_slow_pkt_decrypt( uchar *     pkt,
                     ulong       pkt_sz,
                     ulong       pktnum_off,
                     ulong       pktnum,
                     uchar const pkt_key[ FD_SLOW_KEY_SZ ],
                     uchar const pkt_iv [ FD_SLOW_IV_SZ  ] );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_slow_fd_slow_crypto_h */

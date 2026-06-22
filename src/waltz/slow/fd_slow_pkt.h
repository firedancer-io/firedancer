#ifndef HEADER_fd_src_waltz_slow_fd_slow_pkt_h
#define HEADER_fd_src_waltz_slow_fd_slow_pkt_h

/* fd_slow_pkt.h provides APIs for handling QUIC packets. */

#include "../../util/bits/fd_bits.h"

#define FD_QUICv1_CID_SZ_MAX 20

/* fd_slow_hdr_t describes the common header of all QUIC v1 packets. */

struct fd_slow_hdr {
  union {
    uchar dcid_long[ FD_QUICv1_CID_SZ_MAX ];
    ulong dcid;
  };
  uchar dcid_sz; /* in [0,FD_QUICv1_CID_SZ_MAX] */
  uchar h0; /* partially encrypted */
};

typedef struct fd_slow_hdr fd_slow_hdr_t;

/* fd_slow_h0_hdr_form extract the 'Header Form' bit, the MSB of the
   first byte of a QUIC v1 packet.  Returns 1 if the packet is a long
   header packet, 0 if the packet is a short header packet.  Encrypted
   h0 is fine. */

static inline uchar
fd_slow_h0_hdr_form( uchar h0 ) {
  return h0>>7;
}

/* fd_slow_h0_long_packet_type extracts the 'Long Packet Type' from
   the first byte of a QUIC v1 long header packet. retval in range [0,4)
   Encrypted h0 is fine. */

static inline uchar
fd_slow_h0_long_packet_type( uchar h0 ) {
  return (h0>>4)&3;
}

/* fd_slow_h0_pktnum_len extracts the **compressed** length of the
   Packet Number from the first byte of a QUIC v1 packet.  Requires
   decrypted h0.  To uncompress, add 1. */

static inline uchar
fd_slow_h0_pktnum_len( uint h0 ) {
  return (uchar)( h0 & 0x03 );
}

/* fd_slow_peek extracts the packet type and DCID of an incoming
   protected QUIC v1 packet. */

static inline fd_slow_hdr_t *
fd_slow_peek_hdr( fd_slow_hdr_t * peek,
                  uchar const *   payload,
                  ulong           payload_sz ) {

  if( FD_UNLIKELY( !payload_sz ) ) return NULL;
  if( FD_LIKELY( !fd_slow_h0_hdr_form( payload[ 0 ] ) ) ) {
    if( FD_UNLIKELY( payload_sz<9UL ) ) return NULL;
    *peek = (fd_slow_hdr_t) {
      .dcid     = FD_LOAD( ulong, payload+1 ),
      .dcid_sz  = sizeof(ulong)
    };
    return peek;
  }

  if( FD_UNLIKELY( payload_sz<7UL ) ) return NULL;
  uint version = FD_LOAD( uint, payload );
  if( FD_UNLIKELY( version!=1U ) ) return NULL;
  payload += 5; payload_sz -= 5;

  uchar dcid_sz = payload[ 0 ];
  if( FD_UNLIKELY( dcid_sz>20 ) ) return NULL;
  payload += 1U; payload_sz -= 1U;
  if( FD_UNLIKELY( payload_sz<dcid_sz ) ) return NULL;
  *peek = (fd_slow_hdr_t) {
    .dcid_sz  = dcid_sz
  };
  memcpy( peek->dcid_long, payload, dcid_sz );
  return peek;
}

#define FD_SLOW_PKT_INITIAL   FD_QUICv1_LPKT_INITIAL   /* 0 */
#define FD_SLOW_PKT_ZERO_RTT  FD_QUICv1_LPKT_ZERO_RTT  /* 1 */
#define FD_SLOW_PKT_HANDSHAKE FD_QUICv1_LPKT_HANDSHAKE /* 2 */
#define FD_SLOW_PKT_RETRY     FD_QUICv1_LPKT_RETRY     /* 3 */
#define FD_SLOW_PKT_ONE_RTT   4

struct fd_slow_initial_pkt {
  uchar  h0;
  uchar  dcid_len;
  uchar  dcid[ FD_QUICv1_CID_SZ_MAX ];
  uchar  scid_len;
  uchar  scid[ FD_QUICv1_CID_SZ_MAX ];
  uchar  token_len;
  ushort token_off;
  ulong  len;
  ulong  pktnum;
};

typedef struct fd_slow_initial_pkt fd_slow_initial_pkt_t;

struct fd_slow_handshake_pkt {
  uchar h0;
  uchar scid_len;
  uchar scid[ FD_QUICv1_CID_SZ_MAX ];
  ulong dcid;
  ulong len;
};

typedef struct fd_slow_handshake_pkt fd_slow_handshake_pkt_t;

struct fd_slow_retry_pkt {
  uchar  h0;
  uchar  dcid_len;
  uchar  dcid[ FD_QUICv1_CID_SZ_MAX ];
  uchar  scid_len;
  uchar  scid[ FD_QUICv1_CID_SZ_MAX ];
  uchar  token_len;
  ushort token_off;
  ushort integrity_tag_off;
};

typedef struct fd_slow_retry_pkt fd_slow_retry_pkt_t;

#endif /* HEADER_fd_src_waltz_slow_fd_slow_pkt_h */

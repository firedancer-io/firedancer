#ifndef HEADER_fd_src_waltz_quic_fd_quic_ack_tx_h
#define HEADER_fd_src_waltz_quic_fd_quic_ack_tx_h

/* fd_quic_ack_tx.h provides APIs for generating ACK packets.

   fd_quic generates delayed ACKs fire-and-forget style.
   Outgoing ACKs are artificially delayed by a pseudorandom delay.
   The max delay is known to the peer via the max_ack_delay transport
   parameter. */

#include "fd_quic_common.h"

/* FD_QUIC_ACK_QUEUE_CNT controls the number of disjoint ACK ranges
   that can be acknowledged between two calls to fd_quic_service.
   Higher values decrease retransmission rates in case of excessive
   reordering.  Must be a power of 2.

   Seq ack_queue_head-1 is always assumed to be valid. */

# define FD_QUIC_ACK_QUEUE_CNT (8)

/* fd_quic_ack_t is used to build an ACK frame.  It contains a
   contiguous range of packet numbers to ACK.  Whenever an fd_quic_t
   instance successfully processes a packet, it accumulates the packet
   number into an fd_quic_ack_t. */

struct __attribute__((aligned(16))) fd_quic_ack {
  fd_quic_range_t pkt_number;  /* Range of packet numbers being ACKed */
  ulong           ts;          /* timestamp of highest packet number */
  uchar           enc_level;   /* in [0,4) */
  /* FIXME enc_level should technically be pn_space instead */
  uchar           _pad[7];
  /* Tuned to 32 byte size */
};

typedef struct fd_quic_ack fd_quic_ack_t;

/* fd_quic_ack_gen_t records processed packet numbers and builds ACK
   frames.

   ack_elicited==1 if at least one ACK-eliciting frame was received.
   No ACK frames will be generated unless this is the case.

   ack_instant==1 if an ACK for a packet must not be delayed.
   This is currently the case for initial and handshake-level packets.
   Note that ack_elicited==1 takes priority.

   The ack_queue ring caches the last generated ACK frames.  It uses
   sequence numbers that wrap around in [0,2^32).  queue_tail is the seq
   no of the oldest unsent ACK frame.  queue_head is the next unused
   seq.  Note that packet number ranges in this ring have no ordering
   requirements.

   All fd_quic_ack_t in the ack_queue array are initialized, even when
   they are not present in the ring.  If the ring is empty (head==tail),
   may peek the element at seq queue_head-1. */

struct __attribute__((aligned(16))) fd_quic_ack_gen {

  fd_quic_ack_t  queue[FD_QUIC_ACK_QUEUE_CNT];
  uint           head;
  uint           tail;

  ulong          pending_bytes;  /* No of stream bytes pending ACK, causes fast ACK if too high */
  ulong          deadline;       /* Delay ACK until this timestamp; in [0,1] */
  uchar          is_elicited;
  uchar          is_instant;

};

typedef struct fd_quic_ack_gen fd_quic_ack_gen_t;

FD_PROTOTYPES_BEGIN

/* fd_quic_ack_gen_init initializes the fd_quic_ack_gen_t instance. */

static inline fd_quic_ack_gen_t *
fd_quic_ack_gen_init( fd_quic_ack_gen_t * ack_gen ) {
  memset( ack_gen, 0, sizeof(fd_quic_ack_gen_t) );
  ack_gen->deadline = ULONG_MAX;
  return ack_gen;
}

/* fd_quic_ack_pkt queues a processed packet for acknowledgement. */

void
fd_quic_ack_pkt( fd_quic_ack_gen_t *      ack_gen,
                 fd_quic_config_t const * cfg,
                 fd_quic_pkt_t * const    pkt,
                 ulong                    now,
                 fd_rng_t *               rng );

/* fd_quic_ack_queue_ele returns the ack_queue element indexed by a
   sequence number. */

FD_FN_PURE static inline fd_quic_ack_t *
fd_quic_ack_queue_ele( fd_quic_ack_gen_t * ack_gen,
                       uint                idx ) {
  return ack_gen->queue + (idx & (FD_QUIC_ACK_QUEUE_CNT-1));
}

/* fd_quic_ack_gen_deadline returns the timestamp at which queued ACK
   ranges should be sent to the peer. */

FD_FN_PURE ulong
fd_quic_ack_gen_next_wakeup( fd_quic_ack_gen_t const * ack_gen,
                             fd_quic_config_t const *  cfg,
                             ulong                     now );

/* fd_quic_ack_gen_abandon_enc_level removes queued ACKs with an
   encryption level equal or lower than enc_level. */

void
fd_quic_ack_gen_abandon_enc_level( fd_quic_ack_gen_t * ack_gen,
                                   uint                enc_level );

/* fd_quic_gen_ack_frames writes ACK frames to the memory region
   [payload_ptr,payload_end).  Returns a pointer one past the last byte
   written (in [payload_ptr,payload_end]). */

uchar *
fd_quic_gen_ack_frames( fd_quic_ack_gen_t *      gen,
                        fd_quic_config_t const * cfg,
                        uchar *                  payload_ptr,
                        uchar *                  payload_end,
                        uint                     enc_level,
                        ulong                    now );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_fd_quic_ack_tx_h */

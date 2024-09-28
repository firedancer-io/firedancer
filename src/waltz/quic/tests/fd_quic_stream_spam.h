#ifndef HEADER_fd_src_waltz_quic_tests_fd_quic_stream_spam_h
#define HEADER_fd_src_waltz_quic_tests_fd_quic_stream_spam_h

#include "../fd_quic.h"
#include "../../../ballet/txn/fd_txn.h" /* FD_TXN_MTU */

/* fd_quic_stream_gen_spam_t is a virtual fn that generates a random
   stream buffer to be sent given a stream ID.  data points to a
   writable buffer to be filled in.  On return, this buffer is filled
   with the QUIC stream payload to be sent.  Returns the actual size
   of the payload (which is less or equal to buffer sz).  ctx is the
   virtual call context set in fd_quic_stream_spam_new. */

typedef ulong
(* fd_quic_stream_gen_spam_t)( void * ctx,
                               uchar  data[ FD_TXN_MTU ],
                               ulong  seq );

/* fd_quic_stream_spam_t is a simple load generator that sends sub-MTU
   size unidirectional streams at max rate. */

struct fd_quic_stream_spam {
  fd_quic_stream_gen_spam_t gen_fn;
  void *                    gen_ctx;
  ulong                     seq;
};

typedef struct fd_quic_stream_spam fd_quic_stream_spam_t;

FD_PROTOTYPES_BEGIN

/* fd_quic_stream_spam_service initiates as many random streams as
   possible. Returns number of streams sent on success, -1 on fatal
   error. */

ulong
fd_quic_stream_spam_service( fd_quic_conn_t *        conn,
                             fd_quic_stream_spam_t * spam );

/* fd_quic_stream_spam_gen is an impl of fd_quic_stream_gen_spam_t.
   ctx is ignored.  Generates random bytes with random size within
   [0,pkt->buf_sz) */

ulong
fd_quic_stream_spam_gen( void * ctx,
                         uchar  data[ FD_TXN_MTU ],
                         ulong  seq );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_tests_test_stream_spam_h */


#ifndef HEADER_fd_src_waltz_quic_tests_fd_quic_stream_spam_h
#define HEADER_fd_src_waltz_quic_tests_fd_quic_stream_spam_h

#include "../fd_quic.h"

/* fd_quic_stream_spam_t is a simple load generator that sends sub-MTU
   size unidirectional streams at max rate. */

struct fd_quic_stream_spam_private;
typedef struct fd_quic_stream_spam_private fd_quic_stream_spam_t;

/* fd_quic_stream_gen_spam_t is a virtual fn that generates a random
   stream buffer to be sent given a stream ID.  pkt points to a packet
   info to be filled in.  On entry, pkt->buf is a writable buffer of
   pkt->buf_sz bytes.  On return, this buffer is filled with the QUIC
   stream payload to be sent and pkt->buf_sz is set to the actual size
   of the payload (which is less or equal to buffer sz).  ctx is the
   virtual call context set in fd_quic_stream_spam_new. */

typedef void
(* fd_quic_stream_gen_spam_t)( void *              ctx,
                               fd_aio_pkt_info_t * pkt,
                               fd_quic_stream_t *  stream );

FD_PROTOTYPES_BEGIN

ulong
fd_quic_stream_spam_align( void );

ulong
fd_quic_stream_spam_footprint( ulong stream_cnt );

void *
fd_quic_stream_spam_new( void *                    mem,
                         ulong                     stream_cnt,
                         fd_quic_stream_gen_spam_t gen_fn,
                         void *                    gen_ctx );

fd_quic_stream_spam_t *
fd_quic_stream_spam_join( void * shspam );

void *
fd_quic_stream_spam_leave( fd_quic_stream_spam_t * spam );

void *
fd_quic_stream_spam_delete( void * shspam );

/* fd_quic_stream_spam_service initiates as many random streams as
   possible. Returns number of streams sent on success, -1 on fatal
   error. */

long
fd_quic_stream_spam_service( fd_quic_conn_t *        conn,
                             fd_quic_stream_spam_t * spam );

/* fd_quic_stream_spam_notify notifies the spammer of impending
   finalization of a stream.  U.B. if given stream was not created
   during a fd_quic_stream_spam_service() call. */

void
fd_quic_stream_spam_notify( fd_quic_stream_t * stream,
                            void *             ctx,
                            int                type );

/* fd_quic_stream_spam_gen is an impl of fd_quic_stream_gen_spam_t.
   ctx is ignored.  Generates random bytes with random size within
   [0,pkt->buf_sz) */

void
fd_quic_stream_spam_gen( void *              ctx,
                         fd_aio_pkt_info_t * pkt,
                         fd_quic_stream_t *  stream );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_tests_test_stream_spam_h */


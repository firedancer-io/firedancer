#ifndef HEADER_fd_src_tango_quic_fd_quic_stream_h
#define HEADER_fd_src_tango_quic_fd_quic_stream_h

#include "fd_quic_common.h"
#include "../../util/fd_util.h"

#define FD_QUIC_STREAM_ID_UNUSED (~0ul)

/* Forward declarations */

typedef struct fd_quic_conn       fd_quic_conn_t;
typedef struct fd_quic_stream     fd_quic_stream_t;
typedef struct fd_quic_stream_map fd_quic_stream_map_t;

/* fd_quic_buffer_t is a circular buffer */

struct fd_quic_buffer {
  uchar * buf;
  ulong   cap;  /* capacity of buffer; assert fd_ulong_is_pow2 */

  /* offsets to beginning of stream
     should be masked before being used to access buf data */
  ulong   head; /* first unused byte of stream */
  ulong   tail; /* first byte of used range    */
};
typedef struct fd_quic_buffer fd_quic_buffer_t;


/* buffer helper functions
   fd_quic_buffer_used  returns bytes used in buffer
   fd_quic_buffer_avail returns bytes available in buffer */
#define fd_quic_buffer_used(  buf ) ( (buf)->head - (buf)->tail )
#define fd_quic_buffer_avail( buf ) ( (buf)->cap - fd_quic_buffer_used(buf) )

struct fd_quic_stream {
  fd_quic_conn_t * conn;

  ulong            stream_id;  /* all 1's indicates an unused stream object */
  void *           context;    /* user context for callbacks */

  fd_quic_buffer_t tx_buf;     /* transmit buffer */
  uchar *          tx_ack;     /* ack - 1 bit per byte of tx_buf */
  ulong            tx_sent;    /* stream offset of first unsent byte of tx_buf */

  uint stream_flags;   /* flags representing elements that require action */
# define FD_QUIC_STREAM_FLAGS_TX_FIN          (1u<<0u)
# define FD_QUIC_STREAM_FLAGS_RX_FIN          (1u<<1u)
# define FD_QUIC_STREAM_FLAGS_MAX_STREAM_DATA (1u<<2u)
# define FD_QUIC_STREAM_FLAGS_UNSENT          (1u<<3u)
# define FD_QUIC_STREAM_FLAGS_DEAD            (1u<<4u)

# define FD_QUIC_STREAM_FLAGS_ACTION                   \
           ( FD_QUIC_STREAM_FLAGS_TX_FIN           |   \
             FD_QUIC_STREAM_FLAGS_RX_FIN           |   \
             FD_QUIC_STREAM_FLAGS_MAX_STREAM_DATA  |   \
             FD_QUIC_STREAM_FLAGS_UNSENT           )

# define FD_QUIC_STREAM_ACTION(stream) \
           (!!( (stream)->stream_flags & FD_QUIC_STREAM_FLAGS_ACTION ))


  uint sentinel; /* does this stream represent a sentinel? */

  /* send and receive state
     mask made up of the following:
       FD_QUIC_STREAM_STATE_TX_FIN      TX is finished (no more TX)
       FD_QUIC_STREAM_STATE_RX_FIN      RX is finished (no more RX)
       FD_QUIC_STREAM_STATE_DEAD        stream is dead and waiting to be
	                                  reclaimed */
  uint state;
# define FD_QUIC_STREAM_STATE_TX_FIN (1u<<0u)
# define FD_QUIC_STREAM_STATE_RX_FIN (1u<<1u)
# define FD_QUIC_STREAM_STATE_DEAD   (1u<<2u)

# define FD_QUIC_DEFAULT_INITIAL_RX_MAX_STREAM_DATA 1280  // IPv6 minimum MTU

  /* flow control */
  ulong  tx_max_stream_data; /* the limit on the number of bytes we are allowed to send
                                  to the peer on this stream
                                  this includes bytes implied by offsets that have not
                                  been received yet */
  ulong  tx_tot_data;        /* the total number of bytes transmitted on this stream */
  ulong  tx_last_byte;       /* the index of the last byte of the stream
                                valid only if FD_QUIC_STREAM_FLAGS_TX_FIN set */

  ulong  rx_max_stream_data; /* the limit on the number of bytes we allow the peer to
                                  send to us */
  ulong  rx_max_stream_data_ackd;
                             /* the largest acked value of rx_max_stream_data */
  ulong  rx_tot_data;        /* the total number of bytes received on this stream */

  /* last tx packet num with max_stream_data frame referring to this stream
     set to next_pkt_number to indicate a new max_stream_data frame should be sent
     if we time out this packet (or possibly a later packet) we resend the frame
       and update this value */
  ulong upd_pkt_number;

  /* doubly linked list with sentinel */
  struct fd_quic_stream * next;
  struct fd_quic_stream * prev;

  /* TODO need a timeout on this data */
};

#define FD_QUIC_STREAM_LIST_LINK( LHS, RHS ) \
  do {                                                         \
    (LHS)->next = (RHS);                                       \
    (RHS)->prev = (LHS);                                       \
  } while(0)

/* set up linked list sentinel
   sentinel just points to itself, at first */
#define FD_QUIC_STREAM_LIST_SENTINEL( stream )                 \
  do {                                                         \
    FD_QUIC_STREAM_LIST_LINK( stream, stream );                \
    stream->sentinel = 1;                                      \
  } while(0)

/* insert new_stream after stream in list */
#define FD_QUIC_STREAM_LIST_INSERT_AFTER( stream, new_stream ) \
  do {                                                         \
    fd_quic_stream_t * stream_next = (stream)->next;           \
    FD_QUIC_STREAM_LIST_LINK( stream,     new_stream );        \
    FD_QUIC_STREAM_LIST_LINK( new_stream, stream_next );       \
  } while(0)

/* insert new_stream before stream in list */
#define FD_QUIC_STREAM_LIST_INSERT_BEFORE( stream, new_stream ) \
  do {                                                          \
    fd_quic_stream_t * stream_prev = (stream)->prev;            \
    FD_QUIC_STREAM_LIST_LINK( new_stream,  stream     );        \
    FD_QUIC_STREAM_LIST_LINK( stream_prev, new_stream );        \
  } while(0)

/* remove stream from list */
#define FD_QUIC_STREAM_LIST_REMOVE( stream )                    \
  do {                                                          \
    fd_quic_stream_t * stream_prev = (stream)->prev;            \
    fd_quic_stream_t * stream_next = (stream)->next;            \
    FD_QUIC_STREAM_LIST_LINK( stream_prev, stream_next     );   \
    (stream)->next = (stream)->prev = stream;                   \
  } while(0)



/* stream map for use in fd_map_dynamic map */
struct fd_quic_stream_map {
  ulong              stream_id; /* key */
  uint               hash;      /* hash */
  fd_quic_stream_t * stream;    /* value */
};

FD_PROTOTYPES_BEGIN

/* fd_quic_buffer_store
   store data into circular buffer */
void
fd_quic_buffer_store( fd_quic_buffer_t * buf,
                      uchar const *      data,
                      ulong              data_sz );

/* fd_quic_buffer_load
   load data from circular buffer */
void
fd_quic_buffer_load( fd_quic_buffer_t * buf,
                     ulong              offs,
                     uchar *            data,
                     ulong              data_sz );

/* returns the alignment of the fd_quic_stream_t */
FD_FN_CONST inline
ulong
fd_quic_stream_align( void ) {
  return 128ul;
}

/* returns the required footprint of fd_quic_stream_t

   args
     tx_buf_sz    the size of the tx buffer */
FD_FN_CONST
ulong
fd_quic_stream_footprint( ulong tx_buf_sz );

/* returns a newly initialized stream

   args
     mem          the memory aligned to fd_quic_stream_align, and at least fd_quic_stream_footprint
                    bytes
     tx_buf_sz    the size of the tx buffer */
fd_quic_stream_t *
fd_quic_stream_new( void * mem, fd_quic_conn_t * conn, ulong tx_buf_sz );

/* delete a stream

   args
     stream       the stream to free */
void
fd_quic_stream_delete( fd_quic_stream_t * stream );


/* set stream context

   args
     stream      the stream with which to associate the context
     context     the user-defined context associated with the stream */
void
fd_quic_stream_set_context( fd_quic_stream_t * stream, void * context );


/* get stream context

   args
     stream      the stream from which to obtain the context

   returns
     context     the user defined context associated with the stream */
void *
fd_quic_stream_get_context( fd_quic_stream_t * stream );

void
fd_quic_stream_set_rx_max_stream_data( fd_quic_stream_t * stream, ulong rx_max_stream_data );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_quic_fd_quic_stream_h */

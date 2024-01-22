#ifndef HEADER_fd_src_tango_quic_fd_quic_pkt_meta_h
#define HEADER_fd_src_tango_quic_fd_quic_pkt_meta_h

#include "../../util/fd_util.h"

typedef struct fd_quic_pkt_meta      fd_quic_pkt_meta_t;
typedef struct fd_quic_range         fd_quic_range_t;
typedef struct fd_quic_pkt_meta_list fd_quic_pkt_meta_list_t;
typedef struct fd_quic_pkt_meta_pool fd_quic_pkt_meta_pool_t;

struct fd_quic_range {
  /* offset in [ offset_lo, offset_hi ) is considered inside the range */
  /* a zero-initialized range will be empty [0,0) */
  ulong offset_lo;
  ulong offset_hi;
};

/* TODO convert to a union with various types of metadata overlaid */

/* fd_quic_pkt_meta_var used for tracking max_data, max_stream_data and
 * max_streams
 *
 * type:      FD_QUIC_PKT_META_TYPE_STREAM_DATA
 *            FD_QUIC_PKT_META_TYPE_MAX_STREAM_DATA
 *            FD_QUIC_PKT_META_TYPE_OTHER
 * flags:     FD_QUIC_PKT_META_FLAGS_*
 * value:     max_data          number of bytes
 *            max_stream_data   number of bytes
 *            max_streams       number of streams
 */
union fd_quic_pkt_meta_key {
  union {
    ulong stream_id:62;
    struct {
      ulong flags:62;
      ulong type:2;
#define FD_QUIC_PKT_META_TYPE_OTHER           0
#define FD_QUIC_PKT_META_TYPE_STREAM_DATA     1
#define FD_QUIC_PKT_META_TYPE_MAX_STREAM_DATA 2
    };
  };
};
typedef union fd_quic_pkt_meta_key fd_quic_pkt_meta_key_t;

struct fd_quic_pkt_meta_var {
  fd_quic_pkt_meta_key_t key;
  ulong                  value;
};
typedef struct fd_quic_pkt_meta_var fd_quic_pkt_meta_var_t;

/* the max number of pkt_meta_var entries in pkt_meta
   this limits the number of max_data, max_stream_data and max_streams
   allowed in a single quic packet */
#define FD_QUIC_PKT_META_VAR_MAX 16

/* fd_quic_pkt_meta

   tracks the metadata of data sent to the peer
   used when acks arrive to determine what is being acked specifically */
struct fd_quic_pkt_meta {
  /* stores metadata about what was sent in the identified packet */
  ulong                  pkt_number;  /* the packet number */
  uchar                  enc_level;   /* every packet is sent at a specific
                                       enc_level */
  uchar                  pn_space;    /* packet number space (must be consistent
                                       with enc_level)  */
  uchar                  status;
# define FD_QUIC_PKT_META_STATUS_UNUSED  ((uchar)0)
# define FD_QUIC_PKT_META_STATUS_PENDING ((uchar)1)
# define FD_QUIC_PKT_META_STATUS_SENT    ((uchar)2)

  uchar                  var_sz;      /* number of populated entries in var */

  /* does/should the referenced packet contain:
       FD_QUIC_PKT_META_FLAGS_HS_DATA             handshake data
       FD_QUIC_PKT_META_FLAGS_STREAM              stream data
       FD_QUIC_PKT_META_FLAGS_HS_DONE             handshake-done frame
       FD_QUIC_PKT_META_FLAGS_MAX_DATA            max_data frame
       FD_QUIC_PKT_META_FLAGS_MAX_STREAM_DATA     max_stream_data frame
       FD_QUIC_PKT_META_FLAGS_MAX_STREAMS_UNIDIR  max_streams frame (unidir)
       FD_QUIC_PKT_META_FLAGS_MAX_STREAMS_BIDIR   max_streams frame (bidir)
       FD_QUIC_PKT_META_FLAGS_ACK                 acknowledgement
       FD_QUIC_PKT_META_FLAGS_CLOSE               close frame
       FD_QUIC_PKT_META_FLAGS_KEY_UPDATE          indicates key update was in effect
       FD_QUIC_PKT_META_FLAGS_KEY_PHASE           set only if key_phase was set in the short-header

     some of these flags are mutually exclusive */
  uint                   flags;       /* flags */
# define          FD_QUIC_PKT_META_FLAGS_HS_DATA            (1u<<0u)
# define          FD_QUIC_PKT_META_FLAGS_STREAM             (1u<<1u)
# define          FD_QUIC_PKT_META_FLAGS_HS_DONE            (1u<<2u)
# define          FD_QUIC_PKT_META_FLAGS_MAX_DATA           (1u<<3u)
# define          FD_QUIC_PKT_META_FLAGS_MAX_STREAM_DATA    (1u<<4u)
# define          FD_QUIC_PKT_META_FLAGS_MAX_STREAMS_UNIDIR (1u<<5u)
# define          FD_QUIC_PKT_META_FLAGS_MAX_STREAMS_BIDIR  (1u<<6u)
# define          FD_QUIC_PKT_META_FLAGS_ACK                (1u<<7u)
# define          FD_QUIC_PKT_META_FLAGS_CLOSE              (1u<<8u)
# define          FD_QUIC_PKT_META_FLAGS_KEY_UPDATE         (1u<<9u)
# define          FD_QUIC_PKT_META_FLAGS_KEY_PHASE          (1u<<10u)
  fd_quic_range_t        range;       /* range of bytes referred to by this meta */
                                      /* stream data or crypto data */
                                      /* we currently do not put both in the same packet */
  ulong                  stream_id;   /* if this contains stream data,
                                         the stream id, else zero */

  ulong                  expiry; /* time pkt_meta expires... this is the time the
                                  ack is expected by */

  fd_quic_pkt_meta_var_t var[FD_QUIC_PKT_META_VAR_MAX];

  fd_quic_pkt_meta_t *   next;   /* next in current list */
};


struct fd_quic_pkt_meta_list {
  fd_quic_pkt_meta_t * head;
  fd_quic_pkt_meta_t * tail;
};


struct fd_quic_pkt_meta_pool {
  fd_quic_pkt_meta_list_t free;    /* free pkt_meta */

  /* one of each of these for each enc_level */
  fd_quic_pkt_meta_list_t sent[4]; /* sent pkt_meta */
  fd_quic_pkt_meta_list_t pend[4]; /* pending pkt_meta */
};



FD_PROTOTYPES_BEGIN

/* initialize pool with existing array of pkt_meta */
void
fd_quic_pkt_meta_pool_init( fd_quic_pkt_meta_pool_t * pool,
                            fd_quic_pkt_meta_t * pkt_meta_array,
                            ulong                pkt_meta_array_sz );

/* pop from front of list */
fd_quic_pkt_meta_t *
fd_quic_pkt_meta_pop_front( fd_quic_pkt_meta_list_t * list );


/* push onto front of list */
void
fd_quic_pkt_meta_push_front( fd_quic_pkt_meta_list_t * list,
                             fd_quic_pkt_meta_t *      pkt_meta );


/* push onto back of list */
void
fd_quic_pkt_meta_push_back( fd_quic_pkt_meta_list_t * list,
                            fd_quic_pkt_meta_t *      pkt_meta );

/* remove from list
   requires the prior element */
void
fd_quic_pkt_meta_remove( fd_quic_pkt_meta_list_t * list,
                         fd_quic_pkt_meta_t *      pkt_meta_prior,
                         fd_quic_pkt_meta_t *      pkt_meta );


/* allocate a pkt_meta
   obtains a free pkt_meta from the free list, and returns it
   returns NULL if none is available */
fd_quic_pkt_meta_t *
fd_quic_pkt_meta_allocate( fd_quic_pkt_meta_pool_t * pool );


/* free a pkt_meta
   returns a pkt_meta to the free list, ready to be allocated again */
void
fd_quic_pkt_meta_deallocate( fd_quic_pkt_meta_pool_t * pool,
                             fd_quic_pkt_meta_t *      pkt_meta );

FD_PROTOTYPES_END

#endif // HEADER_fd_src_tango_quic_fd_quic_pkt_meta_h


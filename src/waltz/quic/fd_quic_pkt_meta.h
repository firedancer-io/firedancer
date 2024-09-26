#ifndef HEADER_fd_src_waltz_quic_fd_quic_pkt_meta_h
#define HEADER_fd_src_waltz_quic_fd_quic_pkt_meta_h

/* fd_quic_pkt_meta.h declares structures to track send operations.

   fd_quic_pkt_meta_t are generated when new QUIC packets are sent, and
   are revisited when receiving acknowledgements or detecting timeouts.

   On timeout, fd_quic_pkt_meta_retry (fd_quic.c) looks at pkt_meta info
   to decide what to retransmit.  On ACK, fd_quic_reclaim_pkt_meta
   (fd_quic.c) frees resources that were retained for a potential
   retransmit. */

#include "fd_quic_common.h"

/* fd_quic_pkt_meta_var used for tracking max_data, max_stream_data and
 * max_streams
 *
 * type:      FD_QUIC_PKT_META_TYPE_STREAM_DATA
 *            FD_QUIC_PKT_META_TYPE_OTHER
 * flags:     FD_QUIC_PKT_META_FLAGS_*
 * value:     max_data          number of bytes
 *            max_stream_data   number of bytes
 *            max_streams       number of streams
 */
union fd_quic_pkt_meta_key {
  union {
#define FD_QUIC_PKT_META_STREAM_MASK ((1UL<<62UL)-1UL)
    ulong stream_id;
    struct {
      ulong flags:62;
      ulong type:2;
#define FD_QUIC_PKT_META_TYPE_OTHER           0UL
#define FD_QUIC_PKT_META_TYPE_STREAM_DATA     1UL
    };
#define FD_QUIC_PKT_META_KEY( TYPE, FLAGS, STREAM_ID ) \
    ((fd_quic_pkt_meta_key_t)                          \
     { .stream_id = ( ( (ulong)(STREAM_ID) )    |      \
                      ( (ulong)(TYPE) << 62UL ) |      \
                      ( (ulong)(FLAGS) ) ) } )
    /* FD_QUIC_PKT_META_STREAM_ID
     * This is used to extract the stream_id, since some of the bits are used
     * for "type".
     * The more natural way "stream_id:62" caused compilation warnings and ugly
     * work-arounds */
#define FD_QUIC_PKT_META_STREAM_ID( KEY ) ( (KEY).stream_id & FD_QUIC_PKT_META_STREAM_MASK )
  };
};
typedef union fd_quic_pkt_meta_key fd_quic_pkt_meta_key_t;

struct fd_quic_pkt_meta_var {
  fd_quic_pkt_meta_key_t key;
  union {
    ulong                value;
    fd_quic_range_t      range;
  };
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
       FD_QUIC_PKT_META_FLAGS_MAX_STREAMS_UNIDIR  max_streams frame (unidir)
       FD_QUIC_PKT_META_FLAGS_KEY_UPDATE          indicates key update was in effect
       FD_QUIC_PKT_META_FLAGS_KEY_PHASE           set only if key_phase was set in the short-header

     some of these flags are mutually exclusive */
  uint                   flags;       /* flags */
# define          FD_QUIC_PKT_META_FLAGS_HS_DATA            (1u<<0u)
# define          FD_QUIC_PKT_META_FLAGS_STREAM             (1u<<1u)
# define          FD_QUIC_PKT_META_FLAGS_HS_DONE            (1u<<2u)
# define          FD_QUIC_PKT_META_FLAGS_MAX_DATA           (1u<<3u)
# define          FD_QUIC_PKT_META_FLAGS_MAX_STREAMS_UNIDIR (1u<<5u)
# define          FD_QUIC_PKT_META_FLAGS_KEY_UPDATE         (1u<<9u)
# define          FD_QUIC_PKT_META_FLAGS_KEY_PHASE          (1u<<10u)
  fd_quic_range_t        range;       /* range of bytes referred to by this meta */
                                      /* stream data or crypto data */
                                      /* we currently do not put both in the same packet */

  ulong                  expiry; /* time pkt_meta expires... this is the time the
                                  ack is expected by */

  fd_quic_pkt_meta_var_t var[FD_QUIC_PKT_META_VAR_MAX];

  uint                   next;
};

#define SLIST_NAME  fd_quic_pkt_meta_list
#define SLIST_ELE_T fd_quic_pkt_meta_t
#define SLIST_IDX_T uint
#include "../../util/tmpl/fd_slist.c"

#endif /* HEADER_fd_src_waltz_quic_fd_quic_pkt_meta_h */


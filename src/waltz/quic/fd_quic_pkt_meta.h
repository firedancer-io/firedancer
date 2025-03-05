#ifndef HEADER_fd_src_waltz_quic_fd_quic_pkt_meta_h
#define HEADER_fd_src_waltz_quic_fd_quic_pkt_meta_h

#include "fd_quic_common.h"

typedef struct fd_quic_pkt_meta         fd_quic_pkt_meta_t;
typedef struct fd_quic_pkt_meta_list    fd_quic_pkt_meta_list_t;
typedef struct fd_quic_pkt_meta_tracker fd_quic_pkt_meta_tracker_t;

/* TODO convert to a union with various types of metadata overlaid */

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
  ulong pkt_number;  /* packet number (in pn_space) */
  uchar enc_level;   /* encryption level of packet */
  uchar pn_space;    /* packet number space (derived from enc_level) */
  uchar var_sz;      /* number of populated entries in var */

  /* does/should the referenced packet contain:
       FD_QUIC_PKT_META_FLAGS_HS_DATA             handshake data
       FD_QUIC_PKT_META_FLAGS_STREAM              stream data
       FD_QUIC_PKT_META_FLAGS_HS_DONE             handshake-done frame
       FD_QUIC_PKT_META_FLAGS_MAX_DATA            max_data frame
       FD_QUIC_PKT_META_FLAGS_MAX_STREAMS_UNIDIR  max_streams frame (unidir)
       FD_QUIC_PKT_META_FLAGS_CLOSE               close frame
       FD_QUIC_PKT_META_FLAGS_PING                set to send a PING frame

     some of these flags are mutually exclusive */
  uint                   flags;       /* flags */
# define          FD_QUIC_PKT_META_FLAGS_HS_DATA            (1u<<0u)
# define          FD_QUIC_PKT_META_FLAGS_STREAM             (1u<<1u)
# define          FD_QUIC_PKT_META_FLAGS_HS_DONE            (1u<<2u)
# define          FD_QUIC_PKT_META_FLAGS_MAX_DATA           (1u<<3u)
# define          FD_QUIC_PKT_META_FLAGS_MAX_STREAMS_UNIDIR (1u<<4u)
# define          FD_QUIC_PKT_META_FLAGS_CLOSE              (1u<<5u)
# define          FD_QUIC_PKT_META_FLAGS_PING               (1u<<6u)
  fd_quic_range_t        range;       /* CRYPTO data range; FIXME use pkt_meta var instead */
  ulong                  stream_id;   /* if this contains stream data,
                                         the stream id, else zero */

  ulong                  tx_time;     /* transmit time */
  ulong                  expiry;      /* time pkt_meta expires... this is the time the
                                         ack is expected by */

  fd_quic_pkt_meta_var_t var[FD_QUIC_PKT_META_VAR_MAX];

  /* treap fields */
  ulong parent;
  ulong left;
  ulong right;
  ulong prio;
  ulong next;
  ulong prev;
};

#define     POOL_NAME                 fd_quic_pkt_meta_pool
#define     POOL_T                    fd_quic_pkt_meta_t
#include "../../util/tmpl/fd_pool.c"

#define     TREAP_NAME                fd_quic_pkt_meta_treap
#define     TREAP_T                   fd_quic_pkt_meta_t
#define     TREAP_QUERY_T             ulong
#define     TREAP_CMP(q,e)            (int)((long)(q) - (long)(e)->pkt_number)
#define     TREAP_LT(e0,e1)           ((e0)->pkt_number < (e1)->pkt_number)
#define     TREAP_OPTIMIZE_ITERATION  1
#include "../../util/tmpl/fd_treap.c"

/* begin aliasing to abstract data structure */
typedef fd_quic_pkt_meta_treap_t            fd_quic_pkt_meta_ds_t;
typedef fd_quic_pkt_meta_treap_fwd_iter_t   fd_quic_pkt_meta_ds_fwd_iter_t;

/* fd_quic_pkt_meta_ds_fwd_iter_init is equivalent of ds.begin()
   @arguments:
   - ds: pointer to the ds
   - pool: pointer to the backing pool
   @returns:
   - beginning iterator */
static inline fd_quic_pkt_meta_ds_fwd_iter_t
fd_quic_pkt_meta_ds_fwd_iter_init( fd_quic_pkt_meta_ds_t * ds,
                                   fd_quic_pkt_meta_t    * pool ) {
  return fd_quic_pkt_meta_treap_fwd_iter_init( ds, pool );
}

/* fd_quic_pkt_meta_ds_fwd_iter_ele returns pkt_meta* from iter
   @arguments:
   - iter: iterator
   - pool: pointer to the backing pool
   @returns:
   - pointer to pkt_meta */
static inline fd_quic_pkt_meta_t *
fd_quic_pkt_meta_ds_fwd_iter_ele( fd_quic_pkt_meta_ds_fwd_iter_t   iter,
                                  fd_quic_pkt_meta_t             * pool ) {
  return fd_quic_pkt_meta_treap_fwd_iter_ele( iter, pool );
}

/* fd_quic_pkt_meta_ds_fwd_iter_next is equivalent of iter++
   @arguments:
   - iter: iterator
   - pool: pointer to the backing pool
   @returns:
   - next iterator */
static inline fd_quic_pkt_meta_ds_fwd_iter_t
fd_quic_pkt_meta_ds_fwd_iter_next( fd_quic_pkt_meta_ds_fwd_iter_t   iter,
                                   fd_quic_pkt_meta_t             * pool ) {
  return fd_quic_pkt_meta_treap_fwd_iter_next( iter, pool );
}

/* fd_quic_pkt_meta_ds_fwd_iter_done returns boolean
  @arguments
  - iter: iterator
  @returns
  - non-zero if iterator marks end, 0 otherwise */
static inline int
fd_quic_pkt_meta_ds_fwd_iter_done( fd_quic_pkt_meta_ds_fwd_iter_t iter ) {
  return fd_quic_pkt_meta_treap_fwd_iter_done( iter );
}

/* fd_quic_pkt_meta_ds_idx_ge returns iterator pointing to first pkt_meta
  whose packet number is >= pkt_number
  @arguments
  - ds: pointer to the ds
  - pkt_number: pkt_number to search for
  - pool: pointer to the backing pool
  @returns
  - iterator to first pkt_meta with pkt number >= pkt_number */
static inline fd_quic_pkt_meta_ds_fwd_iter_t
fd_quic_pkt_meta_ds_idx_ge( fd_quic_pkt_meta_ds_t * ds,
                            ulong                   pkt_number,
                            fd_quic_pkt_meta_t    * pool ) {
  return fd_quic_pkt_meta_treap_idx_ge( ds, pkt_number, pool );
}

/* fd_quic_pkt_meta_ds_ele_cnt returns count of elements in ds */
static inline ulong
fd_quic_pkt_meta_ds_ele_cnt( fd_quic_pkt_meta_ds_t * ds ) {
  return fd_quic_pkt_meta_treap_ele_cnt( ds );
}

/* end aliasing to abstract data structure */

struct fd_quic_pkt_meta_tracker {
  fd_quic_pkt_meta_ds_t       sent_pkt_metas[4];
};


/* fd_quic_pkt_meta_tracker_init_pool does any data structure-particular setup
   on the entire pool at once. Useful for e.g. treap randomness
   @arguments:
   - pool: pointer pkt_meta pool
   - total_meta_cnt: total pool size */
void
fd_quic_pkt_meta_tracker_init_pool( fd_quic_pkt_meta_t * pool,
                                    ulong                total_meta_cnt );


/* fd_quic_pkt_meta_tracker_init initializes the metadata tracker
  For each encoding level, it initializes the pkt_meta data structure
  @arguments:
  - tracker: pointer to the pkt_meta tracker
  - total_meta_cnt: total number of max pkt_meta entries in this tracker
    (shared across all encoding levels)
  @returns:
  - pointer to tracker if successful, NULL otherwise */
void *
fd_quic_pkt_meta_tracker_init( fd_quic_pkt_meta_tracker_t *  tracker,
                               ulong                         total_meta_cnt );

/* fd_quic_pkt_meta_insert inserts a pkt_meta into the ds
  @arguments:
  - ds: pointer to the ds
  - pkt_meta: pointer to the pkt_meta to insert. This pkt_meta
      should have been acquired from the pool
  - pool: pointer to the backing pool */
void
fd_quic_pkt_meta_insert( fd_quic_pkt_meta_ds_t * ds,
                         fd_quic_pkt_meta_t    * pkt_meta,
                         fd_quic_pkt_meta_t    * pool );

/*
   remove all pkt_meta in the range [pkt_number_lo, pkt_number_hi]
   rm from treap and return to pool
*/
/* fd_quic_pkt_meta_remove_range removes all pkt_meta in the range
  [pkt_number_lo, pkt_number_hi] from the ds and returns them to the pool.
  Any part of the range that's missing simply gets skipped
  @arguments:
  - ds: pointer to the ds
  - pool: pointer to the backing pool
  - pkt_number_lo: lower bound of the range
  - pkt_number_hi: upper bound of the range */
void
fd_quic_pkt_meta_remove_range( fd_quic_pkt_meta_ds_t * ds,
                               fd_quic_pkt_meta_t    * pool,
                               ulong                   pkt_number_lo,
                               ulong                   pkt_number_hi );

/* fd_quic_pkt_meta_min returns pointer to pkt_meta with smallest pkt_number in the ds
  @arguments:
  - ds: pointer to the ds
  - pool: pointer to the backing pool
  @returns:
  - pointer to pkt_meta with smallest pkt_number in the ds */
fd_quic_pkt_meta_t *
fd_quic_pkt_meta_min( fd_quic_pkt_meta_ds_t * ds,
                      fd_quic_pkt_meta_t    * pool );

/* fd_quic_pkt_meta_ds_clear clears all pkt_meta tracking for a given encoding level
  @arguments:
  - tracker: pointer to the pkt_meta tracker
  - enc_level: encoding level to clear */
void
fd_quic_pkt_meta_ds_clear( fd_quic_pkt_meta_tracker_t * tracker,
                           uint                         enc_level );

FD_PROTOTYPES_END

#endif // HEADER_fd_src_waltz_quic_fd_quic_pkt_meta_h

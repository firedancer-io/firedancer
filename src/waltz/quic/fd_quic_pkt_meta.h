#ifndef HEADER_fd_src_waltz_quic_fd_quic_pkt_meta_h
#define HEADER_fd_src_waltz_quic_fd_quic_pkt_meta_h

#include "fd_quic_common.h"

typedef struct fd_quic_pkt_meta         fd_quic_pkt_meta_t;
typedef struct fd_quic_pkt_meta_list    fd_quic_pkt_meta_list_t;
typedef struct fd_quic_pkt_meta_tracker fd_quic_pkt_meta_tracker_t;

/* fd_quic_pkt_meta_key used as key for tracking sent frames
 *
 * pkt_num:    packet number that carried this data
 * type:       type of data for retx (~frame type)
 * stream_id:  if stream type, the stream id
 */

union fd_quic_pkt_meta_key {
  struct {
    /* which frame type is recorded:
        FD_QUIC_PKT_META_TYPE_HS_DATA             handshake data
        FD_QUIC_PKT_META_TYPE_STREAM              stream data
        FD_QUIC_PKT_META_TYPE_HS_DONE             handshake-done frame
        FD_QUIC_PKT_META_TYPE_MAX_DATA            max_data frame
        FD_QUIC_PKT_META_TYPE_MAX_STREAMS_UNIDIR  max_streams frame (unidir)
        FD_QUIC_PKT_META_TYPE_CLOSE               close frame
        FD_QUIC_PKT_META_TYPE_PING                set to send a PING frame
    */
    # define          FD_QUIC_PKT_META_TYPE_HS_DATA            (0)
    # define          FD_QUIC_PKT_META_TYPE_STREAM             (1)
    # define          FD_QUIC_PKT_META_TYPE_HS_DONE            (2)
    # define          FD_QUIC_PKT_META_TYPE_MAX_DATA           (3)
    # define          FD_QUIC_PKT_META_TYPE_MAX_STREAMS_UNIDIR (4)
    # define          FD_QUIC_PKT_META_TYPE_CLOSE              (5)
    # define          FD_QUIC_PKT_META_TYPE_PING               (6)
    uchar type: 4;

    ulong pkt_num: 60;
    #define FD_QUIC_PKT_META_SET_TYPE(PKT_META_PTR, TYPE) \
      (PKT_META_PTR)->key.type = (uchar)((TYPE)&0x0f)

    #define FD_QUIC_PKT_META_PKT_NUM_MASK ( (1UL<<60) - 1 )
    #define FD_QUIC_PKT_META_SET_PKT_NUM(PKT_META_PTR, PKT_NUM) \
      (PKT_META_PTR)->key.pkt_num = (PKT_NUM)&FD_QUIC_PKT_META_PKT_NUM_MASK

    ulong stream_id;
  };
  ulong b[2];
};
typedef union fd_quic_pkt_meta_key fd_quic_pkt_meta_key_t;
FD_STATIC_ASSERT( sizeof(fd_quic_pkt_meta_key_t) == 16, fd_quic_pkt_meta_key_t );

union fd_quic_pkt_meta_value {
  ulong                scalar;
  fd_quic_range_t      range;
};
typedef union fd_quic_pkt_meta_value fd_quic_pkt_meta_value_t;


/* fd_quic_pkt_meta

   tracks the metadata of data sent to the peer
   used when acks arrive to determine what is being acked specifically */
struct fd_quic_pkt_meta {
  /* stores metadata about what was sent in the identified packet */
  fd_quic_pkt_meta_key_t   key;
  fd_quic_pkt_meta_value_t val;
  uchar                    enc_level: 2;
  uchar                    pn_space;    /* packet number space (derived from enc_level) */
  long                     tx_time;     /* transmit time */
  long                     expiry;      /* time pkt_meta expires... this is the time the
                                         ack is expected by */

  /* treap fields */
  ulong parent;
  ulong left;
  ulong right;
  ulong prio;
  ulong next;
  ulong prev;
};
typedef struct fd_quic_pkt_meta fd_quic_pkt_meta_t;

#define     POOL_NAME                 fd_quic_pkt_meta_pool
#define     POOL_T                    fd_quic_pkt_meta_t
#include "../../util/tmpl/fd_pool.c"

/* if <pkt_nums,type> are diff, returns sign of difference
 *
 * else, returns sign of difference in stream_id */
static inline int
fd_quic_pkt_meta_cmp( const fd_quic_pkt_meta_key_t   q,
                      const fd_quic_pkt_meta_t     * e ) {
  /* branchless implementation of:
    diff = q.b[0] - e->key.b[0]
    if( diff )
      return diff
    return q.stream_id - e->key.stream_id */
  ulong q_b = q.b[0];
  ulong e_b = e->key.b[0];
  ulong q_s = q.stream_id;
  ulong e_s = e->key.stream_id;

  int pkt_num_type_cmp = -2*(q_b < e_b) + ((q_b > e_b)<<1);
  int stream_id_cmp    = -1*(q_s < e_s) + (q_s > e_s);
  return pkt_num_type_cmp + stream_id_cmp;
}

static inline int
fd_quic_pkt_meta_lt( const fd_quic_pkt_meta_t * e1,
                     const fd_quic_pkt_meta_t * e2 ) {
  ulong e1_b0 = e1->key.b[0];
  ulong e2_b0 = e2->key.b[0];
  return e1_b0 < e2_b0 || (e1_b0 == e2_b0 && e1->key.stream_id < e2->key.stream_id);
}

#define     TREAP_NAME                fd_quic_pkt_meta_treap
#define     TREAP_T                   fd_quic_pkt_meta_t
#define     TREAP_QUERY_T             fd_quic_pkt_meta_key_t
#define     TREAP_CMP(q,e)            fd_quic_pkt_meta_cmp( q, e )
#define     TREAP_LT(e0,e1)           fd_quic_pkt_meta_lt( e0, e1 )
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
  return fd_quic_pkt_meta_treap_idx_ge( ds,
                                        (fd_quic_pkt_meta_key_t){
                                          .pkt_num = pkt_number & FD_QUIC_PKT_META_PKT_NUM_MASK,
                                          .type = 0,
                                          .stream_id = 0},
                                        pool );
}

/* fd_quic_pkt_meta_ds_ele_cnt returns count of elements in ds */
static inline ulong
fd_quic_pkt_meta_ds_ele_cnt( fd_quic_pkt_meta_ds_t * ds ) {
  return fd_quic_pkt_meta_treap_ele_cnt( ds );
}

/* end aliasing to abstract data structure */

struct fd_quic_pkt_meta_tracker {
  fd_quic_pkt_meta_ds_t       sent_pkt_metas[4];
  fd_quic_pkt_meta_t        * pool;
};
typedef struct fd_quic_pkt_meta_tracker fd_quic_pkt_meta_tracker_t;

/* fd_quic_pkt_meta_ds_init_pool does any data structure-particular setup
   on the entire pool at once. Useful for e.g. treap randomness
   @arguments:
   - pool: pointer pkt_meta pool
   - total_meta_cnt: total pool size */
void
fd_quic_pkt_meta_ds_init_pool( fd_quic_pkt_meta_t * pool,
                               ulong                total_meta_cnt );

/* fd_quic_pkt_meta_tracker_init initializes the metadata tracker for each enc level
  @arguments:
  - tracker: pointer to the tracker
  - total_meta_cnt: total number of max pkt_meta entries in this tracker
    (shared across all encoding levels)
  - pool: pointer to the backing pool
  @returns:
  - pointer to tracker if successful, NULL otherwise */
void *
fd_quic_pkt_meta_tracker_init( fd_quic_pkt_meta_tracker_t * tracker,
                               ulong                        total_meta_cnt,
                               fd_quic_pkt_meta_t         * pool );

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
  - pkt_number_hi: upper bound of the range
  @returns:
  - number of pkt_meta removed */
ulong
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

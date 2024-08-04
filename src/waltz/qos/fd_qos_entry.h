#ifndef HEADER_fd_src_waltz_qos_fd_qos_entry_h
#define HEADER_fd_src_waltz_qos_fd_qos_entry_h

#include "fd_qos_base.h"

/* state transitions
     IDLE        -> ASSIGNED      : QOS
     ASSIGNED    -> QUEUED        : TILE
     QUEUED      -> PROCESSING    : QOS
     PROCESSING  -> ASSIGNED      : QOS
     ASSIGNED    -> UNASSIGNED    : QOS
     UNASSIGNED  -> IDLE          : TILE (tile has to remove from local hash map) */

#define FD_QOS_STATE_IDLE        0
#define FD_QOS_STATE_ASSIGNED    1
#define FD_QOS_STATE_QUEUED      2
#define FD_QOS_STATE_PROCESSING  3
#define FD_QOS_STATE_UNASSIGNED  4

typedef struct fd_qos_entry    fd_qos_entry_t;
typedef struct fd_qos_stats    fd_qos_stats_t;
typedef struct fd_qos_priority fd_qos_priority_t;

struct fd_qos_priority {
  uchar txn_fail_over;             /* bool: transaction failure ratio over threshold */
  uchar sgn_fail_over;             /* bool: signature failuer ratio over threshold */
  float profit;                    /* total profit */
};

struct fd_qos_stats {
  float        profit;      /* simple total */
  /* EMAs */
  float        txn_success;     /* EMA over transaction success count */
  float        txn_fail;        /* EMA over transaction failure count */
  float        sgn_success;     /* EMA over signature success count */
  float        sgn_fail;        /* EMA over signature failure count */
};

struct fd_qos_entry {
  fd_qos_key_t key;

  /* field required for fd_map_dynamic */
  uint         hash;

  struct {
    uint           state;
    fd_qos_stats_t stats;
    ulong          last_update;     /* last_update time is needed for EMA decay */
    ulong          next_queue_time; /* time client should queue the entry */
    ulong          blacklist_until; /* if blacklisted, this will be set to the resume time */
    ulong          conn_cnt;        /* number of connections from this key */

    /* for enqueuing on the qos processing queue */
    /* next is relative to this "next" element address */
    /* fd_qos_entry_t objects from different allocations will work well */
    /* together so long as they are in the same workspace, regardless of */
    /* virtual address */
    ulong          rel_next;
  } value;

};

FD_PROTOTYPES_BEGIN

/* atomic add for updating members of fd_qos_entry_t
 *
 * This is used for the following reasons:
 *   Locking may result in deadlock, if the a thread dies while locked
 *   The update is unlikely to be delayed
 *   It reduces synchronization cost compared to most other methods */
void
fd_qos_atomic_add( float * member, float delta );

/* atomic multiply-add for updating members of fd_qos_entry_t
 *
 * This is used for the following reasons:
 *   Locking may result in deadlock, if the a thread dies while locked
 *   The update is unlikely to be delayed
 *   It reduces synchronization cost compared to most other methods */
void
fd_qos_atomic_mul_add( float * member, float scale, float addend );

/* atomically swaps the value at *value with replacement
 * and returns the value previosly there */
float
fd_qos_atomic_swap( float * value, float replacement );

/* atomic transfer
 *
 * takes two pointers:
 *   accum
 *   delta
 *
 * it atomically swaps *delta with zero
 * it then atomically adds the old value of *delta to *accum
 */
void
fd_qos_atomic_xfer( float * accum, float * delta );


/* apply deltas to an ema entry */
void
fd_qos_delta_apply( fd_qos_entry_t * entry,
                    fd_qos_entry_t * delta,
                    float            decay );

/* set values to zero */
void
fd_qos_entry_clear( fd_qos_entry_t * entry );

/* update a local ema - not atomic */
void
fd_qos_delta_update( float * ema,
                     float   decay,
                     float   delta,
                     long    decay_time );

/* these are for making next points relative to the address of the */
/* pointer itself */
/* this makes accesses work regardless of the current virtual address */
/* mapping */
#if 1
#  define FD_QOS_ENTRY_NEXT_SET( next, new_ptr ) (                  (ulong)(new_ptr) - (ulong)&(next) )
#  define FD_QOS_ENTRY_NEXT_GET( next )          ((fd_qos_entry_t*)((ulong)(next)    + (ulong)&(next)))
#else
/* TODO testing */
#  define FD_QOS_ENTRY_NEXT_SET( next, new_ptr )                   ((ulong)(new_ptr) - (ulong)0)
#  define FD_QOS_ENTRY_NEXT_GET( next )          ((fd_qos_entry_t*)((ulong)(next)    + (ulong)0))
#endif

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_qos_fd_qos_entry_h */

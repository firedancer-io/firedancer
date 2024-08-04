#ifndef HEADER_fd_src_waltz_qos_fd_qos
#define HEADER_fd_src_waltz_qos_fd_qos

#include "fd_qos_base.h"
#include "fd_qos_entry.h"
#include "fd_qos_map.h"
#include "fd_qos_local.h"

#include <math.h>

/* FD_QOS_EMA_HALFLIFE_MINUTES */
/* duration used as a halflife for QoS EMA based statistics */
#define FD_QOS_EMA_HALFLIFE_MINUTES 30.0f

/* Threshold of failed transaction ratio before an IP is considered */
/* over */
#define FD_QOS_TXN_RATIO_THRESH 0.5f

/* Threshold is ignored if total transactions is below this value */
/* total is an EMA over FD_QOS_EMA_HALFLIFE_MINUTES */
#define FD_QOS_TXN_MIN_TOTAL    30.0f

/* Threshold of failed signatures ratio before an IP is considered */
/* over */
#define FD_QOS_SGN_RATIO_THRESH 0.1f

/* Threshold is ignored if total signatures is below this value */
/* total is an EMA over FD_QOS_EMA_HALFLIFE_MINUTES */
#define FD_QOS_SGN_MIN_TOTAL    30.0f

#define FD_QOS_ALIGN      64
#define FD_QOS_MAGIC      0x5cb80aefa7a803cbul

/* max number of elements allowed in qos queue */
/* this limits the amount of time spent in process */
#define FD_QOS_MAX_QUEUED 64UL

/* Max nuimber of connections per IP address */
/* TODO put into config file */
#define FD_QOS_MAX_CONN_CNT 32UL

/* ema decay
 * used in alpha = exp( ema_decay * time_in_ns ) to determine
 * the value used in the ema calc "alpha * old_value + delta" */
#define FD_QOS_EMA_DECAY ( logf( 0.5f ) / ( FD_QOS_EMA_HALFLIFE_MINUTES * 60.0f * 1e9f ) )

/* period between qos tile updates to global map in nanoseconds */
#define FD_QOS_UPDATE_PERIOD ((ulong)( 2. * 60. * 1e9 ))

/* fd_qos
 *
 * Implements quality of service initially for QUIC
 *
 * Allows the validator to track health metrics, such as:
 *    txn failed
 *    sign failed
 *    profit
 *
 * These are collated by ip address
 *
 * Then component(s) such as QUIC can query the values to determine
 * priority among clients
 *
 * Each tile that updates the table has a local cache of data
 * The global table is updated periodically from the local cache */

typedef struct fd_qos fd_qos_t;

FD_PROTOTYPES_BEGIN

/* fd_qos_{align,footprint} return the required alignment and footprint
 * for the memory region in order to create a new fd_qos */

FD_FN_CONST ulong
fd_qos_align( void );

FD_FN_CONST ulong
fd_qos_footprint( ulong entry_cnt );

/* fd_new_qos creates a new fd_qos with the capacity for the given number
 * of entries and tiles. Period is the amount of time in nanoseconds between
 * updates to the global map.
 * A local cache of data is maintained by the producing tiles to keep
 * the work cheap and fast
 * Periodically the local cache is used to update the global map */
void *
fd_qos_new( void * mem, ulong entry_cnt );


fd_qos_t *
fd_qos_join( void * mem );

void *
fd_qos_leave( fd_qos_t * qos );

void *
fd_qos_delete( void * mem );

void
fd_qos_set_rng_seed( fd_qos_t * qos, uint seq, ulong idx );

/* inserts key into map, initialized value to all zeros */
fd_qos_entry_t *
fd_qos_insert( fd_qos_map_t * map, fd_qos_key_t key );

/* find an entry by key */
fd_qos_entry_t *
fd_qos_query( fd_qos_map_t * map, fd_qos_key_t key );

/* find an entry by key in global map, if none create one and if none */
/* available, evict one, and complete the process */
/* there should be at least as many entries as allowed connections */
fd_qos_entry_t *
fd_qos_query_forced( fd_qos_t * qos, fd_qos_key_t key );

/* removes entry from map
 *
 * entry must be return value of fd_qos_query */
void
fd_qos_remove( fd_qos_map_t * map, fd_qos_entry_t * entry );

/* removes entry from map by key */
void
fd_qos_remove_key( fd_qos_map_t * map, fd_qos_key_t key );

/* obtain global map in local address spacce */
fd_qos_map_t *
fd_qos_global_get_map( fd_qos_t * qos );

/* add delta to linked list of deltas to apply */
void
fd_qos_enqueue_delta( fd_qos_t * qos, fd_qos_entry_t * delta );

/* process deltas in linked list, updating global map with each */
void
fd_qos_process_deltas( fd_qos_t * qos );

/* set priority based on QoS stats */
void
fd_qos_set_priority( fd_qos_priority_t * prio, fd_qos_stats_t * stats );

/* update connection count */
void
fd_qos_update_conn_cnt( fd_qos_t * qos, fd_qos_entry_t * entry, ulong new_conn_cnt );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_qos_fd_qos */

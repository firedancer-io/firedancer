#ifndef HEADER_fd_src_waltz_qos_fd_qos_local
#define HEADER_fd_src_waltz_qos_fd_qos_local

#include "fd_qos_base.h"
#include "fd_qos_entry.h"
#include "fd_qos_map.h"

#define FD_QOS_LOCAL_MAGIC 0xccacf2d4aa73367fUL

#ifndef FD_DEBUG
#  define FD_DEBUG(...)
#endif

/* fwd declare */
typedef struct fd_qos fd_qos_t;


/* stats types */

/* invalid type */
#define FD_QOS_TYPE_NULL        0

/* total PROFIT */
#define FD_QOS_TYPE_PROFIT      1

/* recent transaction success */
#define FD_QOS_TYPE_TXN_SUCCESS 2

/* recent transaction failure */
#define FD_QOS_TYPE_TXN_FAIL    3

/* recent signature success */
#define FD_QOS_TYPE_SGN_SUCCESS 4

/* recent signature failure */
#define FD_QOS_TYPE_SGN_FAIL    5

/* end of types range - keep last such that all valid types */
/* are in ( FD_QOS_TYPE_NULL, FD_QOS_TYPE_LAST ) */
#define FD_QOS_TYPE_LAST        6

/* fd_qos_local is used by tiles to maintain local copies of qos
 * deltas
 * These deltas periodically get transferred to the global map */
typedef struct fd_qos_local fd_qos_local_t;

FD_PROTOTYPES_BEGIN
/* fd_qos_local_{align,footprint} return the required alignment and footprint
 * for the memory region in order to create a new fd_qos */

FD_FN_CONST ulong
fd_qos_local_align( void );

FD_FN_CONST ulong
fd_qos_local_footprint( ulong entry_cnt );

/* fd_qos_local_new creates a new fd_qos_local with the capacity for the given number
 * of entries and tiles.
 * This represents a local cache ofqos data that is periodically forwarded to the
 * global qos for processing */
void *
fd_qos_local_new( void * mem, ulong entry_cnt );


fd_qos_local_t *
fd_qos_local_join( void * mem );

void *
fd_qos_local_leave( fd_qos_local_t * qos );

void *
fd_qos_local_delete( void * mem );

/* get map for the local tile */
fd_qos_map_t *
fd_qos_local_get_map( fd_qos_local_t * qos_local );

/* find an entry in the local map, or create one if necessary */
fd_qos_entry_t *
fd_qos_local_query_forced( fd_qos_local_t * qos_local, fd_qos_key_t key );

/* update qos value for ip address */
/* adjusts the qos value specified in the "type" parameter by the value */
/* in the "delta" parameter */
void
fd_qos_local_update( fd_qos_local_t * qos_local,
                     fd_qos_t *       qos,
                     long             now,
                     int              type,
                     fd_qos_key_t     key,
                     float            delta );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_qos_fd_qos_local */

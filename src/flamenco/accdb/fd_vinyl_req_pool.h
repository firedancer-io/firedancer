#ifndef HEADER_fd_src_flamenco_accdb_fd_vinyl_req_pool_h
#define HEADER_fd_src_flamenco_accdb_fd_vinyl_req_pool_h

/* fd_vinyl_req_pool.h provides a simple allocation policy for vinyl
   request metadata, and a shared memory persistent object class for
   convenience.

   This exists because metadata is not stored in-line with the shared
   memory request queue.  Instead, the request queue holds pointers to
   request batches stored in another shared memory workspace.

   ┌───────────────┐    ┌────────────────┐    ┌───────────────┐
   │ vinyl_rq      │    │ vinyl_req_pool │    │ vinyl_data    │
   ├───────────────┤    ├────────────────┤    │               │
   │               │    │                │ ┌──┼►┌───────────┐ │
   │ request batch │    │                │ │  │ │  account  │ │
   │               │    │                │ │  │ │   data    │ │
   │ request batch ┼─┬──┼► key 0         │ │  │ │           │ │
   │      ...      │ │  │  key 1         │ │  │ │           │ │
   └───────────────┘ │  │  key ...       │ │  │ └───────────┘ │
                     │  │                │ │  │               │
                     └──┼► val_gaddr 0 ──┼─┘  │               │
                        │  val_gaddr 1 ──┼─┐  │               │
                        │  val_gaddr ... │ └──┼►┌───────────┐ │
                        │                │    │ │  account  │ │
                        │                │    │ │   data    │ │
                        │                │    │ └───────────┘ │
                        └────────────────┘    └───────────────┘

   The above figure illustrates the relationship between vinyl_rq and
   record data values.  Note that the vinyl tile need not be aware of
   the vinyl_req_pool allocator. */

#include "../../vinyl/rq/fd_vinyl_rq.h"
#include "../../vinyl/cq/fd_vinyl_cq.h"

/* fd_vinyl_req_pool_t stores request metadata batches.

   It is sized by two parameters: batch_max, the max number of request
   batches.  And batch_key_max, the max number of keys in each request
   batch.

   Should not be declared locally (construct via fd_vinyl_req_pool_new).

   The req_pool itself is not safe to share across threads.  However,
   the _gaddr() values returned are safe to share. */

struct fd_vinyl_req_pool {
  ulong magic;
  ulong batch_key_max;
  ulong batch_max;
  ulong free_off;
  ulong free_cnt;
  ulong used_off;

  ulong key_off;
  ulong val_gaddr_off;
  ulong err_off;
  ulong comp_off;

  /* ... variable size data follows ...*/
};

typedef struct fd_vinyl_req_pool fd_vinyl_req_pool_t;

#define FD_VINYL_REQ_POOL_MAGIC (0x7ecb0aa4a4730117UL)  /* magic */
#define FD_VINYL_REQ_POOL_ALIGN (128UL)  /* double cache line */

FD_PROTOTYPES_BEGIN

/* fd_vinyl_req_pool_{align,footprint} describe a memory region suitable
   to hold a vinyl_req_pool object.  If any footprint params are
   invalid, footprint silently returns 0UL.
   Footprint scales like O(batch_max*batch_key_max). */

ulong
fd_vinyl_req_pool_align( void );

ulong
fd_vinyl_req_pool_footprint( ulong batch_max,
                             ulong batch_key_max );

/* fd_vinyl_req_pool_new formats the memory region as a vinyl_req_pool
   object.  shmem is assumed to be in a wksp.  Returns the newly created
   object on success.  On failure logs warning and returns NULL.

   Reasons for failure are: NULL shmem, misaligned shmem, invalid
   params, shmem not in a wksp. */

void *
fd_vinyl_req_pool_new( void * shmem,
                       ulong  batch_max,
                       ulong  batch_key_max );

/* fd_vinyl_req_pool_join joins the caller to a vinyl_req_pool object in
   shared memory.  Only one join should be active at a time. */

fd_vinyl_req_pool_t *
fd_vinyl_req_pool_join( void * shmem );

/* fd_vinyl_req_pool_leave detaches the caller from a vinyl_req_pool
   object.  (Currently a no-op, provided for readability) */

void *
fd_vinyl_req_pool_leave( fd_vinyl_req_pool_t * pool );

/* fd_vinyl_req_pool_delete destroys a vinyl_req_pool object and returns
   the backing memory region back to the caller.  On failure logs
   warning and returns NULL. */

void *
fd_vinyl_req_pool_delete( void * shmem );

/* fd_vinyl_req_{batch_max,batch_req_max} return parameters of an
   existing object. */

static inline ulong
fd_vinyl_req_batch_max( fd_vinyl_req_pool_t * pool ) {
  return pool->batch_max;
}

static inline ulong
fd_vinyl_req_batch_key_max( fd_vinyl_req_pool_t * pool ) {
  return pool->batch_key_max;
}

/* fd_vinyl_req_pool_free_batch_cnt returns the number of free batches. */

static inline ulong
fd_vinyl_req_pool_free_batch_cnt( fd_vinyl_req_pool_t * pool ) {
  return pool->free_cnt;
}

/* fd_vinyl_req_pool_acquire opens a new request batch.  Returns the
   index of the newly required batch.  Panics with FD_LOG_CRIT if no
   batches are free. */

ulong
fd_vinyl_req_pool_acquire( fd_vinyl_req_pool_t * pool );

/* fd_vinyl_req_pool_release frees a request batch.  Panics with
   FD_LOG_CRIT if this is an invalid free. */

void
fd_vinyl_req_pool_release( fd_vinyl_req_pool_t * pool,
                           ulong                 batch_idx );

/* fd_vinyl_req_batch_key returns a pointer to the array of keys for a
   request batch. */

static inline fd_vinyl_key_t *
fd_vinyl_req_batch_key( fd_vinyl_req_pool_t * pool,
                        ulong                 batch_idx ) {
  fd_vinyl_key_t * key0 = (fd_vinyl_key_t *)( (ulong)pool + pool->key_off );
  return key0 + (batch_idx * pool->batch_key_max);
}

/* fd_vinyl_req_batch_key_gaddr returns the 'key_gaddr' paramter for a
   request batch. */

static inline ulong
fd_vinyl_req_batch_key_gaddr( fd_vinyl_req_pool_t * pool,
                              fd_wksp_t *           wksp,
                              ulong                 batch_idx ) {
  return fd_wksp_gaddr_fast( wksp, fd_vinyl_req_batch_key( pool, batch_idx ) );
}

/* fd_vinyl_req_batch_val_gaddr returns a pointer to the array of
   val_gaddr values for a request batch. */

static inline ulong *
fd_vinyl_req_batch_val_gaddr( fd_vinyl_req_pool_t * pool,
                              ulong                 batch_idx ) {
  ulong * val_gaddr0 = (ulong *)( (ulong)pool + pool->val_gaddr_off );
  return val_gaddr0 + (batch_idx * pool->batch_key_max);
}

/* fd_vinyl_req_batch_val_gaddr_gaddr returns the 'val_gaddr_gaddr'
   parameter for a request batch. */

static inline ulong
fd_vinyl_req_batch_val_gaddr_gaddr( fd_vinyl_req_pool_t * pool,
                                    fd_wksp_t *           wksp,
                                    ulong                 batch_idx ) {
  return fd_wksp_gaddr_fast( wksp, fd_vinyl_req_batch_val_gaddr( pool, batch_idx ) );
}

/* fd_vinyl_req_batch_err returns a pointer to the error codes for a
   request batch. */

static inline schar *
fd_vinyl_req_batch_err( fd_vinyl_req_pool_t * pool,
                        ulong                 batch_idx ) {
  schar * err0 = (schar *)( (ulong)pool + pool->err_off );
  return err0 + (batch_idx * pool->batch_key_max);
}

/* fd_vinyl_req_batch_err_gaddr returns the 'err_gaddr' parameter for a
   request batch. */

static inline ulong
fd_vinyl_req_batch_err_gaddr( fd_vinyl_req_pool_t * pool,
                              fd_wksp_t *           wksp,
                              ulong                 batch_idx ) {
  return fd_wksp_gaddr_fast( wksp, fd_vinyl_req_batch_err( pool, batch_idx ) );
}

/* fd_vinyl_req_batch_comp returns a pointer to the array of completion
   objects for a request batch. */

static inline fd_vinyl_comp_t *
fd_vinyl_req_batch_comp( fd_vinyl_req_pool_t * pool,
                         ulong                 batch_idx ) {
  fd_vinyl_comp_t * comp0 = (fd_vinyl_comp_t *)( (ulong)pool + pool->comp_off );
  return comp0 + (batch_idx * pool->batch_key_max);
}

/* fd_vinyl_req_batch_comp_gaddr returns the 'comp_gaddr' parameter for
   a request batch. */

static inline ulong
fd_vinyl_req_batch_comp_gaddr( fd_vinyl_req_pool_t * pool,
                               fd_wksp_t *           wksp,
                               ulong                 batch_idx ) {
  return fd_wksp_gaddr_fast( wksp, fd_vinyl_req_batch_comp( pool, batch_idx ) );
}

/* fd_vinyl_rq_send_batch is syntax sugar for fd_vinyl_rq_send with a
   req_pool-provided request batch. */

static inline void
fd_vinyl_req_send_batch( fd_vinyl_rq_t *       rq,
                         fd_vinyl_req_pool_t * req_pool,
                         fd_wksp_t *           req_pool_wksp,
                         ulong                 req_id,
                         ulong                 link_id,
                         int                   type,
                         ulong                 flags,
                         ulong                 batch_idx,
                         ulong                 batch_cnt,
                         ulong                 val_max ) {
  ulong key_gaddr        = fd_vinyl_req_batch_key_gaddr      ( req_pool, req_pool_wksp, batch_idx );
  ulong val_gaddr_gaddr  = fd_vinyl_req_batch_val_gaddr_gaddr( req_pool, req_pool_wksp, batch_idx );
  ulong err_gaddr        = fd_vinyl_req_batch_err_gaddr      ( req_pool, req_pool_wksp, batch_idx );
  ulong comp_gaddr       = fd_vinyl_req_batch_comp_gaddr     ( req_pool, req_pool_wksp, batch_idx );
  fd_vinyl_rq_send( rq, req_id, link_id, type, flags, batch_cnt, val_max, key_gaddr, val_gaddr_gaddr, err_gaddr, comp_gaddr );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_vinyl_req_pool_h */

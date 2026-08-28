#ifndef HEADER_fd_src_discof_replay_fd_rdisp_mq_h
#define HEADER_fd_src_discof_replay_fd_rdisp_mq_h

/* The multiprq (mq) is a strange combination of data structures
   specifically for use in fd_rdisp.  It's factored out into its own
   file to abstract the details away and to facilitate testing.  It
   supports 4 priority queues (corresponding to the 4 staging lanes),
   with each prq also having an optimization for top priority (prio=0)
   items.  For each element (acct_idx, staging_lane_idx) it supports the
   following operations:
      * Is the element in the structure?
      * Insert the element with a specific priority
      * Adjust the element's priority
   Additionally, for a staging_lane_idx, it supports:
      * Return the element with the best priority (lowest value) and
        remove it from the structure.
      * Count the number of elements in the structure with the specified
        lane index.

   For each element, we require acct_idx in [1, acct_depth] and
   staging_lane_idx in [0, 4).  Additionally, at most writers_per_block
   elements can be in the structure for each staging_lane_idx at a time.
   prio>=0 with 0 being the highest priority item. */

struct fd_rdisp_mq_private;
typedef struct fd_rdisp_mq_private fd_rdisp_mq_t;

/* fd_rdisp_mq_{align,footprint} return the required alignment and
   footprint in bytes of a region of memory to be formatted to be used
   as a multiprq.  acct_depth is the maximum acct_idx (inclusive) that
   can be used for an element, and max_writers_per_block elements can be
   tracked in each staging lane.  acct_depth in range [1, UINT_MAX] and
   max_writers_per_block in range [1, UINT_MAX].  If
   max_writers_per_block > acct_depth, the effective value used will be
   acct_depth instead. */
ulong fd_rdisp_mq_align( void ) { return 8UL; }
ulong fd_rdisp_mq_footprint( ulong acct_depth, ulong max_writers_per_block );

/* fd_rdisp_mq_new formats a region of memory with the required
   footprint and depth for use as a multiprq.  acct_depth and
   max_writers_per_block are as in footprint.  The caller will not be
   joined upon return.

   fd_rdisp_mq_join joins the caller to the multique, making it ready
   for use. */
void *
fd_rdisp_mq_new( void * mem,
                 ulong acct_depth,
                 ulong max_writers_per_block );

fd_rdisp_mq_t * fd_rdisp_mq_join( void * mem );

/* fd_rdisp_mq_query returns 1 if the element (acct_idx, staging_lane)
   is in mq, and 0 otherwise.  acct_idx and staging_lane must be in the
   requisite range and mq must be a valid local join.  An element is in
   the multiprq if it has been inserted one more time than it has been
   popped. */
int
fd_rdisp_mq_query( fd_rdisp_mq_t const * mq,
                   ulong                 acct_idx,
                   ulong                 staging_lane );

/* fd_rdisp_mq_insert inserts the element (acct_idx, staging_lane) into
   the multiprq with priority prio.  The element must not be in the
   multiprq prior to this call.  prio>=0, with lower values getting
   popped first. */
void
fd_rdisp_mq_insert( fd_rdisp_mq_t * mq,
                    ulong           acct_idx,
                    ulong           staging_lane,
                    float           prio );

/* fd_rdisp_mq_adjust changes the priority of the specified element
   (acct_idx, staging_lane) to prio.  The element must be in the
   multiprq prior to this call and remains so after the call.  prio>=0.
   This is especially optimized for the prio==0 case. */
void
fd_rdisp_mq_adjust( fd_rdisp_mq_t * mq,
                    ulong           acct_idx,
                    ulong           staging_lane,
                    float           prio );

/* fd_rdisp_mq_pop returns and removes the best priority element with
   the specified staging lane.  The caller promises that there is at
   least one element in the multiprq with the specified staging lane. */
ulong
fd_rdisp_mq_pop( fd_rdisp_mq_t * mq,
                 ulong           staging_lane );

/* fd_rdisp_mq_cnt returns the number of elements in the multiprq with
   specified staging lane. */
ulong
fd_rdisp_mq_cnt( fd_rdisp_mq_t * mq,
                 ulong           staging_lane );

void *
fd_rdisp_mq_leave( fd_rdisp_mq_t * mq );

void *
fd_rdisp_mq_delete( void * mem );

/* Implementation details below.  These would be in a .c file, but they
   are mostly pretty quick functions, such that inlining is probably
   a significant performance win.

   Probably the most straightforward implementation would be some kind
   of pool-based heap, with a map.  However, the current pool-based heap
   does not allow deleting or changing priorities because it does not
   contain a parent pointer.  Rather than that, we use fd_prq with an
   inverse index that gets updated as elements get moved.  This leads to
   some strange macros, but they can be isolated to this file and
   tested. */


struct fd_rdisp_mq_4u {
  uint per_lane[4];
};
typedef struct fd_rdisp_mq_4u fd_rdisp_mq_4u_t;

struct fd_rdisp_mq_prqe {
  uint  idx;
  float prio;
};
typedef struct fd_rdisp_mq_prqe fd_rdisp_mq_prqe_t;


/* In this macro, heap (which is defined each place the macro expands)
   is a pointer to the field with offset 16B from private_t.  The field
   before the private_t struct is a pointer to the start of the 4u_t
   array, with 4B*staging lane added. */
#define PRQ_TMP_ST(p, t) do {                                                                 \
    (p)[0] = (t);                                                                             \
    ((fd_rdisp_mq_4u_t *)((void * const *)heap)[-3])[(t).idx].per_lane[0] = (uint)((p)-heap); \
  } while(0)
#define PRQ_NAME      fd_rdisp_mprq
#define PRQ_T         fd_rdisp_mq_prqe_t
#define PRQ_TIMEOUT_T float
#define PRQ_TIMEOUT   prio
#include "../../../util/tmpl/fd_prq.c"
/* As an optimization, we store the prio0 elements at the end of the
   heap instead of in the heap.  prq allocates 2 dummy elements at the
   end that are read but not written to, so we'll store the prio0
   elements there.

   Elements [0, prq_cnt) are handled by the prq
   Elements (max_writers_per_block-prio0_cnt, max_writers_per_block]
   are in the prio0 list.

   There's always one element in between the lists, since
   max_writers_per_block-prio0_cnt-prq_cnt >=0. */

FD_STATIC_ASSERT( sizeof(fd_rdisp_mprq_private_t )==2*sizeof(ulong)+sizeof(fd_rdisp_mq_prqe_t), "prq details" );
FD_STATIC_ASSERT( alignof(fd_rdisp_mprq_private_t)==8UL,                                        "prq details" );

struct fd_rdisp_mq_private {
  ulong acct_depth;
  ulong max_writers_per_block;
  ulong prio0_cnt[4];

  fd_rdisp_mq_4u_t *   flat; /* indexed [0, acct_depth+1) */
  fd_rdisp_mq_prqe_t * prq[4];
  /* Then follows:
     the footprint for flat
     for i in [0, 4)
        a pointer to flat[0].per_lane[i]
        the footprint for prq[i]
   */
};
typedef struct fd_rdisp_mq_private fd_rdisp_mq_t;

ulong
fd_rdisp_mq_footprint( ulong acct_depth,
                       ulong max_writers_per_block ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_rdisp_mq_t),                     sizeof(fd_rdisp_mq_t)            );
  l = FD_LAYOUT_APPEND( l, alignof(fd_rdisp_mq_4u_t), (acct_depth+1UL)*sizeof(fd_rdisp_mq_4u_t)         );
  l = FD_LAYOUT_APPEND( l, 8UL, 4UL*(sizeof(void *)+fd_rdisp_mprq_footprint( max_writers_per_block )) );
  return FD_LAYOUT_FINI( l, fd_rdisp_mq_align() );
}

void *
fd_rdisp_mq_new( void * mem,
                 ulong acct_depth,
                 ulong max_writers_per_block ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_rdisp_mq_t *    mq = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rdisp_mq_t),    sizeof(fd_rdisp_mq_t)                     );
  fd_rdisp_mq_4u_t * u4 = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rdisp_mq_4u_t), (acct_depth+1UL)*sizeof(fd_rdisp_mq_4u_t) );

  mq->acct_depth = acct_depth;
  mq->max_writers_per_block = max_writers_per_block;
  memset( mq->prio0_cnt, '\0', 4UL*sizeof(ulong) );

  memset( u4, '\0', (acct_depth+1UL)*sizeof(fd_rdisp_mq_4u_t) );

  for( ulong i=0UL; i<4UL; i++ ) {
    void * _pq = FD_SCRATCH_ALLOC_APPEND( l, 8UL, sizeof(void *)+fd_rdisp_mprq_footprint( max_writers_per_block ) );
    fd_rdisp_mprq_new( (void *)(8UL + (ulong)_pq), max_writers_per_block );
  }
  return mem;
}

fd_rdisp_mq_t *
fd_rdisp_mq_join( void * mem ) {
  fd_rdisp_mq_t * mq                    = (fd_rdisp_mq_t *)mem;
  ulong           acct_depth            = mq->acct_depth;
  ulong           max_writers_per_block = mq->max_writers_per_block;

  FD_SCRATCH_ALLOC_INIT( l, mem );
  /*                   */ FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rdisp_mq_t),    sizeof(fd_rdisp_mq_t)                     );
  fd_rdisp_mq_4u_t * u4 = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rdisp_mq_4u_t), (acct_depth+1UL)*sizeof(fd_rdisp_mq_4u_t) );

  mq->flat = u4;
  for( ulong i=0UL; i<4UL; i++ ) {
    void * _pq = FD_SCRATCH_ALLOC_APPEND( l, 8UL, sizeof(void *)+fd_rdisp_mprq_footprint( max_writers_per_block ) );
    *((uint **)_pq) = u4->per_lane+i;
    mq->prq[i] = fd_rdisp_mprq_join( (void *)(sizeof(void *) + (ulong)_pq) );
  }
  return mq;
}

int
fd_rdisp_mq_query( fd_rdisp_mq_t const * mq,
                   ulong                 acct_idx,
                   ulong                 staging_lane ) {
  return mq->flat[acct_idx].per_lane[staging_lane]==0;
}

void
fd_rdisp_mq_insert( fd_rdisp_mq_t * mq,
                    ulong           acct_idx,
                    ulong           staging_lane,
                    float           prio ) {
  fd_rdisp_mq_prqe_t temp[1] = {{
    .idx  = (uint)acct_idx,
    .prio = prio,
  }};
  if( FD_UNLIKELY( prio==0.0f ) ) {
    ulong fidx = mq->max_writers_per_block - (mq->prio0_cnt[staging_lane]++);
    mq->prq[staging_lane][fidx] = *temp;
    mq->flat[acct_idx].per_lane[staging_lane] = (uint)fidx;
  } else {
    fd_rdisp_mprq_insert( mq->prq[staging_lane], temp );
    /* flat is auto-populated by _insert */
  }
}

void
fd_rdisp_mq_adjust( fd_rdisp_mq_t * mq,
                    ulong           acct_idx,
                    ulong           staging_lane,
                    float           prio ) {
  ulong M      = mq->max_writers_per_block;
  ulong p0_cnt = mq->prio0_cnt[staging_lane];

  fd_rdisp_mq_prqe_t * prq = mq->prq[staging_lane];

  uint fidx                = mq->flat[acct_idx].per_lane[staging_lane];
  int  pre_prio0           = fidx>fd_rdisp_mprq_cnt( prq );
  int  new_prio0           = prio==0.0f;

  if( FD_UNLIKELY( pre_prio0 & new_prio0 ) ) return; /* nothing to do */
  fd_rdisp_mq_prqe_t temp = prq[fidx];

  if( pre_prio0 ) {
    /* move tail to hole (they could be the same) */
    prq[fidx] = prq[M - (--p0_cnt)];
    mq->flat[prq[fidx].idx].per_lane[staging_lane] = fidx;
  } else {
    fd_rdisp_mprq_remove( prq, fidx );
  }

  if( new_prio0 ) {
    ulong new_idx = M-(p0_cnt++);
    prq[new_idx] = temp;
    mq->flat[acct_idx].per_lane[staging_lane] = (uint)new_idx;
  } else {
    fd_rdisp_mprq_insert( prq, &temp );
  }

  mq->prio0_cnt[staging_lane] = p0_cnt;
}

ulong
fd_rdisp_mq_pop( fd_rdisp_mq_t * mq,
                 ulong           staging_lane ) {
  fd_rdisp_mq_prqe_t * prq = mq->prq[staging_lane];

  if( FD_LIKELY( mq->prio0_cnt[ staging_lane ] ) ) {
    ulong tail_idx  = mq->max_writers_per_block - (--mq->prio0_cnt[staging_lane]);
    ulong to_return = prq[tail_idx].idx;
    mq->flat[to_return].per_lane[staging_lane] = 0;
    return to_return;
  } else {
    ulong to_return = prq->idx;
    fd_rdisp_mprq_remove_min( prq );
    return to_return;
  }
}

ulong
fd_rdisp_mq_cnt( fd_rdisp_mq_t * mq,
                 ulong           staging_lane ) {
  return fd_rdisp_mprq_cnt( mq->prq[staging_lane] ) + mq->prio0_cnt[staging_lane];
}

void * fd_rdisp_mq_leave ( fd_rdisp_mq_t * mq ) { return (void *)mq;  }
void * fd_rdisp_mq_delete( void * mem )         { return (void *)mem; }

#endif /* HEADER_fd_src_discof_replay_fd_rdisp_mq_h */

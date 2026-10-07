#include "fd_sched_lthash.h"
#include "../../util/fd_hash32.h"

#define MAP_NAME          lthash_map
#define MAP_ELE_T         fd_sched_lthash_entry_t
#define MAP_KEY_T         fd_acct_addr_t
#define MAP_KEY           acct
#define MAP_NEXT          map_next
#define MAP_IDX_T         uint
#define MAP_KEY_HASH(k,s) fd_hash32( (k)->b, (s) )
#define MAP_KEY_EQ(k0,k1) (!memcmp( (k0)->b, (k1)->b, 32UL ))
#define MAP_COUNT         1
#include "../../util/tmpl/fd_map_chain.c"

struct fd_sched_lthash_lane {
  fd_sched_lthash_entry_t * entry_pool; /* entry_max entries */
  lthash_map_t *            map;        /* keyed by acct over entry_pool */
  uint                      free_head;  /* free list through q_next, UINT_MAX when empty */
  ulong                     bank_idx;   /* claimed bank, ULONG_MAX when idle */
};
typedef struct fd_sched_lthash_lane fd_sched_lthash_lane_t;

struct fd_sched_lthash {
  ulong                  entry_max;
  ulong                  hash_max;
  ulong                  hash_free_cnt; /* hash_free[ hash_free_cnt-1 ] is the top */
  fd_lthash_value_t *    hash_pool;     /* hash_max slots */
  uint *                 hash_free;     /* stack of free slot indices */
  fd_sched_lthash_lane_t lane[ FD_SCHED_LTHASH_LANE_CNT ];
};

/* The hash pool needs FD_LTHASH_ALIGN; 128 is the usual top-level
   object alignment. */
#define SCHED_LTHASH_ALIGN (128UL)
FD_STATIC_ASSERT( alignof(fd_lthash_value_t)<=SCHED_LTHASH_ALIGN, lthash_align );

/* lthash_chain_cnt is the chain count of a lane map, sized for
   2*entry_max entries to keep chains short. */
static inline ulong
lthash_chain_cnt( ulong entry_max ) {
  return lthash_map_chain_cnt_est( 2UL*entry_max );
}

ulong
fd_sched_lthash_align( void ) {
  return SCHED_LTHASH_ALIGN;
}

ulong
fd_sched_lthash_footprint( ulong entry_max,
                           ulong hash_max ) {
  if( FD_UNLIKELY( !entry_max || entry_max>UINT_MAX || hash_max>UINT_MAX ) ) return 0UL;

  ulong chain_cnt = lthash_chain_cnt( entry_max );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_sched_lthash_align(),          sizeof(fd_sched_lthash_t)                 );
  for( ulong i=0UL; i<FD_SCHED_LTHASH_LANE_CNT; i++ ) {
    l = FD_LAYOUT_APPEND( l, alignof(fd_sched_lthash_entry_t), entry_max*sizeof(fd_sched_lthash_entry_t) ); /* entry_pool */
    l = FD_LAYOUT_APPEND( l, lthash_map_align(),               lthash_map_footprint( chain_cnt )         ); /* map        */
  }
  l = FD_LAYOUT_APPEND( l, alignof(fd_lthash_value_t),       hash_max*sizeof(fd_lthash_value_t)        ); /* hash_pool  */
  l = FD_LAYOUT_APPEND( l, alignof(uint),                    hash_max*sizeof(uint)                     ); /* hash_free  */
  return FD_LAYOUT_FINI( l, fd_sched_lthash_align() );
}

void *
fd_sched_lthash_new( void * mem,
                     ulong  entry_max,
                     ulong  hash_max,
                     ulong  seed ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_sched_lthash_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem (%p)", mem ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_sched_lthash_footprint( entry_max, hash_max ) ) ) {
    FD_LOG_WARNING(( "bad entry_max (%lu) or hash_max (%lu)", entry_max, hash_max ));
    return NULL;
  }

  ulong chain_cnt = lthash_chain_cnt( entry_max );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_sched_lthash_t * lt = FD_SCRATCH_ALLOC_APPEND( l, fd_sched_lthash_align(), sizeof(fd_sched_lthash_t) );
  for( ulong i=0UL; i<FD_SCHED_LTHASH_LANE_CNT; i++ ) {
    fd_sched_lthash_entry_t * pool = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sched_lthash_entry_t), entry_max*sizeof(fd_sched_lthash_entry_t) );
    void *                    map  = FD_SCRATCH_ALLOC_APPEND( l, lthash_map_align(),               lthash_map_footprint( chain_cnt )         );

    for( ulong j=0UL; j<entry_max-1UL; j++ ) pool[ j ].q_next = (uint)(j+1UL);
    pool[ entry_max-1UL ].q_next = UINT_MAX;
    lthash_map_new( map, chain_cnt, fd_ulong_hash( seed+i ) );

    lt->lane[ i ].free_head = 0U;
    lt->lane[ i ].bank_idx  = ULONG_MAX;
  }
  /**/                 FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_lthash_value_t), hash_max*sizeof(fd_lthash_value_t) );
  uint * hash_free   = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),              hash_max*sizeof(uint)              );
  FD_SCRATCH_ALLOC_FINI( l, fd_sched_lthash_align() );

  /* Stack the slots so that acquire hands out 0, 1, 2, ... */
  for( ulong j=0UL; j<hash_max; j++ ) hash_free[ j ] = (uint)(hash_max-1UL-j);

  lt->entry_max     = entry_max;
  lt->hash_max      = hash_max;
  lt->hash_free_cnt = hash_max;

  return mem;
}

fd_sched_lthash_t *
fd_sched_lthash_join( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  fd_sched_lthash_t * lt        = (fd_sched_lthash_t *)mem;
  ulong               entry_max = lt->entry_max;
  ulong               hash_max  = lt->hash_max;
  ulong               chain_cnt = lthash_chain_cnt( entry_max );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  /**/ FD_SCRATCH_ALLOC_APPEND( l, fd_sched_lthash_align(), sizeof(fd_sched_lthash_t) );
  for( ulong i=0UL; i<FD_SCHED_LTHASH_LANE_CNT; i++ ) {
    void * pool = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sched_lthash_entry_t), entry_max*sizeof(fd_sched_lthash_entry_t) );
    void * map  = FD_SCRATCH_ALLOC_APPEND( l, lthash_map_align(),               lthash_map_footprint( chain_cnt )         );
    lt->lane[ i ].entry_pool = (fd_sched_lthash_entry_t *)pool;
    lt->lane[ i ].map        = lthash_map_join( map );
  }
  lt->hash_pool = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_lthash_value_t), hash_max*sizeof(fd_lthash_value_t) );
  lt->hash_free = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),              hash_max*sizeof(uint)              );
  FD_SCRATCH_ALLOC_FINI( l, fd_sched_lthash_align() );

  return lt;
}

ulong
fd_sched_lthash_lane_bank( fd_sched_lthash_t * l,
                           ulong               lane ) {
  return l->lane[ lane ].bank_idx;
}

void
fd_sched_lthash_lane_claim( fd_sched_lthash_t * l,
                            ulong               lane,
                            ulong               bank_idx ) {
  fd_sched_lthash_lane_t * ln = l->lane + lane;
  if( FD_UNLIKELY( bank_idx>=UINT_MAX ) ) FD_LOG_CRIT(( "bad bank_idx %lu", bank_idx ));
  if( FD_UNLIKELY( ln->bank_idx!=ULONG_MAX && ln->bank_idx!=bank_idx ) ) {
    FD_LOG_CRIT(( "invariant violation: claiming lane %lu for bank %lu, already claimed by bank %lu", lane, bank_idx, ln->bank_idx ));
  }
  ln->bank_idx = bank_idx;
}

fd_sched_lthash_entry_t *
fd_sched_lthash_query( fd_sched_lthash_t *    l,
                       ulong                  lane,
                       fd_acct_addr_t const * acct ) {
  fd_sched_lthash_lane_t * ln = l->lane + lane;
  return lthash_map_ele_query( ln->map, acct, NULL, ln->entry_pool );
}

fd_sched_lthash_entry_t *
fd_sched_lthash_insert( fd_sched_lthash_t *    l,
                        ulong                  lane,
                        fd_acct_addr_t const * acct ) {
  fd_sched_lthash_lane_t * ln = l->lane + lane;
  if( FD_UNLIKELY( ln->bank_idx==ULONG_MAX ) ) FD_LOG_CRIT(( "invariant violation: insert into idle lane %lu", lane ));
  if( FD_UNLIKELY( ln->free_head==UINT_MAX ) ) FD_LOG_CRIT(( "lane %lu has no free entry, entry_max %lu", lane, l->entry_max ));
  if( FD_UNLIKELY( lthash_map_ele_query_const( ln->map, acct, NULL, ln->entry_pool ) ) ) {
    FD_LOG_CRIT(( "invariant violation: account already in lane %lu", lane ));
  }

  uint                      idx = ln->free_head;
  fd_sched_lthash_entry_t * e   = ln->entry_pool + idx;
  ln->free_head = e->q_next;

  e->acct      = *acct;
  e->q_next    = UINT_MAX;
  e->hash_idx  = UINT_MAX;
  e->ptxn_idx  = 0U;
  e->bank_idx  = (uint)ln->bank_idx;
  e->sub_state = (uchar)FD_SCHED_LTHASH_SUB_QUEUED;
  e->add_state = (uchar)FD_SCHED_LTHASH_ADD_NONE;
  lthash_map_idx_insert( ln->map, idx, ln->entry_pool );
  return e;
}

ulong
fd_sched_lthash_entry_idx( fd_sched_lthash_t *             l,
                           ulong                           lane,
                           fd_sched_lthash_entry_t const * e ) {
  return (ulong)( e - l->lane[ lane ].entry_pool );
}

fd_sched_lthash_entry_t *
fd_sched_lthash_entry( fd_sched_lthash_t * l,
                       ulong               lane,
                       ulong               idx ) {
  return l->lane[ lane ].entry_pool + idx;
}

ulong
fd_sched_lthash_lane_cnt( fd_sched_lthash_t const * l,
                          ulong                     lane ) {
  return lthash_map_ele_cnt( l->lane[ lane ].map );
}

void
fd_sched_lthash_lane_reset( fd_sched_lthash_t * l,
                            ulong               lane ) {
  fd_sched_lthash_lane_t *  ln   = l->lane + lane;
  fd_sched_lthash_entry_t * pool = ln->entry_pool;
  ln->bank_idx = ULONG_MAX;
  /* An empty lane has nothing to free, so skip the two sweeps over the
     chain heads. */
  if( !lthash_map_ele_cnt( ln->map ) ) return;
  for( lthash_map_iter_t iter = lthash_map_iter_init( ln->map, pool );
       !lthash_map_iter_done( iter, ln->map, pool );
       iter = lthash_map_iter_next( iter, ln->map, pool ) ) {
    ulong                     idx = lthash_map_iter_idx( iter, ln->map, pool );
    fd_sched_lthash_entry_t * e   = pool + idx;
    if( e->hash_idx!=UINT_MAX ) fd_sched_lthash_slot_release( l, e->hash_idx );
    /* The iterator only follows map_next, so relinking q_next is safe. */
    e->q_next     = ln->free_head;
    ln->free_head = (uint)idx;
  }
  lthash_map_reset( ln->map );
}

fd_sched_lthash_iter_t
fd_sched_lthash_iter_init( fd_sched_lthash_t * l,
                           ulong               lane ) {
  fd_sched_lthash_lane_t * ln = l->lane + lane;
  return lthash_map_iter_init( ln->map, ln->entry_pool );
}

int
fd_sched_lthash_iter_done( fd_sched_lthash_t *    l,
                           ulong                  lane,
                           fd_sched_lthash_iter_t it ) {
  fd_sched_lthash_lane_t * ln = l->lane + lane;
  return lthash_map_iter_done( it, ln->map, ln->entry_pool );
}

fd_sched_lthash_iter_t
fd_sched_lthash_iter_next( fd_sched_lthash_t *    l,
                           ulong                  lane,
                           fd_sched_lthash_iter_t it ) {
  fd_sched_lthash_lane_t * ln = l->lane + lane;
  return lthash_map_iter_next( it, ln->map, ln->entry_pool );
}

fd_sched_lthash_entry_t *
fd_sched_lthash_iter_ele( fd_sched_lthash_t *    l,
                          ulong                  lane,
                          fd_sched_lthash_iter_t it ) {
  fd_sched_lthash_lane_t * ln = l->lane + lane;
  return lthash_map_iter_ele( it, ln->map, ln->entry_pool );
}

uint
fd_sched_lthash_slot_acquire( fd_sched_lthash_t * l ) {
  if( FD_UNLIKELY( !l->hash_free_cnt ) ) return UINT_MAX;
  return l->hash_free[ --l->hash_free_cnt ];
}

void
fd_sched_lthash_slot_release( fd_sched_lthash_t * l,
                              uint                idx ) {
  if( FD_UNLIKELY( (ulong)idx>=l->hash_max || l->hash_free_cnt>=l->hash_max ) ) {
    FD_LOG_CRIT(( "invariant violation: release of slot %u, hash_max %lu, free cnt %lu", idx, l->hash_max, l->hash_free_cnt ));
  }
  l->hash_free[ l->hash_free_cnt++ ] = idx;
}

fd_lthash_value_t *
fd_sched_lthash_slot( fd_sched_lthash_t * l,
                      uint                idx ) {
  return l->hash_pool + idx;
}

ulong
fd_sched_lthash_slot_free_cnt( fd_sched_lthash_t const * l ) {
  return l->hash_free_cnt;
}

void
fd_sched_lthash_entry_rewrite( fd_sched_lthash_t *       l,
                               fd_sched_lthash_entry_t * e,
                               fd_lthash_value_t *       delta ) {
  uint hash_idx = e->hash_idx;
  if( e->add_state==FD_SCHED_LTHASH_ADD_DONE ) {
    if( FD_UNLIKELY( hash_idx==UINT_MAX ) ) {
      FD_LOG_CRIT(( "invariant violation: rewrite of an applied addition with no slot to undo it, bank %u", e->bank_idx ));
    }
    fd_lthash_sub( delta, fd_sched_lthash_slot( l, hash_idx ) );
  }
  if( hash_idx!=UINT_MAX ) {
    fd_sched_lthash_slot_release( l, hash_idx );
    e->hash_idx = UINT_MAX;
  }
  e->ptxn_idx  = 0U;
  e->add_state = (uchar)FD_SCHED_LTHASH_ADD_NONE;
}

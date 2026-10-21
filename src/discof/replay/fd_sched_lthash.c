#include "fd_sched_lthash.h"
#include "../../util/fd_hash32.h"
#include "../../ballet/base58/fd_base58.h"

#define MAP_NAME          lthash_map
#define MAP_ELE_T         fd_sched_lthash_entry_t
#define MAP_KEY_T         fd_acct_addr_t
#define MAP_KEY           acct
#define MAP_NEXT          map_next
#define MAP_IDX_T         uint
#define MAP_KEY_HASH(k,s) fd_hash32( (k)->b, (s) )
#define MAP_KEY_EQ(k0,k1) (!memcmp( (k0)->b, (k1)->b, 32UL ))
#include "../../util/tmpl/fd_map_chain.c"

/* Each lane has two maps with an entry region each.  The lane head
   owns one and the block behind it builds its entries in the other, so
   that the switch of heads only swaps the two.  Entries are handed out
   in index order and only ever freed together when their map is
   released, so a map's live entries are the first entry_cnt of its
   region and no free list is needed.  Map k owns entry indices
   [k*entry_max,(k+1)*entry_max). */
struct fd_sched_lthash_lane {
  fd_sched_lthash_entry_t * entry_pool;        /* 2*entry_max entries. */
  lthash_map_t *            map[ 2 ];
  uint                      entry_cnt[ 2 ];    /* Live entries of the map. */
  uint                      clean_cursor[ 2 ]; /* Entries of a CLEANING map cleared so far. */
  ulong                     bank_idx[ 2 ];     /* Block that owns the map, ULONG_MAX if none. */
  int                       state[ 2 ];        /* FD_SCHED_LTHASH_MAP_* */
  ulong                     primary;           /* Map the lane head owns. */
};
typedef struct fd_sched_lthash_lane fd_sched_lthash_lane_t;

struct fd_sched_lthash {
  ulong                  entry_max;
  ulong                  spec_max;
  ulong                  spec_free_cnt; /* spec_free[ spec_free_cnt-1 ] is the top. */
  fd_lthash_value_t *    spec_pool;     /* spec_max total entries. */
  uint *                 spec_free;     /* Stack of free entry indices. */
  fd_sched_lthash_lane_t lane[ FD_SCHED_LTHASH_LANE_CNT ];
};

#define SCHED_LTHASH_ALIGN (128UL)
FD_STATIC_ASSERT( alignof(fd_lthash_value_t)<=SCHED_LTHASH_ALIGN, lthash_align );

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
                           ulong spec_max ) {
  if( FD_UNLIKELY( !entry_max || entry_max>UINT_MAX/2UL || spec_max>UINT_MAX ) ) return 0UL;

  ulong chain_cnt = lthash_chain_cnt( entry_max );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_sched_lthash_align(), sizeof(fd_sched_lthash_t) );
  for( ulong i=0UL; i<FD_SCHED_LTHASH_LANE_CNT; i++ ) {
    l = FD_LAYOUT_APPEND( l, alignof(fd_sched_lthash_entry_t), 2UL*entry_max*sizeof(fd_sched_lthash_entry_t) ); /* entry_pool */
    l = FD_LAYOUT_APPEND( l, lthash_map_align(),               lthash_map_footprint( chain_cnt )             ); /* map[0]     */
    l = FD_LAYOUT_APPEND( l, lthash_map_align(),               lthash_map_footprint( chain_cnt )             ); /* map[1]     */
  }
  l = FD_LAYOUT_APPEND( l, alignof(fd_lthash_value_t), spec_max*sizeof(fd_lthash_value_t) ); /* spec_pool  */
  l = FD_LAYOUT_APPEND( l, alignof(uint),              spec_max*sizeof(uint)              ); /* spec_free  */
  return FD_LAYOUT_FINI( l, fd_sched_lthash_align() );
}

void *
fd_sched_lthash_new( void * mem,
                     ulong  entry_max,
                     ulong  spec_max,
                     ulong  seed ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_sched_lthash_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem (%p)", mem ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_sched_lthash_footprint( entry_max, spec_max ) ) ) {
    FD_LOG_WARNING(( "bad entry_max (%lu) or spec_max (%lu)", entry_max, spec_max ));
    return NULL;
  }

  ulong chain_cnt = lthash_chain_cnt( entry_max );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_sched_lthash_t * lt = FD_SCRATCH_ALLOC_APPEND( l, fd_sched_lthash_align(), sizeof(fd_sched_lthash_t) );
  for( ulong i=0UL; i<FD_SCHED_LTHASH_LANE_CNT; i++ ) {
    /**/ FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sched_lthash_entry_t), 2UL*entry_max*sizeof(fd_sched_lthash_entry_t) );
    for( ulong k=0UL; k<2UL; k++ ) {
      void * map = FD_SCRATCH_ALLOC_APPEND( l, lthash_map_align(), lthash_map_footprint( chain_cnt ) );
      lthash_map_new( map, chain_cnt, fd_ulong_hash( seed+2UL*i+k ) );
      lt->lane[ i ].entry_cnt   [ k ] = 0U;
      lt->lane[ i ].clean_cursor[ k ] = 0U;
      lt->lane[ i ].bank_idx    [ k ] = ULONG_MAX;
      lt->lane[ i ].state       [ k ] = FD_SCHED_LTHASH_MAP_FREE;
    }
    lt->lane[ i ].primary = 0UL;
  }
  /**/                 FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_lthash_value_t), spec_max*sizeof(fd_lthash_value_t) );
  uint * spec_free   = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),              spec_max*sizeof(uint)              );
  FD_SCRATCH_ALLOC_FINI( l, fd_sched_lthash_align() );

  /* Acquire is LIFO, so this hands out 0, 1, 2, ... */
  for( ulong j=0UL; j<spec_max; j++ ) spec_free[ j ] = (uint)(spec_max-1UL-j);

  lt->entry_max     = entry_max;
  lt->spec_max      = spec_max;
  lt->spec_free_cnt = spec_max;

  return mem;
}

fd_sched_lthash_t *
fd_sched_lthash_join( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  fd_sched_lthash_t * lt        = mem;
  ulong               entry_max = lt->entry_max;
  ulong               spec_max  = lt->spec_max;
  ulong               chain_cnt = lthash_chain_cnt( entry_max );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  FD_SCRATCH_ALLOC_APPEND( l, fd_sched_lthash_align(), sizeof(fd_sched_lthash_t) );
  for( ulong i=0UL; i<FD_SCHED_LTHASH_LANE_CNT; i++ ) {
    void * pool = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sched_lthash_entry_t), 2UL*entry_max*sizeof(fd_sched_lthash_entry_t) );
    lt->lane[ i ].entry_pool = (fd_sched_lthash_entry_t *)pool;
    for( ulong k=0UL; k<2UL; k++ ) {
      void * map = FD_SCRATCH_ALLOC_APPEND( l, lthash_map_align(), lthash_map_footprint( chain_cnt ) );
      lt->lane[ i ].map[ k ] = lthash_map_join( map );
    }
  }
  lt->spec_pool = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_lthash_value_t), spec_max*sizeof(fd_lthash_value_t) );
  lt->spec_free = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),              spec_max*sizeof(uint)              );
  FD_SCRATCH_ALLOC_FINI( l, fd_sched_lthash_align() );

  return lt;
}

/* The two maps of a lane. */

ulong
fd_sched_lthash_lane_primary( fd_sched_lthash_t const * l,
                                ulong                     lane_idx ) {
  return l->lane[ lane_idx ].primary;
}

ulong
fd_sched_lthash_lane_spare( fd_sched_lthash_t const * l,
                                 ulong                     lane_idx ) {
  return 1UL-l->lane[ lane_idx ].primary;
}

ulong
fd_sched_lthash_lane_map_of( fd_sched_lthash_t const * l,
                           ulong                     lane_idx,
                           ulong                     bank_idx ) {
  fd_sched_lthash_lane_t const * ln = l->lane + lane_idx;
  if( ln->state[ 0 ]==FD_SCHED_LTHASH_MAP_LIVE && ln->bank_idx[ 0 ]==bank_idx ) return 0UL;
  if( ln->state[ 1 ]==FD_SCHED_LTHASH_MAP_LIVE && ln->bank_idx[ 1 ]==bank_idx ) return 1UL;
  return ULONG_MAX;
}

int
fd_sched_lthash_map_state( fd_sched_lthash_t const * l,
                            ulong                     lane_idx,
                            ulong                     map_idx ) {
  return l->lane[ lane_idx ].state[ map_idx ];
}

ulong
fd_sched_lthash_map_bank( fd_sched_lthash_t const * l,
                           ulong                     lane_idx,
                           ulong                     map_idx ) {
  fd_sched_lthash_lane_t const * ln = l->lane + lane_idx;
  return ln->state[ map_idx ]==FD_SCHED_LTHASH_MAP_LIVE ? ln->bank_idx[ map_idx ] : ULONG_MAX;
}

ulong
fd_sched_lthash_map_clean( fd_sched_lthash_t * l,
                            ulong               lane_idx,
                            ulong               map_idx,
                            ulong               max ) {
  fd_sched_lthash_lane_t * ln = l->lane + lane_idx;
  if( FD_UNLIKELY( ln->state[ map_idx ]!=FD_SCHED_LTHASH_MAP_CLEANING ) ) return 0UL;
  lthash_map_t *            m         = ln->map[ map_idx ];
  fd_sched_lthash_entry_t * pool      = ln->entry_pool + map_idx*l->entry_max;
  uint *                    chain     = lthash_map_private_chain( m );
  ulong                     seed      = lthash_map_seed     ( m );
  ulong                     chain_cnt = lthash_map_chain_cnt( m );
  ulong                     cnt       = ln->entry_cnt[ map_idx ];
  ulong                     cur       = ln->clean_cursor[ map_idx ];
  ulong                     end       = fd_ulong_min( cnt, cur+max );
  /* Clearing the head of each live entry's chain empties the map.  A
     chain head is set only while the chain holds an entry, and every
     entry of the map is freed here, so no chain loses an entry that
     should stay.  The dead entries keep stale map_next links, which no
     chain head reaches and which the next insert of the entry
     overwrites.  The template has no call for clearing one head, so
     this goes through the private chain array. */
  for( ; cur<end; cur++ ) {
    fd_sched_lthash_entry_t * e = pool + cur;
    chain[ lthash_map_private_chain_idx( &e->acct, seed, chain_cnt ) ] = UINT_MAX;
    if( e->spec_idx!=UINT_MAX ) fd_sched_lthash_spec_release( l, e->spec_idx );
  }
  ln->clean_cursor[ map_idx ] = (uint)cur;
  if( cur<cnt ) return cnt-cur;
  ln->entry_cnt   [ map_idx ] = 0U;
  ln->clean_cursor[ map_idx ] = 0U;
  ln->state       [ map_idx ] = FD_SCHED_LTHASH_MAP_FREE;
  return 0UL;
}

void
fd_sched_lthash_map_claim( fd_sched_lthash_t * l,
                            ulong               lane_idx,
                            ulong               map_idx,
                            ulong               bank_idx ) {
  fd_sched_lthash_lane_t * ln = l->lane + lane_idx;
  if( FD_UNLIKELY( bank_idx>=UINT_MAX ) ) FD_LOG_CRIT(( "bad bank_idx %lu", bank_idx ));
  if( FD_UNLIKELY( ln->state[ map_idx ]==FD_SCHED_LTHASH_MAP_CLEANING ) ) fd_sched_lthash_map_clean( l, lane_idx, map_idx, ULONG_MAX );
  if( FD_UNLIKELY( ln->state[ map_idx ]!=FD_SCHED_LTHASH_MAP_FREE ) ) {
    FD_LOG_CRIT(( "invariant violation: claiming map %lu of lane %lu for bank %lu, owned by bank %lu", map_idx, lane_idx, bank_idx, ln->bank_idx[ map_idx ] ));
  }
  FD_TEST( !ln->entry_cnt[ map_idx ] );
  ln->bank_idx[ map_idx ] = bank_idx;
  ln->state   [ map_idx ] = FD_SCHED_LTHASH_MAP_LIVE;
}

void
fd_sched_lthash_map_release( fd_sched_lthash_t * l,
                              ulong               lane_idx,
                              ulong               map_idx ) {
  fd_sched_lthash_lane_t * ln = l->lane + lane_idx;
  FD_TEST( ln->state[ map_idx ]==FD_SCHED_LTHASH_MAP_LIVE );
  ln->bank_idx    [ map_idx ] = ULONG_MAX;
  ln->clean_cursor[ map_idx ] = 0U;
  ln->state       [ map_idx ] = ln->entry_cnt[ map_idx ] ? FD_SCHED_LTHASH_MAP_CLEANING : FD_SCHED_LTHASH_MAP_FREE;
}

void
fd_sched_lthash_lane_swap( fd_sched_lthash_t * l,
                           ulong               lane_idx ) {
  fd_sched_lthash_lane_t * ln = l->lane + lane_idx;
  ulong spare = 1UL-ln->primary;
  FD_TEST( ln->state[ spare ]==FD_SCHED_LTHASH_MAP_LIVE );
  FD_TEST( ln->state[ ln->primary ]!=FD_SCHED_LTHASH_MAP_LIVE );
  ln->primary = spare;
}

/* The primary map entry points. */

ulong
fd_sched_lthash_lane_bank( fd_sched_lthash_t * l,
                           ulong               lane_idx ) {
  return fd_sched_lthash_map_bank( l, lane_idx, l->lane[ lane_idx ].primary );
}

void
fd_sched_lthash_lane_claim( fd_sched_lthash_t * l,
                            ulong               lane_idx,
                            ulong               bank_idx ) {
  fd_sched_lthash_lane_t * ln = l->lane + lane_idx;
  if( ln->state[ ln->primary ]==FD_SCHED_LTHASH_MAP_LIVE && ln->bank_idx[ ln->primary ]==bank_idx ) return;
  fd_sched_lthash_map_claim( l, lane_idx, ln->primary, bank_idx );
}

void
fd_sched_lthash_lane_reset( fd_sched_lthash_t * l,
                            ulong               lane_idx ) {
  fd_sched_lthash_lane_t * ln = l->lane + lane_idx;
  if( ln->state[ ln->primary ]==FD_SCHED_LTHASH_MAP_LIVE ) fd_sched_lthash_map_release( l, lane_idx, ln->primary );
  fd_sched_lthash_map_clean( l, lane_idx, ln->primary, ULONG_MAX );
}

ulong
fd_sched_lthash_lane_entry_cnt( fd_sched_lthash_t const * l,
                                ulong                     lane_idx ) {
  fd_sched_lthash_lane_t const * ln = l->lane + lane_idx;
  return ln->entry_cnt[ ln->primary ];
}

fd_sched_lthash_entry_t *
fd_sched_lthash_query_map( fd_sched_lthash_t *    l,
                          ulong                  lane_idx,
                          ulong                  map_idx,
                          fd_acct_addr_t const * acct ) {
  fd_sched_lthash_lane_t * ln = l->lane + lane_idx;
  return lthash_map_ele_query( ln->map[ map_idx ], acct, NULL, ln->entry_pool );
}

fd_sched_lthash_entry_t *
fd_sched_lthash_query( fd_sched_lthash_t *    l,
                       ulong                  lane_idx,
                       fd_acct_addr_t const * acct ) {
  return fd_sched_lthash_query_map( l, lane_idx, l->lane[ lane_idx ].primary, acct );
}

fd_sched_lthash_entry_t *
fd_sched_lthash_insert_map( fd_sched_lthash_t *    l,
                           ulong                  lane_idx,
                           ulong                  map_idx,
                           fd_acct_addr_t const * acct ) {
  fd_sched_lthash_lane_t * ln = l->lane + lane_idx;
  if( FD_UNLIKELY( ln->state[ map_idx ]!=FD_SCHED_LTHASH_MAP_LIVE ) ) FD_LOG_CRIT(( "invariant violation: insert into unowned map %lu of lane %lu", map_idx, lane_idx ));
  if( FD_UNLIKELY( ln->entry_cnt[ map_idx ]==l->entry_max ) ) FD_LOG_CRIT(( "lane %lu map %lu has no free entry, entry_max %lu", lane_idx, map_idx, l->entry_max ));
  if( FD_UNLIKELY( lthash_map_ele_query_const( ln->map[ map_idx ], acct, NULL, ln->entry_pool ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( acct->b, acct_str );
    FD_LOG_CRIT(( "invariant violation: account %s already in lane %lu map %lu", acct_str, lane_idx, map_idx ));
  }

  uint                      idx = (uint)( map_idx*l->entry_max + ln->entry_cnt[ map_idx ]++ );
  fd_sched_lthash_entry_t * e   = ln->entry_pool + idx;

  e->acct      = *acct;
  e->q_next    = UINT_MAX;
  e->spec_idx  = UINT_MAX;
  e->ptxn_idx  = 0U;
  e->bank_idx  = (uint)ln->bank_idx[ map_idx ]; /* Safe cast, range checked when the map is claimed. */
  e->sub_state = (uchar)FD_SCHED_LTHASH_SUB_QUEUED;
  e->add_state = (uchar)FD_SCHED_LTHASH_ADD_NONE;
  lthash_map_idx_insert( ln->map[ map_idx ], idx, ln->entry_pool );
  return e;
}

fd_sched_lthash_entry_t *
fd_sched_lthash_insert( fd_sched_lthash_t *    l,
                        ulong                  lane_idx,
                        fd_acct_addr_t const * acct ) {
  return fd_sched_lthash_insert_map( l, lane_idx, l->lane[ lane_idx ].primary, acct );
}

ulong
fd_sched_lthash_entry_idx( fd_sched_lthash_t *             l,
                           ulong                           lane_idx,
                           fd_sched_lthash_entry_t const * entry ) {
  return (ulong)( entry - l->lane[ lane_idx ].entry_pool );
}

fd_sched_lthash_entry_t *
fd_sched_lthash_entry( fd_sched_lthash_t * l,
                       ulong               lane_idx,
                       ulong               entry_idx ) {
  return l->lane[ lane_idx ].entry_pool + entry_idx;
}

fd_sched_lthash_iter_t
fd_sched_lthash_iter_init( fd_sched_lthash_t * l,
                           ulong               lane_idx,
                           ulong               map_idx ) {
  (void)lane_idx;
  return (fd_sched_lthash_iter_t)( map_idx*l->entry_max );
}

int
fd_sched_lthash_iter_done( fd_sched_lthash_t *    l,
                           ulong                  lane_idx,
                           fd_sched_lthash_iter_t iter ) {
  ulong map_idx = iter/l->entry_max;
  return iter>=map_idx*l->entry_max+l->lane[ lane_idx ].entry_cnt[ map_idx ];
}

fd_sched_lthash_iter_t
fd_sched_lthash_iter_next( fd_sched_lthash_t *    l,
                           ulong                  lane_idx,
                           fd_sched_lthash_iter_t iter ) {
  (void)l;
  (void)lane_idx;
  return iter+1U;
}

fd_sched_lthash_entry_t *
fd_sched_lthash_iter_ele( fd_sched_lthash_t *    l,
                          ulong                  lane_idx,
                          fd_sched_lthash_iter_t iter ) {
  return l->lane[ lane_idx ].entry_pool + iter;
}

uint
fd_sched_lthash_spec_acquire( fd_sched_lthash_t * l ) {
  if( FD_UNLIKELY( !l->spec_free_cnt ) ) return UINT_MAX;
  return l->spec_free[ --l->spec_free_cnt ];
}

void
fd_sched_lthash_spec_release( fd_sched_lthash_t * l,
                              uint                idx ) {
  if( FD_UNLIKELY( (ulong)idx>=l->spec_max || l->spec_free_cnt>=l->spec_max ) ) {
    FD_LOG_CRIT(( "invariant violation: release of speculation entry %u, spec_max %lu, free cnt %lu", idx, l->spec_max, l->spec_free_cnt ));
  }
  l->spec_free[ l->spec_free_cnt++ ] = idx;
}

fd_lthash_value_t *
fd_sched_lthash_spec_entry( fd_sched_lthash_t * l,
                            uint                idx ) {
  return l->spec_pool + idx;
}

ulong
fd_sched_lthash_spec_free_cnt( fd_sched_lthash_t const * l ) {
  return l->spec_free_cnt;
}

void
fd_sched_lthash_entry_rewrite( fd_sched_lthash_t *       l,
                               fd_sched_lthash_entry_t * entry,
                               fd_lthash_value_t *       block_lthash ) {
  uint spec_idx = entry->spec_idx;
  if( entry->add_state==FD_SCHED_LTHASH_ADD_DONE ) {
    if( FD_UNLIKELY( spec_idx==UINT_MAX ) ) {
      FD_LOG_CRIT(( "invariant violation: rewrite of an applied addition with no entry to undo it, bank idx %u", entry->bank_idx ));
    }
    fd_lthash_sub( block_lthash, fd_sched_lthash_spec_entry( l, spec_idx ) );
  }
  if( spec_idx!=UINT_MAX ) {
    fd_sched_lthash_spec_release( l, spec_idx );
    entry->spec_idx = UINT_MAX;
  }
  entry->ptxn_idx  = 0U;
  entry->add_state = (uchar)FD_SCHED_LTHASH_ADD_NONE;
}

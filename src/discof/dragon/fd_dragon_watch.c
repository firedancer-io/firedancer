#include "fd_dragon_watch.h"
#include "../../util/fd_util.h"
#include "../../ballet/siphash13/fd_siphash13.h"

#define FD_DRAGON_WATCH_MAGIC (0xf17eda2547d2a701UL) /* firedancer dragon watch */

#define WATCH_BIT_NONE ((uchar)0xff)

struct watch_key {
  uchar b[ 32 ];
};

typedef struct watch_key watch_key_t;

/* watch_ele_t is one stored address.  mask has one bit per watch set
   that holds the address, live or retired, and is zero exactly when
   the element is free.  pend is the subset of mask whose sets await
   the answer to the add that put the address in them.  gen counts the
   times the element was freed,
   which is what tells a reference to an address that left the index
   from one to the address stored in its place. */

struct watch_ele {
  watch_key_t key;
  ulong       mask;
  ulong       pend;
  uint        next;
  uint        gen;
};

typedef struct watch_ele watch_ele_t;

FD_STATIC_ASSERT( sizeof(watch_ele_t)==56UL, layout );

#define POOL_NAME  watch_pool
#define POOL_T     watch_ele_t
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               watch_map
#define MAP_ELE_T              watch_ele_t
#define MAP_KEY_T              watch_key_t
#define MAP_IDX_T              uint
#define MAP_KEY_EQ(k0,k1)      fd_memeq( (k0)->b, (k1)->b, 32UL )
#define MAP_KEY_HASH(key,seed) fd_siphash13_hash( (key)->b, 32UL, (seed), fd_ulong_rotate_left( (seed), 32 ) )
#include "../../util/tmpl/fd_map_chain.c"

struct fd_dragon_watch {
  ulong magic;
  ulong key_max;

  ulong open;    /* the open sets, bit i for set i */
  ulong live;    /* the bits open sets use */
  ulong retired; /* the bits the sweep is taking out; disjoint from live */
  ulong cursor;  /* the storage slot the sweep visits next */

  /* An open set gets its bit with its first address, so that a set
     can be open or cleared while no bit is free. */
  uchar bit_of_set[ FD_DRAGON_WATCH_SET_MAX ]; /* valid for open sets; WATCH_BIT_NONE if the set has no bit */
  uchar set_of_bit[ FD_DRAGON_WATCH_SET_MAX ]; /* valid for live bits */

  /* bit_key_cnt is the number of stored addresses whose mask has the
     bit.  It is nonzero for every retired bit. */
  ulong bit_key_cnt[ FD_DRAGON_WATCH_SET_MAX ];

  watch_ele_t * pool;
  watch_map_t * map;
};

FD_FN_CONST ulong
fd_dragon_watch_align( void ) {
  return FD_DRAGON_WATCH_ALIGN;
}

FD_FN_CONST ulong
fd_dragon_watch_footprint( ulong key_max ) {
  if( FD_UNLIKELY( !key_max || key_max>FD_DRAGON_WATCH_KEY_MAX ) ) return 0UL;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_DRAGON_WATCH_ALIGN, sizeof(fd_dragon_watch_t)                                  );
  l = FD_LAYOUT_APPEND( l, watch_pool_align(),    watch_pool_footprint( key_max )                            );
  l = FD_LAYOUT_APPEND( l, watch_map_align(),     watch_map_footprint( watch_map_chain_cnt_est( key_max ) )  );
  return FD_LAYOUT_FINI( l, FD_DRAGON_WATCH_ALIGN );
}

void *
fd_dragon_watch_new( void * mem,
                     ulong  key_max,
                     ulong  seed ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_DRAGON_WATCH_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_dragon_watch_footprint( key_max ) ) ) {
    FD_LOG_WARNING(( "invalid key_max %lu", key_max ));
    return NULL;
  }

  ulong chain_cnt = watch_map_chain_cnt_est( key_max );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_dragon_watch_t * watch    = FD_SCRATCH_ALLOC_APPEND( l, FD_DRAGON_WATCH_ALIGN, sizeof(fd_dragon_watch_t)        );
  void *              pool_mem = FD_SCRATCH_ALLOC_APPEND( l, watch_pool_align(),    watch_pool_footprint( key_max )  );
  void *              map_mem  = FD_SCRATCH_ALLOC_APPEND( l, watch_map_align(),     watch_map_footprint( chain_cnt ) );
  FD_SCRATCH_ALLOC_FINI( l, FD_DRAGON_WATCH_ALIGN );

  fd_memset( watch, 0, sizeof(fd_dragon_watch_t) );
  watch->key_max = key_max;

  watch->pool = watch_pool_join( watch_pool_new( pool_mem, key_max ) );
  watch->map  = watch_map_join ( watch_map_new ( map_mem, chain_cnt, seed ) );
  if( FD_UNLIKELY( !watch->pool || !watch->map ) ) {
    FD_LOG_WARNING(( "failed to format the index" ));
    return NULL;
  }
  for( ulong i=0UL; i<key_max; i++ ) {
    watch->pool[ i ].mask = 0UL;
    watch->pool[ i ].pend = 0UL;
    watch->pool[ i ].gen  = 0U;
  }

  FD_COMPILER_MFENCE();
  watch->magic = FD_DRAGON_WATCH_MAGIC;
  FD_COMPILER_MFENCE();
  return mem;
}

fd_dragon_watch_t *
fd_dragon_watch_join( void * mem ) {
  fd_dragon_watch_t * watch = mem;
  if( FD_UNLIKELY( !watch ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( watch->magic!=FD_DRAGON_WATCH_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  return watch;
}

void *
fd_dragon_watch_leave( fd_dragon_watch_t * watch ) {
  return watch;
}

void *
fd_dragon_watch_delete( void * mem ) {
  fd_dragon_watch_t * watch = mem;
  if( FD_UNLIKELY( !watch || watch->magic!=FD_DRAGON_WATCH_MAGIC ) ) {
    FD_LOG_WARNING(( "bad mem" ));
    return NULL;
  }
  FD_COMPILER_MFENCE();
  watch->magic = 0UL;
  FD_COMPILER_MFENCE();
  return mem;
}

/* watch_set_bit returns the bit of an open set as a mask, or 0 if the
   set has none. */

static inline ulong
watch_set_bit( fd_dragon_watch_t const * watch,
               ulong                     set ) {
  if( FD_UNLIKELY( set>=FD_DRAGON_WATCH_SET_MAX || !( ( watch->open>>set )&1UL ) ) ) FD_LOG_CRIT(( "watch set %lu is not open", set ));
  ulong bit = watch->bit_of_set[ set ];
  return fd_ulong_if( bit==WATCH_BIT_NONE, 0UL, 1UL<<( bit&63UL ) );
}

/* watch_strip takes the retired bits out of a stored address and
   returns the mask that is left.  A bit that no address holds any
   more stops being retired.  The caller frees an element whose mask
   it leaves at zero. */

static inline ulong
watch_strip( fd_dragon_watch_t * watch,
             watch_ele_t *       ele ) {
  ulong gone = ele->mask & watch->retired;
  ele->mask &= ~gone;
  ele->pend &= ~gone;
  while( gone ) {
    int bit = fd_ulong_find_lsb( gone );
    gone    = fd_ulong_pop_lsb( gone );
    if( !--watch->bit_key_cnt[ bit ] ) watch->retired &= ~( 1UL<<bit );
  }
  return ele->mask;
}

static inline void
watch_ele_free( fd_dragon_watch_t * watch,
                watch_ele_t *       ele ) {
  watch_map_idx_remove( watch->map, &ele->key, UINT_MAX, watch->pool );
  ele->gen++;
  watch_pool_ele_release( watch->pool, ele );
}

/* watch_set_drop takes the bit of an open set away, which leaves the
   set empty.  A bit that no address holds is free at once; any other
   is retired. */

static inline void
watch_set_drop( fd_dragon_watch_t * watch,
                ulong               set ) {
  ulong bit_mask = watch_set_bit( watch, set );
  if( !bit_mask ) return;
  watch->live &= ~bit_mask;
  if( watch->bit_key_cnt[ fd_ulong_find_lsb( bit_mask ) ] ) watch->retired |= bit_mask;
  watch->bit_of_set[ set ] = WATCH_BIT_NONE;
}

void
fd_dragon_watch_set_open( fd_dragon_watch_t * watch,
                          ulong               set ) {
  if( FD_UNLIKELY( set>=FD_DRAGON_WATCH_SET_MAX || ( ( watch->open>>set )&1UL ) ) ) FD_LOG_CRIT(( "watch set %lu is open", set ));
  watch->bit_of_set[ set ] = WATCH_BIT_NONE;
  watch->open |= 1UL<<set;
}

void
fd_dragon_watch_set_clear( fd_dragon_watch_t * watch,
                           ulong               set ) {
  watch_set_drop( watch, set );
}

void
fd_dragon_watch_set_close( fd_dragon_watch_t * watch,
                           ulong               set ) {
  watch_set_drop( watch, set );
  watch->open &= ~( 1UL<<set );
}

FD_FN_PURE ulong
fd_dragon_watch_set_mask( fd_dragon_watch_t const * watch ) {
  return watch->open;
}

FD_FN_PURE ulong
fd_dragon_watch_set_key_cnt( fd_dragon_watch_t const * watch,
                             ulong                     set ) {
  ulong bit_mask = watch_set_bit( watch, set );
  return bit_mask ? watch->bit_key_cnt[ fd_ulong_find_lsb( bit_mask ) ] : 0UL;
}

int
fd_dragon_watch_add( fd_dragon_watch_t * watch,
                     ulong               set,
                     uchar const *       pubkey ) {
  ulong bit_mask = watch_set_bit( watch, set );

  watch_key_t key[1];
  memcpy( key->b, pubkey, 32UL );

  watch_ele_t * ele = watch_map_ele_query( watch->map, key, NULL, watch->pool );
  if( ele && ( ele->mask & bit_mask ) ) return 0;
  if( FD_UNLIKELY( !ele && !watch_pool_free( watch->pool ) ) ) return -1;

  if( FD_UNLIKELY( !bit_mask ) ) {
    ulong free = ~( watch->live | watch->retired );
    if( FD_UNLIKELY( !free ) ) return -1;
    int bit  = fd_ulong_find_lsb( free );
    bit_mask = 1UL<<bit;
    watch->live |= bit_mask;
    watch->bit_of_set[ set ] = (uchar)bit;
    watch->set_of_bit[ bit ] = (uchar)set;
  }

  if( ele ) {
    watch_strip( watch, ele );
  } else {
    ele       = watch_pool_ele_acquire( watch->pool );
    ele->key  = *key;
    ele->mask = 0UL;
    ele->pend = 0UL;
    watch_map_ele_insert( watch->map, ele, watch->pool );
  }
  ele->mask |= bit_mask;
  watch->bit_key_cnt[ fd_ulong_find_lsb( bit_mask ) ]++;
  return 1;
}

int
fd_dragon_watch_remove( fd_dragon_watch_t * watch,
                        ulong               set,
                        uchar const *       pubkey ) {
  ulong bit_mask = watch_set_bit( watch, set );
  if( !bit_mask ) return 0;

  watch_key_t key[1];
  memcpy( key->b, pubkey, 32UL );

  watch_ele_t * ele = watch_map_ele_query( watch->map, key, NULL, watch->pool );
  if( !ele || !( ele->mask & bit_mask ) ) return 0;

  ele->mask &= ~bit_mask;
  ele->pend &= ~bit_mask;
  watch->bit_key_cnt[ fd_ulong_find_lsb( bit_mask ) ]--;
  if( !watch_strip( watch, ele ) ) watch_ele_free( watch, ele );
  return 1;
}

FD_FN_PURE ulong
fd_dragon_watch_query( fd_dragon_watch_t const * watch,
                       uchar const *             pubkey ) {
  watch_key_t key[1];
  memcpy( key->b, pubkey, 32UL );

  watch_ele_t const * ele = watch_map_ele_query_const( watch->map, key, NULL, watch->pool );
  if( !ele ) return 0UL;

  ulong bits = ele->mask & watch->live;
  ulong sets = 0UL;
  while( bits ) {
    sets |= 1UL<<watch->set_of_bit[ fd_ulong_find_lsb( bits ) ];
    bits  = fd_ulong_pop_lsb( bits );
  }
  return sets;
}

ulong
fd_dragon_watch_query_pending( fd_dragon_watch_t const * watch,
                               uchar const *             pubkey,
                               ulong *                   pending ) {
  *pending = 0UL;

  watch_key_t key[1];
  memcpy( key->b, pubkey, 32UL );

  watch_ele_t const * ele = watch_map_ele_query_const( watch->map, key, NULL, watch->pool );
  if( !ele ) return 0UL;

  ulong sets = 0UL;
  ulong pend = 0UL;
  for( ulong bits = ele->mask & watch->live; bits; bits = fd_ulong_pop_lsb( bits ) ) {
    int   bit = fd_ulong_find_lsb( bits );
    ulong set = 1UL<<watch->set_of_bit[ bit ];
    sets |= set;
    pend |= fd_ulong_if( ( ele->pend>>bit )&1UL, set, 0UL );
  }
  *pending = pend;
  return sets;
}

void
fd_dragon_watch_ref_pending( fd_dragon_watch_t * watch,
                             ulong               set,
                             ulong               ref,
                             int                 pending ) {
  if( FD_UNLIKELY( !fd_dragon_watch_ref_key( watch, set, ref ) ) ) return;
  watch_ele_t * ele = watch->pool + ( ref & 0xffffffffUL );
  ulong         bit = watch_set_bit( watch, set );
  ele->pend = fd_ulong_if( !!pending, ele->pend | bit, ele->pend & ~bit );
}

FD_FN_PURE ulong
fd_dragon_watch_ref( fd_dragon_watch_t const * watch,
                     ulong                     set,
                     uchar const *             pubkey ) {
  ulong bit_mask = watch_set_bit( watch, set );

  watch_key_t key[1];
  memcpy( key->b, pubkey, 32UL );

  watch_ele_t const * ele = watch_map_ele_query_const( watch->map, key, NULL, watch->pool );
  if( !ele || !( ele->mask & bit_mask ) ) return ULONG_MAX;
  return (ulong)( ele - watch->pool ) | ( (ulong)ele->gen<<32 );
}

FD_FN_PURE uchar const *
fd_dragon_watch_ref_key( fd_dragon_watch_t const * watch,
                         ulong                     set,
                         ulong                     ref ) {
  ulong idx = ref & 0xffffffffUL;
  if( FD_UNLIKELY( idx>=watch->key_max || set>=FD_DRAGON_WATCH_SET_MAX || !( ( watch->open>>set )&1UL ) ) ) return NULL;
  watch_ele_t const * ele = watch->pool + idx;
  if( ele->gen!=(uint)( ref>>32 ) || !( ele->mask & watch_set_bit( watch, set ) ) ) return NULL;
  return ele->key.b;
}

FD_FN_PURE ulong
fd_dragon_watch_key_cnt( fd_dragon_watch_t const * watch ) {
  return watch_pool_used( watch->pool );
}

FD_FN_PURE ulong
fd_dragon_watch_key_max( fd_dragon_watch_t const * watch ) {
  return watch->key_max;
}

int
fd_dragon_watch_sweep( fd_dragon_watch_t * watch,
                       ulong               visit_max ) {
  ulong cursor = watch->cursor;
  for( ulong i=0UL; i<visit_max && watch->retired; i++ ) {
    watch_ele_t * ele = watch->pool + cursor;
    cursor = fd_ulong_if( cursor+1UL<watch->key_max, cursor+1UL, 0UL );
    if( !( ele->mask & watch->retired ) ) continue;
    if( !watch_strip( watch, ele ) ) watch_ele_free( watch, ele );
  }
  watch->cursor = cursor;
  return !!watch->retired;
}

FD_FN_PURE int
fd_dragon_watch_sweep_pending( fd_dragon_watch_t const * watch ) {
  return !!watch->retired;
}

int
fd_dragon_watch_verify( fd_dragon_watch_t const * watch ) {

# define WATCH_TEST(c) do {                                                      \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return -1; } \
  } while(0)

  WATCH_TEST( watch );
  WATCH_TEST( watch->magic==FD_DRAGON_WATCH_MAGIC );
  WATCH_TEST( watch->key_max && watch->key_max<=FD_DRAGON_WATCH_KEY_MAX );
  WATCH_TEST( watch->cursor<watch->key_max );
  WATCH_TEST( watch_pool_max( watch->pool )==watch->key_max );
  WATCH_TEST( !watch_map_verify( watch->map, watch->key_max, watch->pool ) );

  /* Live bits and the open sets that have a bit are in one to one
     correspondence */

  WATCH_TEST( !( watch->live & watch->retired ) );
  ulong live_cnt = 0UL;
  for( ulong set=0UL; set<FD_DRAGON_WATCH_SET_MAX; set++ ) {
    if( !( ( watch->open>>set )&1UL ) ) continue;
    ulong bit = watch->bit_of_set[ set ];
    if( bit==WATCH_BIT_NONE ) continue;
    live_cnt++;
    WATCH_TEST( bit<FD_DRAGON_WATCH_SET_MAX );
    WATCH_TEST( ( watch->live>>bit )&1UL );
    WATCH_TEST( watch->set_of_bit[ bit ]==set );
  }
  WATCH_TEST( live_cnt==(ulong)fd_ulong_popcnt( watch->live ) );

  /* Every stored address is reachable and holds only bits in use */

  ulong bit_key_cnt[ FD_DRAGON_WATCH_SET_MAX ] = {0};
  ulong used = 0UL;
  for( ulong i=0UL; i<watch->key_max; i++ ) {
    watch_ele_t const * ele = watch->pool + i;
    if( !ele->mask ) continue;
    used++;
    WATCH_TEST( !( ele->mask & ~( watch->live | watch->retired ) ) );
    WATCH_TEST( !( ele->pend & ~ele->mask ) );
    WATCH_TEST( watch_map_ele_query_const( watch->map, &ele->key, NULL, watch->pool )==ele );
    for( ulong m=ele->mask; m; m=fd_ulong_pop_lsb( m ) ) bit_key_cnt[ fd_ulong_find_lsb( m ) ]++;
  }
  WATCH_TEST( used==watch_pool_used( watch->pool ) );

  for( ulong bit=0UL; bit<FD_DRAGON_WATCH_SET_MAX; bit++ ) {
    WATCH_TEST( bit_key_cnt[ bit ]==watch->bit_key_cnt[ bit ] );
    if( ( watch->retired>>bit )&1UL ) WATCH_TEST( bit_key_cnt[ bit ] );
  }

# undef WATCH_TEST

  return 0;
}

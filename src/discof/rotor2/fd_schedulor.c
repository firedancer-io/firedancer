#include "fd_schedulor.h"

#define FD_SCHEDULOR_MAGIC (0xf17eda2ce75c4ed0UL) /* firedancer schedulor v1 */

/* A task is a pending check of one slot version, keyed by {slot,
   block_id}.  A task exists iff it is queued: it is acquired from the
   pool on schedule and released on pop or cancel. */

struct task_key {
  ulong     slot;
  fd_hash_t block_id;
};
typedef struct task_key task_key_t;
FD_STATIC_ASSERT( sizeof(task_key_t)==40UL, task_key_sz );

struct task {
  task_key_t key;
  long       timeout; /* quantized */

  ulong next;  /* pool, map */
  ulong parent; ulong left; ulong right; ulong prio; ulong treap_next; ulong treap_prev;
};
typedef struct task task_t;

#define POOL_NAME pool
#define POOL_T    task_t
#define POOL_NEXT next
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               map
#define MAP_ELE_T              task_t
#define MAP_KEY_T              task_key_t
#define MAP_KEY                key
#define MAP_NEXT               next
#define MAP_KEY_EQ(k0,k1)      ( (k0)->slot==(k1)->slot && !memcmp( (k0)->block_id.uc, (k1)->block_id.uc, sizeof(fd_hash_t) ) )
#define MAP_KEY_HASH(key,seed) fd_hash( (seed), (key), sizeof(task_key_t) )
#include "../../util/tmpl/fd_map_chain.c"

#define TREAP_NAME               treap
#define TREAP_T                  task_t
#define TREAP_QUERY_T            long
#define TREAP_CMP(q,e)           ( ((q)>(e)->timeout) - ((q)<(e)->timeout) )
#define TREAP_LT(e0,e1)          ( (e0)->timeout< (e1)->timeout || ( (e0)->timeout==(e1)->timeout && (e0)->key.slot<(e1)->key.slot ) )
#define TREAP_IDX_T              ulong
#define TREAP_NEXT               treap_next
#define TREAP_PREV               treap_prev
#define TREAP_OPTIMIZE_ITERATION 1
#include "../../util/tmpl/fd_treap.c"

struct fd_schedulor {
  ulong     task_max;
  task_t *  pool;  /* task storage */
  map_t *   map;   /* queued tasks queryable by {slot, block_id} */
  treap_t * treap; /* queued tasks by (timeout, slot) */
  ulong     magic;
};

FD_FN_CONST ulong
fd_schedulor_align( void ) {
  return 128UL;
}

FD_FN_CONST ulong
fd_schedulor_footprint( ulong slotv_max ) {
  ulong task_max = 2UL*slotv_max;
  if( FD_UNLIKELY( !slotv_max || !pool_footprint( task_max ) || !treap_footprint( task_max ) ) ) return 0UL;
  ulong chain_cnt = map_chain_cnt_est( task_max );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_schedulor_t), sizeof(fd_schedulor_t)      );
  l = FD_LAYOUT_APPEND( l, pool_align(),            pool_footprint ( task_max  ) );
  l = FD_LAYOUT_APPEND( l, map_align(),             map_footprint  ( chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, treap_align(),           treap_footprint( task_max  ) );
  return FD_LAYOUT_FINI( l, fd_schedulor_align() );
}

void *
fd_schedulor_new( void * mem,
                  ulong  slotv_max,
                  ulong  seed ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_schedulor_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  ulong footprint = fd_schedulor_footprint( slotv_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad slotv_max %lu", slotv_max ));
    return NULL;
  }

  fd_memset( mem, 0, footprint );

  ulong task_max  = 2UL*slotv_max;
  ulong chain_cnt = map_chain_cnt_est( task_max );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_schedulor_t * self  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_schedulor_t), sizeof(fd_schedulor_t)      );
  void *           pool  = FD_SCRATCH_ALLOC_APPEND( l, pool_align(),            pool_footprint ( task_max  ) );
  void *           map   = FD_SCRATCH_ALLOC_APPEND( l, map_align(),             map_footprint  ( chain_cnt ) );
  void *           treap = FD_SCRATCH_ALLOC_APPEND( l, treap_align(),           treap_footprint( task_max  ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_schedulor_align() )==(ulong)mem+footprint );

  self->task_max = task_max;
  self->pool     = pool_join ( pool_new ( pool,  task_max        ) );
  self->map      = map_join  ( map_new  ( map,   chain_cnt, seed ) );
  self->treap    = treap_join( treap_new( treap, task_max        ) );
  treap_seed( self->pool, task_max, seed ^ 0x5eedUL );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( self->magic ) = FD_SCHEDULOR_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_schedulor_t *
fd_schedulor_join( void * mem ) {
  fd_schedulor_t * self = (fd_schedulor_t *)mem;
  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( self->magic!=FD_SCHEDULOR_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  return self;
}

void *
fd_schedulor_leave( fd_schedulor_t const * self ) {
  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL schedulor" ));
    return NULL;
  }
  return (void *)self;
}

void *
fd_schedulor_delete( void * mem ) {
  fd_schedulor_t * self = (fd_schedulor_t *)mem;
  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( self->magic!=FD_SCHEDULOR_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  FD_COMPILER_MFENCE();
  FD_VOLATILE( self->magic ) = 0UL;
  FD_COMPILER_MFENCE();
  return mem;
}

/* Internal helpers */

static inline long
quantize( long timeout ) {
  return timeout - ( timeout % FD_SCHEDULOR_QUANTUM_NS );
}

static inline task_key_t
task_key( ulong slot, fd_hash_t const * block_id ) {
  task_key_t key = { .slot = slot, .block_id = *block_id };
  return key;
}

/* task_release removes a queued task from the map and treap and returns
   it to the pool. */

static void
task_release( fd_schedulor_t * self,
              task_t *         task ) {
  treap_ele_remove( self->treap, task, self->pool );
  map_ele_remove( self->map, &task->key, NULL, self->pool );
  pool_ele_release( self->pool, task );
}

/* schedule asks for version key to be checked at timeout. If the key
   is not queued a task is created. If queued the timeout is pulled
   earlier. */

static void
schedule( fd_schedulor_t *   self,
          task_key_t const * key,
          long               timeout ) {
  timeout = quantize( timeout );
  task_t * task = map_ele_query( self->map, key, NULL, self->pool );
  if( FD_LIKELY( task ) ) {
    if( FD_LIKELY( timeout>=task->timeout ) ) return;
    treap_ele_remove( self->treap, task, self->pool );
  } else {
    if( FD_UNLIKELY( !pool_free( self->pool ) ) ) FD_LOG_CRIT(( "schedulor task pool full (%lu tasks)", self->task_max ));
    task      = pool_ele_acquire( self->pool );
    task->key = *key;
    map_ele_insert( self->map, task, self->pool );
  }
  task->timeout = timeout;
  treap_ele_insert( self->treap, task, self->pool );
}

/* cancel drops version key's task if queued. */

static void
cancel( fd_schedulor_t *   self,
        task_key_t const * key ) {
  task_t * task = map_ele_query( self->map, key, NULL, self->pool );
  if( FD_UNLIKELY( !task ) ) return;
  task_release( self, task );
}

/* Public API */

void
fd_schedulor_block_insert( fd_schedulor_t *  self,
                           ulong             slot,
                           fd_hash_t const * block_id,
                           long              timeout ) {
  task_key_t key = task_key( slot, block_id );
  schedule( self, &key, timeout );
}

int
fd_schedulor_block_query( fd_schedulor_t const * self,
                          ulong                  slot,
                          fd_hash_t const *      block_id ) {
  task_key_t key = task_key( slot, block_id );
  return !!map_ele_query_const( self->map, &key, NULL, self->pool );
}

void
fd_schedulor_block_remove( fd_schedulor_t *  self,
                           ulong             slot,
                           fd_hash_t const * block_id ) {
  task_key_t key = task_key( slot, block_id );
  cancel( self, &key );
}

int
fd_schedulor_block_pop( fd_schedulor_t * self,
                        long             now,
                        ulong *          slot,
                        fd_hash_t *      block_id ) {
  treap_fwd_iter_t iter = treap_fwd_iter_init( self->treap, self->pool );
  if( FD_LIKELY( treap_fwd_iter_done( iter ) ) ) return 0;
  task_t * task = treap_fwd_iter_ele( iter, self->pool );
  if( FD_LIKELY( task->timeout>now ) ) return 0;

  *slot     = task->key.slot;
  *block_id = task->key.block_id;
  task_release( self, task );
  return 1;
}

void
fd_schedulor_publish( fd_schedulor_t * self,
                      ulong            root ) {
  treap_fwd_iter_t iter = treap_fwd_iter_init( self->treap, self->pool );
  while( !treap_fwd_iter_done( iter ) ) {
    task_t * task = treap_fwd_iter_ele( iter, self->pool );
    iter = treap_fwd_iter_next( iter, self->pool ); /* before release */
    if( task->key.slot<=root ) task_release( self, task );
  }
}

/* Introspection */

ulong
fd_schedulor_queued_cnt( fd_schedulor_t const * self ) {
  return treap_ele_cnt( self->treap );
}

long
fd_schedulor_next_timeout( fd_schedulor_t const * self ) {
  treap_fwd_iter_t iter = treap_fwd_iter_init( self->treap, self->pool );
  if( FD_UNLIKELY( treap_fwd_iter_done( iter ) ) ) return LONG_MAX;
  return treap_fwd_iter_ele_const( iter, self->pool )->timeout;
}

int
fd_schedulor_verify( fd_schedulor_t const * self ) {
# define FAIL( msg ) do { FD_LOG_WARNING(( "fd_schedulor_verify: %s", msg )); return -1; } while(0)

  if( FD_UNLIKELY( !self                                                    ) ) FAIL( "NULL schedulor" );
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)self, fd_schedulor_align() ) ) ) FAIL( "misaligned schedulor" );
  if( FD_UNLIKELY( self->magic!=FD_SCHEDULOR_MAGIC                          ) ) FAIL( "bad magic" );

  task_t const *  pool  = self->pool;
  map_t const *   map   = self->map;
  treap_t const * treap = self->treap;

  if( FD_UNLIKELY( map_verify  ( map, self->task_max, pool )==-1 ) ) FAIL( "map corrupted" );
  if( FD_UNLIKELY( treap_verify( treap, pool )==-1             ) ) FAIL( "treap corrupted" );

  /* every pooled task is in the map and the treap */

  if( FD_UNLIKELY( pool_used( pool )!=treap_ele_cnt( treap ) ) ) FAIL( "pool used does not match treap count" );

  task_t const * prev = NULL;
  for( treap_fwd_iter_t iter = treap_fwd_iter_init( treap, pool );
                        !treap_fwd_iter_done( iter );
                        iter = treap_fwd_iter_next( iter, pool ) ) {
    task_t const * task = treap_fwd_iter_ele_const( iter, pool );
    if( FD_UNLIKELY( task->timeout!=quantize( task->timeout )                  ) ) FAIL( "queued task timeout not quantized" );
    if( FD_UNLIKELY( map_ele_query_const( map, &task->key, NULL, pool )!=task    ) ) FAIL( "treap task not found in map" );
    /* non-decreasing: two versions of one slot may share a timeout */
    if( FD_UNLIKELY( prev && ( task->timeout<prev->timeout || ( task->timeout==prev->timeout && task->key.slot<prev->key.slot ) ) ) ) FAIL( "treap out of (timeout, slot) order" );
    prev = task;
  }
  return 0;

# undef FAIL
}

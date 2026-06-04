#include "fd_fwd_confirmed.h"
#include "../../flamenco/fd_flamenco_base.h"

struct confirmed {
  fd_hash_t block_id;
  ulong     next;
  struct {
    ulong next;
    ulong prev;
  } dlist;
};
typedef struct confirmed confirmed_t;

#define MAP_NAME               confirmed_map
#define MAP_ELE_T              confirmed_t
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY                block_id
#define MAP_NEXT               next
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1), sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t)))
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME               confirmed_dlist
#define DLIST_ELE_T              confirmed_t
#define DLIST_NEXT               dlist.next
#define DLIST_PREV               dlist.prev
#include "../../util/tmpl/fd_dlist.c"

#define POOL_NAME               confirmed_pool
#define POOL_T                  confirmed_t
#include "../../util/tmpl/fd_pool.c"

struct fd_fwd_confirmed {
  confirmed_map_t   * map;
  confirmed_dlist_t * dlist;
  confirmed_t       * pool;
};

ulong
fd_fwd_confirmed_align( void ) {
  return 128UL;
}

ulong
fd_fwd_confirmed_footprint( ulong max ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_fwd_confirmed_align(), sizeof(fd_fwd_confirmed_t) );
  l = FD_LAYOUT_APPEND( l, confirmed_map_align(),   confirmed_map_footprint( max ) );
  l = FD_LAYOUT_APPEND( l, confirmed_dlist_align(), confirmed_dlist_footprint() );
  l = FD_LAYOUT_APPEND( l, confirmed_pool_align(),  confirmed_pool_footprint( max ) );
  return FD_LAYOUT_FINI( l, fd_fwd_confirmed_align() );
}

void *
fd_fwd_confirmed_new( void * shmem,
                      ulong  max ) {
  ulong footprint = fd_fwd_confirmed_footprint( max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad max (%lu)", max ));
    return NULL;
  }
  fd_memset( shmem, 0, footprint );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_fwd_confirmed_t * buf = FD_SCRATCH_ALLOC_APPEND( l, fd_fwd_confirmed_align(), sizeof(fd_fwd_confirmed_t) );
  void * map_mem   = FD_SCRATCH_ALLOC_APPEND( l, confirmed_map_align(),   confirmed_map_footprint( max ) );
  void * dlist_mem = FD_SCRATCH_ALLOC_APPEND( l, confirmed_dlist_align(), confirmed_dlist_footprint() );
  void * pool_mem  = FD_SCRATCH_ALLOC_APPEND( l, confirmed_pool_align(),  confirmed_pool_footprint( max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_fwd_confirmed_align() ) == (ulong)shmem + footprint );

  buf->map   = confirmed_map_new  ( map_mem,   max, 0UL );
  buf->dlist = confirmed_dlist_new( dlist_mem           );
  buf->pool  = confirmed_pool_new ( pool_mem,  max      );

  return buf;
}

fd_fwd_confirmed_t *
fd_fwd_confirmed_join( void * shmem ) {
  fd_fwd_confirmed_t * buf = (fd_fwd_confirmed_t *)shmem;
  buf->map   = confirmed_map_join  ( buf->map   );
  buf->dlist = confirmed_dlist_join( buf->dlist );
  buf->pool  = confirmed_pool_join ( buf->pool  );
  return buf;
}

void
fd_fwd_confirmed_insert( fd_fwd_confirmed_t * buf,
                         fd_hash_t const *    block_id ) {
  if( FD_UNLIKELY( !confirmed_pool_free( buf->pool ) ) ) {
    confirmed_t * oldest = confirmed_dlist_ele_peek_head( buf->dlist, buf->pool );
    confirmed_map_ele_remove  ( buf->map,   &oldest->block_id, NULL, buf->pool );
    confirmed_dlist_ele_remove( buf->dlist, oldest,                   buf->pool );
    confirmed_pool_ele_release( buf->pool,  oldest );
  }

  confirmed_t * ele = confirmed_pool_ele_acquire( buf->pool );
  ele->block_id = *block_id;
  confirmed_map_ele_insert     ( buf->map,   ele, buf->pool );
  confirmed_dlist_ele_push_tail( buf->dlist, ele, buf->pool );
}

int
fd_fwd_confirmed_remove( fd_fwd_confirmed_t * buf,
                         fd_hash_t const *    block_id ) {
  confirmed_t * ele = confirmed_map_ele_query( buf->map, block_id, NULL, buf->pool );
  if( FD_LIKELY( !ele ) ) return 0;
  confirmed_map_ele_remove  ( buf->map,   &ele->block_id, NULL, buf->pool );
  confirmed_dlist_ele_remove( buf->dlist, ele,                   buf->pool );
  confirmed_pool_ele_release( buf->pool,  ele );
  return 1;
}

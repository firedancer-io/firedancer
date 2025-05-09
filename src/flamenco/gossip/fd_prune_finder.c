#include "fd_prune_finder.h"

struct pubkey_private {
  uchar b[ 32UL ];
};

typedef struct pubkey_private pubkey_private_t;

struct fd_prune_origin {
  pubkey_private_t identity_pubkey;

  ulong num_upserts;

  ulong pool_next;

  ulong map_next;
  ulong map_prev;

  ulong lru_prev;
  ulong lru_next;
};

typedef struct fd_prune_origin fd_prune_origin_t;

#define POOL_NAME pool
#define POOL_NEXT pool_next
#define POOL_T    fd_prune_origin_t
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME  lru_list
#define DLIST_ELE_T fd_prune_origin_t
#define DLIST_PREV  lru_prev
#define DLIST_NEXT  lru_next
#include "../../util/tmpl/fd_dlist.c"

#define MAP_NAME  origin_map
#define MAP_ELE_T fd_prune_origin_t
#define MAP_KEY_T pubkey_private_t
#define MAP_KEY   identity_pubkey
#define MAP_IDX_T ulong
#define MAP_NEXT  map_next
#define MAP_PREV  map_prev
#define MAP_KEY_HASH(k,s) ((s) ^ fd_ulong_load_8( (k)->b ))
#define MAP_KEY_EQ(k0,k1) (!memcmp((k0)->b, (k1)->b, 32UL))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

struct fd_prune_finder_private {
  fd_prune_origin_t * pool;

  origin_map_t * origins;
  lru_list_t *   lru;
};

void
fd_prune_finder_record( fd_prune_finder_t * pf,
                        uchar const *       origin_pubkey,
                        uchar const *       relayer_pubkey,
                        ulong               num_dups ) {
  fd_prune_origin_t * origin = origin_map_ele_query( pf->origins, fd_type_pun_const( origin_pubkey ), NULL, pf->pool );

  if( FD_UNLIKELY( !origin ) ) {
    if( FD_LIKELY( fd_pool_free( pf->pool ) ) ) {
      origin = pool_ele_acquire( pf->pool );
    } else {
      origin = lru_list_ele_pop_head( pf->lru, pf->pool );
    }

    origin->num_upserts = 0UL;
    fd_memcpy( origin->identity_pubkey.b, origin_pubkey, 32UL );

    origin_map_ele_insert( pf->origins, origin, pf->pool );
    lru_list_ele_push_tail( pf->lru, origin, pf->pool );
  } else {
    /* Move to back of the LRU list */
    lru_list_ele_remove( pf->lru, origin, pf->pool );
    lru_list_ele_push_tail( pf->lru, origin, pf->pool );
  }

  if( FD_UNLIKELY( !num_dups ) ) origin->num_upserts++;

  if( FD_LIKELY( num_dups<2UL ) ) {

  }
}

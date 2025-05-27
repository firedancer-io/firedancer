#include "fd_dns_cache.h"
#include "fd_dns_cache_private.h"

/* Generate map implementation */

#define MAP_NAME               fd_dns_cache_map
#define MAP_ELE_T              fd_dns_cache_ele_t
#define MAP_KEY_EQ_IS_SLOW     1
#define MAP_MEMOIZE            1
#define MAP_IMPL_STYLE         2
#define MAP_IDX_T              uint
#define MAP_KEY_T              fd_dns_cache_key_t
#define MAP_KEY_EQ(k1,k2)      fd_dns_cache_key_eq( (k1), (k2) )
#define MAP_KEY_HASH(key,seed) defined in header
#include "../../util/tmpl/fd_map_chain_para.c"

/* Begin implementation */

FD_FN_CONST ulong
fd_dns_cache_align( void ) {
  return FD_DNS_CACHE_ALIGN;
}

FD_FN_CONST ulong
fd_dns_cache_footprint( ulong domains_max,
                        ulong addrs_max ) {
  if( FD_UNLIKELY( !domains_max || domains_max>INT_MAX ) ) return 0UL;
  if( FD_UNLIKELY( !addrs_max   || addrs_max  >INT_MAX ) ) return 0UL;
  ulong chain_cnt_est = fd_dns_cache_map_chain_cnt_est( domains_max );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_dns_cache_t),        sizeof(fd_dns_cache_t)                          );
  l = FD_LAYOUT_APPEND( l, fd_dns_cache_map_align(),       fd_dns_cache_map_footprint( chain_cnt_est )     );
  l = FD_LAYOUT_APPEND( l, fd_dns_cache_name_pool_align(), fd_dns_cache_name_pool_footprint( domains_max ) );
  l = FD_LAYOUT_APPEND( l, fd_dns_cache_addr_pool_align(), fd_dns_cache_addr_pool_footprint( addrs_max   ) );
  return FD_LAYOUT_FINI( l, FD_DNS_CACHE_ALIGN );
}

fd_dns_cache_t *
fd_dns_cache_new( void * shmem,
                  ulong  domains_max,
                  ulong  addrs_max,
                  ulong  hash_seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL dns_cache memory" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, FD_DNS_CACHE_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned dns_cache memory" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_dns_cache_t * cache       = FD_SCRATCH_ALLOC_APPEND( l, fd_dns_cache_align(),           sizeof(fd_dns_cache_t)                          );
  void *           shmap       = FD_SCRATCH_ALLOC_APPEND( l, fd_dns_cache_map_align(),       fd_dns_cache_map_footprint( domains_max )       );
  void *           shname_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_dns_cache_name_pool_align(), fd_dns_cache_name_pool_footprint( domains_max ) );
  void *           shaddr_pool = FD_SCRATCH_ALLOC_APPEND( l, fd_dns_cache_addr_pool_align(), fd_dns_cache_addr_pool_footprint( addrs_max )   );
  FD_SCRATCH_ALLOC_FINI( l, FD_DNS_CACHE_ALIGN );
  if( FD_UNLIKELY( (ulong)cache != (ulong)shmem ) ) {
    FD_LOG_CRIT(( "Alignment failure. This is a code bug." )); /* unreachable */
  }

  void * map = fd_dns_cache_map_new( shmap, domains_max, hash_seed );
  if( FD_UNLIKELY( !map ) ) {
    FD_LOG_WARNING(( "fd_dns_cache_map_new failed" ));
    return NULL;
  }
  void * name_pool = fd_dns_cache_name_pool_new( shname_pool, addrs_max );
  if( FD_UNLIKELY( !name_pool ) ) {
    FD_LOG_WARNING(( "fd_dns_cache_name_pool_new failed" ));
    return NULL;
  }
  void * addr_pool = fd_dns_cache_addr_pool_new( shaddr_pool, addrs_max );
  if( FD_UNLIKELY( !addr_pool ) ) {
    FD_LOG_WARNING(( "fd_dns_cache_addr_pool_new failed" ));
    return NULL;
  }

  *cache = (fd_dns_cache_t) {
    .map_off       = (ulong)map       - (ulong)cache,
    .name_pool_off = (ulong)name_pool - (ulong)cache,
    .addr_pool_off = (ulong)addr_pool - (ulong)cache,
  };

  FD_COMPILER_MFENCE();
  FD_VOLATILE( cache->magic ) = FD_DNS_CACHE_MAGIC;
  FD_COMPILER_MFENCE();

  return cache;
}

fd_dns_cache_join_t *
fd_dns_cache_join( fd_dns_cache_t *      shcache,
                   fd_dns_cache_join_t * ljoin ) {

  if( FD_UNLIKELY( !shcache ) ) {
    FD_LOG_WARNING(( "NULL dns_cache" ));
    return NULL;
  }
  if( FD_UNLIKELY( !ljoin ) ) {
    FD_LOG_WARNING(( "NULL dns_cache_join" ));
    return NULL;
  }
  if( FD_UNLIKELY( shcache->magic != FD_DNS_CACHE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic (corrupt dns_cache?)" ));
    return NULL;
  }

  /* Join sub data structures.  Fail non-gracefully if a join to any of
     them fails, as that indicates memory corruption or logic bugs. */

  memset( ljoin, 0, sizeof(fd_dns_cache_join_t) );

  void * shmap       = (void *)( (ulong)shcache + shcache->map_off       );
  void * shname_pool = (void *)( (ulong)shcache + shcache->name_pool_off );
  void * shaddr_pool = (void *)( (ulong)shcache + shcache->addr_pool_off );

  fd_dns_cache_ele_t * name_pool = fd_dns_cache_name_pool_join( shname_pool );
  if( FD_UNLIKELY( !name_pool ) ) {
    FD_LOG_CRIT(( "fd_dns_cache_name_pool_join failed (memory corruption?)" ));
  }
  fd_dns_cache_addr_t * addr_pool = fd_dns_cache_addr_pool_join( shaddr_pool );
  if( FD_UNLIKELY( !addr_pool ) ) {
    FD_LOG_CRIT(( "fd_dns_cache_addr_pool_join faile (memory corruption?)" ));
  }
  fd_dns_cache_map_t * map = fd_dns_cache_map_join( ljoin->map, shmap, name_pool, fd_dns_cache_name_pool_max( name_pool ) );
  if( FD_UNLIKELY( !map ) ) {
    FD_LOG_CRIT(( "fd_dns_cache_map_join faile (memory corruption?)" ));
  }

  /* Success */

  ljoin->name_pool = name_pool;
  ljoin->addr_pool = addr_pool;
  return ljoin;
}

void *
fd_dns_cache_leave( fd_dns_cache_join_t * join ) {
  if( FD_UNLIKELY( !join ) ) {
    FD_LOG_WARNING(( "NULL dns_cache_join" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_dns_cache_map_leave( join->map ) ) ) {
    FD_LOG_CRIT(( "fd_dns_cache_map_leave failed (memory corruption?)" ));
  }
  if( FD_UNLIKELY( !fd_dns_cache_name_pool_leave( join->name_pool ) ) ) {
    FD_LOG_CRIT(( "fd_dns_cache_name_pool_leave failed (memory corruption?)" ));
  }
  if( FD_UNLIKELY( !fd_dns_cache_addr_pool_leave( join->addr_pool ) ) ) {
    FD_LOG_CRIT(( "fd_dns_cache_addr_pool_leave failed (memory corruption?)" ));
  }
  memset( join, 0, sizeof(fd_dns_cache_join_t) );
  return join;
}

void *
fd_dns_cache_delete( fd_dns_cache_t * shcache ) {
  if( FD_UNLIKELY( !shcache ) ) {
    FD_LOG_WARNING(( "NULL dns_cache pointer" ));
    return NULL;
  }
  if( FD_UNLIKELY( shcache->magic != FD_DNS_CACHE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic (corrupt dns_cache?)" ));
    return NULL;
  }

  void * shmap       = (void *)( (ulong)shcache + shcache->map_off       );
  void * shname_pool = (void *)( (ulong)shcache + shcache->name_pool_off );
  void * shaddr_pool = (void *)( (ulong)shcache + shcache->addr_pool_off );

  if( FD_UNLIKELY( !fd_dns_cache_map_delete( shmap ) ) ) {
    FD_LOG_CRIT(( "fd_dns_cache_map_delete failed (memory corruption?)" ));
  }
  if( FD_UNLIKELY( !fd_dns_cache_name_pool_delete( shname_pool ) ) ) {
    FD_LOG_CRIT(( "fd_dns_cache_name_pool_delete failed (memory corruption?)" ));
  }
  if( FD_UNLIKELY( !fd_dns_cache_addr_pool_delete( shaddr_pool ) ) ) {
    FD_LOG_CRIT(( "fd_dns_cache_addr_pool_delete failed (memory corruption?)" ));
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( shcache->magic ) = 0UL;
  FD_COMPILER_MFENCE();
  return shcache;
}

static void
fd_dns_cache_remove_addresses(
    fd_dns_cache_join_t *  ljoin,
    fd_dns_cache_ele_t *   ele
) {
  while( !fd_dns_cache_addr_list_is_empty( ele->addr_list, ljoin->addr_pool ) ) {
    ulong addr_idx = fd_dns_cache_addr_list_idx_pop_tail( ele->addr_list, ljoin->addr_pool );
    ljoin->addr_pool[ addr_idx ].prev = UINT_MAX;
    fd_dns_cache_addr_pool_idx_release( ljoin->addr_pool, addr_idx );
  }
}

fd_dns_cache_ele_t *
fd_dns_cache_put(
    fd_dns_cache_join_t *  ljoin,
    char const *           fqdn,
    ulong                  fqdn_len,  /* in [1,255] */
    long                   resolve_time_nanos,
    uchar *                ip6_addr_tbl,
    ulong                  ip6_addr_cnt
) {
  if( FD_UNLIKELY( !fqdn_len || fqdn_len>255 ) ) return NULL;
  fd_dns_cache_key_t key = fd_dns_cache_key( fqdn, fqdn_len );

  fd_dns_cache_ele_t * retval = NULL;

  /* FIXME hack to avoid alloca */
  struct {
    fd_dns_cache_map_txn_t txn;
    fd_dns_cache_map_txn_private_info_t info[1];
  } txn_mem;
  fd_dns_cache_map_txn_t * txn = fd_dns_cache_map_txn_init( &txn_mem, ljoin->map, 1UL );
  if( FD_UNLIKELY( !txn ) ) FD_LOG_CRIT(( "fd_dns_cache_map_txn_init failed.  This is a bug." ));
  if( FD_UNLIKELY( fd_dns_cache_map_txn_add( txn, &key, 1 )!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_dns_cache_map_txn_add failed.  This is a bug." ));

  if( FD_UNLIKELY( fd_dns_cache_map_txn_try( txn, FD_MAP_FLAG_BLOCKING ) )!=FD_MAP_SUCCESS ) {
    FD_LOG_WARNING(( "fd_dns_cache_map_txn_try failed.  This is a bug." ));
    goto fini;
  }

  fd_dns_cache_map_query_t query[1] = {0};
  fd_dns_cache_ele_t * ele = NULL;
  if( FD_UNLIKELY( fd_dns_cache_map_txn_query( ljoin->map, &key, NULL, query, 0 )==FD_MAP_SUCCESS ) ) {

    /* Drop address objects of domain name object */
    ele = query->ele;
    fd_dns_cache_remove_addresses( ljoin, ele );

  } else {

    /* Allocate a domain name object */
    if( FD_UNLIKELY( fd_dns_cache_name_pool_free( ljoin->name_pool )==0 ) ) goto fini;
    ele = fd_dns_cache_name_pool_ele_acquire( ljoin->name_pool );
    memset( ele, 0, sizeof(fd_dns_cache_ele_t) );
    ele->key = key;
    fd_dns_cache_map_txn_insert( ljoin->map, ele ); /* infallible */
    /* Assumes the rest below is infallible (otherwise ele would leak) */

  }

  ele->resolve_time_nanos = resolve_time_nanos;

  /* Allocate address objects and construct a linked list */
  fd_dns_cache_addr_list_t * list = fd_dns_cache_addr_list_join( fd_dns_cache_addr_list_new( ele->addr_list ) );
  ip6_addr_cnt = fd_ulong_min( ip6_addr_cnt, fd_dns_cache_addr_pool_free( ljoin->addr_pool ) );
  while( ip6_addr_cnt ) {
    ulong                 addr_idx = fd_dns_cache_addr_pool_idx_acquire( ljoin->addr_pool );
    fd_dns_cache_addr_t * addr     = ljoin->addr_pool + addr_idx;

    memset( addr, 0, sizeof(fd_dns_cache_addr_t) );
    fd_memcpy( addr->ip6, ip6_addr_tbl, 16UL );
    fd_dns_cache_addr_list_idx_push_tail( list, addr_idx, ljoin->addr_pool );

    ip6_addr_tbl += 16UL;
    ip6_addr_cnt--;
  }
  fd_dns_cache_addr_list_leave( list );

  retval = ele; /* success */

fini:
  fd_dns_cache_map_txn_test( txn );
  fd_dns_cache_map_txn_fini( txn );
  return retval;
}

void
fd_dns_cache_remove(
    fd_dns_cache_join_t *  ljoin,
    char const *           fqdn,
    ulong                  fqdn_len  /* in [1,255] */
) {
  if( FD_UNLIKELY( !fqdn_len || fqdn_len>255 ) ) return;
  fd_dns_cache_key_t key = fd_dns_cache_key( fqdn, fqdn_len );

  /* FIXME hack to avoid alloca */
  struct {
    fd_dns_cache_map_txn_t txn;
    fd_dns_cache_map_txn_private_info_t info[1];
  } txn_mem;
  fd_dns_cache_map_txn_t * txn = fd_dns_cache_map_txn_init( &txn_mem, ljoin->map, 1UL );
  if( FD_UNLIKELY( !txn ) ) FD_LOG_CRIT(( "fd_dns_cache_map_txn_init failed.  This is a bug." ));
  fd_dns_cache_map_txn_add( txn, &key, 1 );

  if( FD_UNLIKELY( fd_dns_cache_map_txn_try( txn, FD_MAP_FLAG_BLOCKING ) )!=FD_MAP_SUCCESS ) {
    FD_LOG_WARNING(( "fd_dns_cache_map_txn_try failed.  This is a bug." ));
    goto fini;
  }

  fd_dns_cache_map_query_t query[1] = {0};
  if( FD_LIKELY( fd_dns_cache_map_txn_query( ljoin->map, &key, NULL, query, 0 )==FD_MAP_SUCCESS ) ) {
    fd_dns_cache_remove_addresses( ljoin, query->ele );
    /* invalidates query */
    if( FD_UNLIKELY( fd_dns_cache_map_txn_remove( ljoin->map, &key, NULL, query, 0 )!=FD_MAP_SUCCESS ) ) {
      FD_LOG_CRIT(( "fd_dns_cache_map_txn_remove failed (memory corruption?)" ));
    }
    fd_dns_cache_name_pool_ele_release( ljoin->name_pool, query->ele );
  }

fini:
  fd_dns_cache_map_txn_test( txn );
  fd_dns_cache_map_txn_fini( txn );
}

fd_dns_cache_addr_t *
fd_dns_cache_query_start(
    fd_dns_cache_join_t *  ljoin,
    fd_dns_cache_query_t * query,
    char const *           fqdn,
    ulong                  fqdn_len
    //ulong                  memo
) {
  if( FD_UNLIKELY( !fqdn_len || fqdn_len>255 ) ) return NULL;
  memset( query, 0, sizeof(fd_dns_cache_query_t) );
  fd_dns_cache_key_t key = fd_dns_cache_key( fqdn, fqdn_len );

  /* FIXME MODIFY MAP_CHAIN_PARA TO USE MEMO (SKIPS HASH) */
  //(void)memo;

  /* FIXME consider removing this spin loop and exposing the 'try again'
     failure to the caller. */
  if( FD_UNLIKELY( fd_dns_cache_map_query_try( ljoin->map, &key, NULL, query->q, 0 )!=FD_MAP_SUCCESS ) ) return NULL;

  /* Atomically query the head of the domain name's address list. */
  uint const addr_idx = FD_VOLATILE_CONST( fd_dns_cache_map_query_ele( query->q )->addr_list->head );
  if( FD_UNLIKELY( addr_idx==UINT_MAX ) ) return NULL;

  /* Speculatively copy address data.  Note that pointer might be stray
     (but bounded within pool) or that address might be overrun at this
     point. */
  fd_dns_cache_addr_t * addr = ljoin->addr_pool + addr_idx;
  fd_memcpy( query->addr, addr, sizeof(fd_dns_cache_addr_t) );

  /* Overrun check */

  if( FD_UNLIKELY( fd_dns_cache_map_query_test( query->q )!=FD_MAP_SUCCESS ) ) return NULL;

  return query->addr;
}

fd_dns_cache_addr_t *
fd_dns_cache_query_next(
    fd_dns_cache_join_t *  ljoin,
    fd_dns_cache_query_t * query
) {
  /* Overrun check */
  if( FD_UNLIKELY( fd_dns_cache_map_query_test( query->q )!=FD_MAP_SUCCESS ) ) return NULL;

  /* Advance to next address and speculatively copy */
  uint const addr_idx = query->addr->next;
  if( FD_UNLIKELY( addr_idx==UINT_MAX ) ) return NULL;
  fd_dns_cache_addr_t * addr = ljoin->addr_pool + addr_idx;
  fd_memcpy( query->addr, addr, sizeof(fd_dns_cache_addr_t) );

  /* Overrun check */
  if( FD_UNLIKELY( fd_dns_cache_map_query_test( query->q )!=FD_MAP_SUCCESS ) ) return NULL;

  return query->addr;
}

#if FD_HAS_HOSTED

#include <netdb.h>

FD_FN_CONST char const *
fd_dns_gai_strerror( int err ) {
  switch( err ) {
  case EAI_BADFLAGS:
    return "invalid flags";
  case EAI_NONAME:
    return "name or service not known";
  case EAI_AGAIN:
    return "try again";
  case EAI_FAIL:
    return "non-recoverable failure";
# ifdef EAI_NODATA
  case EAI_NODATA:
    return "name has no usable address";
# endif
  case EAI_FAMILY:
    return "unsupported address family";
  case EAI_SOCKTYPE:
    return "unsupported socket type";
  case EAI_SERVICE:
    return "unsupported service";
  case EAI_MEMORY:
    return "out of memory";
  case EAI_SYSTEM:
    return "system error";
  case EAI_OVERFLOW:
    return "overflow";
  default:
    return "unknown";
  }
}

#endif /* FD_HAS_HOSTED */

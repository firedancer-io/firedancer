#include "fd_fib4.h"
#include "fd_fib4_private.h"
#include "../../util/net/fd_ip4.h"  /* for printing ip4 addrs */

static const fd_fib4_hop_t
fd_fib4_hop_blackhole = {
  .rtype = FD_FIB4_RTYPE_BLACKHOLE
};

FD_FN_CONST ulong
fd_fib4_align( void ) {
  return alignof(fd_fib4_t);
}

FD_FN_CONST ulong
fd_fib4_footprint( ulong route_max,
                   ulong route_peer_max ) {
  if( route_max==0 || route_max>UINT_MAX ||
      route_peer_max==0 || route_peer_max>UINT_MAX ) return 0UL;
  ulong elem_max       = fd_fib4_hmap_get_ele_max( route_peer_max   );
  ulong probe_max      = fd_fib4_hmap_get_probe_max( elem_max );
  ulong lock_cnt       = fd_fib4_hmap_get_lock_cnt( elem_max );
  ulong hmap_footprint = fd_fib4_hmap_footprint( elem_max, lock_cnt, probe_max );
  if( !hmap_footprint ) return 0UL;

  return FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,
      alignof(fd_fib4_t),            sizeof(fd_fib4_t)                     ),
      alignof(fd_fib4_key_t),        route_max*sizeof(fd_fib4_key_t)       ),
      alignof(fd_fib4_hop_t),        route_max*sizeof(fd_fib4_hop_t)       ),
      fd_fib4_hmap_align(),          hmap_footprint                        ),
      alignof(fd_fib4_hmap_entry_t), elem_max*sizeof(fd_fib4_hmap_entry_t) ),
      alignof(fd_fib4_t) );
}

void *
fd_fib4_new( void * mem,
             ulong  route_max,
             ulong  route_peer_max,
             ulong  route_peer_seed ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_fib4_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( route_max==0 || route_max>UINT_MAX ) ) {
    FD_LOG_WARNING(( "invalid route_max" ));
    return NULL;
  }
  if( FD_UNLIKELY( route_peer_max==0 || route_peer_max>UINT_MAX ) ) {
    FD_LOG_WARNING(( "invalid route_peer_max" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_fib4_t *     fib4     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fib4_t),     sizeof(fd_fib4_t)               );
  fd_fib4_key_t * keys     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fib4_key_t), route_max*sizeof(fd_fib4_key_t) );
  fd_fib4_hop_t * vals     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fib4_hop_t), route_max*sizeof(fd_fib4_hop_t) );
  ulong hmap_elem_max      = fd_fib4_hmap_get_ele_max(    route_peer_max );
  ulong hmap_probe_max     = fd_fib4_hmap_get_probe_max( hmap_elem_max  );
  ulong hmap_lock_cnt      = fd_fib4_hmap_get_lock_cnt(  hmap_elem_max  );
  ulong hmap_footprint     = fd_fib4_hmap_footprint( hmap_elem_max, hmap_lock_cnt, hmap_probe_max );
  FD_TEST( hmap_footprint );
  void * fib4_hmap_mem     = FD_SCRATCH_ALLOC_APPEND( l, fd_fib4_hmap_align(), hmap_footprint );
  void * fib4_hmap_ele_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fib4_hmap_entry_t), hmap_elem_max*sizeof(fd_fib4_hmap_entry_t) );
  FD_TEST( fib4_hmap_mem );
  FD_TEST( fib4_hmap_ele_mem );
  FD_SCRATCH_ALLOC_FINI( l, alignof(fd_fib4_t) );

  fd_memset( fib4, 0, sizeof(fd_fib4_t)               );
  fd_memset( keys, 0, route_max*sizeof(fd_fib4_key_t) );
  fd_memset( vals, 0, route_max*sizeof(fd_fib4_hop_t) );
  fd_memset( fib4_hmap_ele_mem, 0, hmap_elem_max*sizeof(fd_fib4_hmap_entry_t) );

  FD_TEST( fd_fib4_hmap_new( fib4_hmap_mem, hmap_elem_max, hmap_lock_cnt, hmap_probe_max, route_peer_seed ) );

  fib4->cnt              = 1UL;   // first route entry is 0.0.0.0/0
  fib4->max              = route_max;
  fib4->hop_off          = (ulong)vals - (ulong)fib4;
  fib4->hmap_offset      = (ulong)fib4_hmap_mem - (ulong)fib4;
  fib4->hmap_elem_offset = (ulong)fib4_hmap_ele_mem - (ulong)fib4;
  fib4->hmap_max         = route_peer_max;
  fib4->hmap_cnt         = 0;
  keys[0].prio           = UINT_MAX;
  vals[0].rtype          = FD_FIB4_RTYPE_THROW;

  return fib4;
}

fd_fib4_t *
fd_fib4_join( void * mem ) {
  return (fd_fib4_t *)mem;
}

void *
fd_fib4_leave( fd_fib4_t * fib4 ) {
  return fib4;
}

void *
fd_fib4_delete( void * mem ) {
  return mem;
}

void
fd_fib4_clear( fd_fib4_t * fib4 ) {
  fib4->cnt = 1UL;

  if( fib4->hmap_cnt==0 ) return;

  fd_fib4_hmap_t hmap[1];
  FD_TEST( fd_fib4_hmap_join( hmap, fd_fib4_hmap_mem( fib4 ), fd_fib4_hmap_ele_mem( fib4 ) ) );

  fib4->hmap_cnt = 0;
  ulong elem_max  = fd_fib4_hmap_get_ele_max( fib4->hmap_max );
  ulong probe_max = fd_fib4_hmap_get_probe_max( elem_max );
  ulong lock_cnt  = fd_fib4_hmap_get_lock_cnt( elem_max );
  ulong seed      = fd_fib4_hmap_seed( hmap );
  ulong ignored[ fd_fib4_hmap_lock_max( ) ];
  FD_TEST( fd_fib4_hmap_lock_range( hmap, 0, lock_cnt, FD_MAP_FLAG_BLOCKING, ignored )==FD_MAP_SUCCESS );
  FD_TEST( fd_fib4_hmap_new( fd_fib4_hmap_mem( fib4 ), elem_max, lock_cnt, probe_max, seed ) );
  fd_memset( fd_fib4_hmap_ele_mem( fib4 ), 0, elem_max*sizeof(fd_fib4_hmap_entry_t) );
}

FD_FN_PURE ulong
fd_fib4_max( fd_fib4_t const * fib ) {
  return fib->max;
}

FD_FN_PURE ulong
fd_fib4_peer_max( fd_fib4_t const * fib ) {
  return fib->hmap_max;
}

FD_FN_PURE ulong
fd_fib4_cnt( fd_fib4_t const * fib ) {
  return fib->cnt+fib->hmap_cnt;
}

/* fd_fib4_hmap_insert adds a new entry (key=ip4_dst, value=hop) to the fib4
   hmap. Assume the netmask for the ip4_dst entry is 32, and ip4_dst is not 0.
   The insertion to fib->hmap is blocking. Return FD_MAP_SUCCESS on success,
   FD_MAP_ERR_FULL if the hmap is full.
*/

static int
fd_fib4_hmap_insert( fd_fib4_t *     fib,
                     uint            ip4_dst,
                     fd_fib4_hop_t * hop ) {

  if( FD_UNLIKELY( fib->hmap_cnt>=fib->hmap_max ) ) return FD_MAP_ERR_FULL;

  fd_fib4_hmap_t hmap[1];
  FD_TEST( fd_fib4_hmap_join( hmap, fd_fib4_hmap_mem( fib ), fd_fib4_hmap_ele_mem( fib ) ) );

  uint key = ip4_dst;
  fd_fib4_hmap_query_t query[1];
  fd_fib4_hmap_entry_t sentinel[1];
  int err = fd_fib4_hmap_prepare( hmap, &key, sentinel, query, FD_MAP_FLAG_BLOCKING );
  if( FD_UNLIKELY( err==FD_MAP_ERR_FULL ) ) return FD_MAP_ERR_FULL;
  else if ( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_fib4_hmap_insert failed. err: %d", err ));

  fd_fib4_hmap_entry_t * ele = fd_fib4_hmap_query_ele( query );
  ele->dst_addr              = ip4_dst;
  FD_TEST( hop );
  ele->next_hop = *hop;
  fib->hmap_cnt++;

  fd_fib4_hmap_publish( query );

  return FD_MAP_SUCCESS;
}

int
fd_fib4_insert( fd_fib4_t *     fib,
                uint            ip4_dst,
                int             prefix,
                uint            prio,
                fd_fib4_hop_t * hop ) {

  if( ip4_dst!=0 && prefix==32 ) {
    if( fd_fib4_hmap_insert( fib, ip4_dst, hop )==FD_MAP_SUCCESS ) return 1;
    FD_LOG_WARNING(( "Failed to insert /32 route " FD_IP4_ADDR_FMT " into fib4 hashmap", FD_IP4_ADDR_FMT_ARGS(ip4_dst) ));
    return 0;
  }

  ulong const generation = fib->generation;

  if( FD_UNLIKELY( fib->cnt>=fib->max ) ) {
    FD_LOG_WARNING(( "Failed to insert route " FD_IP4_ADDR_FMT ", route table is full (%lu max)", FD_IP4_ADDR_FMT_ARGS(ip4_dst), fib->max ));
    return 0;
  }

  FD_COMPILER_MFENCE();
  fib->generation = generation+1UL;
  FD_COMPILER_MFENCE();

  ulong idx = fib->cnt;
  fib->cnt = idx+1UL;

  fd_fib4_key_t * key = fd_fib4_key_tbl( fib ) + idx;
  *key = (fd_fib4_key_t) {
    .addr = fd_uint_bswap( ip4_dst ),
    .mask = prefix>0 ? fd_uint_mask( 32-prefix, 31 ) : 0U,
    .prio = prio
  };
  fd_fib4_hop_t * entry = fd_fib4_hop_tbl( fib ) + idx;

  FD_COMPILER_MFENCE();
  fib->generation = generation+2UL;
  FD_COMPILER_MFENCE();

  FD_TEST( hop );
  *entry = *hop;

  return 1;
}

fd_fib4_hop_t const *
fd_fib4_lookup( fd_fib4_t const * fib,
                fd_fib4_hop_t *   out,
                uint              ip4_dst,
                ulong             flags ) {
  if( FD_UNLIKELY( flags ) ) {
    return fd_fib4_hop_tbl_const( fib ) + 0; /* dead route */
  }

  FD_TEST( out );

  if( fib->hmap_cnt>0 ) {
    fd_fib4_hmap_t hmap[1];
    FD_TEST( fd_fib4_hmap_join( hmap, fd_fib4_hmap_mem( (void *)fib ), fd_fib4_hmap_ele_mem( (void *)fib ) ) );
    uint key = ip4_dst;
    fd_fib4_hmap_query_t query[1];
    fd_fib4_hmap_entry_t sentinel[1];
    int find_err  = fd_fib4_hmap_query_try( hmap, &key, sentinel, query, 0 );
    if( find_err==FD_MAP_SUCCESS ) {
      fd_fib4_hmap_entry_t const * ele = fd_fib4_hmap_query_ele_const( query );
      fd_fib4_hop_t next_hop           = ele->next_hop;                    // speculatively save the next hop
      find_err                         = fd_fib4_hmap_query_test( query ); // test again
      if( FD_UNLIKELY( find_err ) ) {
        return &fd_fib4_hop_blackhole;
      }
      *out = next_hop;
      return out;
    } else if( FD_UNLIKELY( find_err!=FD_MAP_ERR_KEY ) ) {
      return &fd_fib4_hop_blackhole;
    }
    // Can't find a match in the fib4 hashmap. Look up in the routing table.
  }

  ip4_dst = fd_uint_bswap( ip4_dst );
  fd_fib4_key_t const * keys = fd_fib4_key_tbl_const( fib );

  ulong generation = FD_VOLATILE_CONST( fib->generation );
  FD_COMPILER_MFENCE();

  ulong best_idx  = 0UL; /* dead route */
  int   best_mask = 32;  /* least specific mask (/0) */
  ulong cnt       = fib->cnt;
  for( ulong j=0UL; j<cnt; j++ ) {
    /* FIXME consider branch variant? */
    int match         = (ip4_dst & keys[j].mask)==keys[j].addr;
    int mask_bits     = fd_uint_find_lsb_w_default( keys[j].mask, 32 );
    int more_specific = mask_bits< best_mask;
    int less_costly   = mask_bits==best_mask && keys[j].prio<keys[best_idx].prio;
    int better        = match && (more_specific || less_costly);
    if( better ) {
      best_idx  = j;
      best_mask = mask_bits;
    }
  }
  *out = fd_fib4_hop_tbl_const( fib )[ best_idx ];

  FD_COMPILER_MFENCE();
  if( FD_UNLIKELY( FD_VOLATILE_CONST( fib->generation )!=generation ) ) {
    return &fd_fib4_hop_blackhole; /* torn read */
  }
  return out;
}

#if FD_HAS_HOSTED

#include <errno.h>
#include <stdio.h>
#include "../../util/net/fd_ip4.h"

#define WRAP_PRINT(file,str) if( FD_UNLIKELY( fputs( (str), (file) )<0 ) ) return errno
#define WRAP_PRINTF(file,...) if( FD_UNLIKELY( fprintf( (file), __VA_ARGS__ )<0 ) ) return errno

static int
fd_fib4_fprintf_route( fd_fib4_key_t const * key,
                       fd_fib4_hop_t const * hop,
                       FILE *                file ) {

  switch( hop->rtype ) {
  case FD_FIB4_RTYPE_UNSPEC:
    WRAP_PRINT( file, "unspecified " );
    break;
  case FD_FIB4_RTYPE_UNICAST:
    break;
  case FD_FIB4_RTYPE_LOCAL:
    WRAP_PRINT( file, "local " );
    break;
  case FD_FIB4_RTYPE_BROADCAST:
    WRAP_PRINT( file, "broadcast " );
    break;
  case FD_FIB4_RTYPE_MULTICAST:
    WRAP_PRINT( file, "multicast " );
    break;
  case FD_FIB4_RTYPE_BLACKHOLE:
    WRAP_PRINT( file, "blackhole " );
    break;
  case FD_FIB4_RTYPE_THROW:
    WRAP_PRINT( file, "throw " );
    break;
  default:
    WRAP_PRINTF( file, "invalid (%u) ", hop->rtype );
    break;
  }

  if( key->mask==0 ) {
    WRAP_PRINT( file, "default" );
  } else {
    WRAP_PRINTF( file, FD_IP4_ADDR_FMT, FD_IP4_ADDR_FMT_ARGS( fd_uint_bswap( key->addr ) ) );
    if( key->mask!=UINT_MAX ) {
      WRAP_PRINTF( file, "/%u", 32U-(uint)fd_uint_find_lsb_w_default( key->mask, 32 ) );
    }
  }

  if( hop->ip4_gw ) {
    WRAP_PRINTF( file, " via " FD_IP4_ADDR_FMT, FD_IP4_ADDR_FMT_ARGS( hop->ip4_gw ) );
  }

  if( hop->if_idx ) {
    WRAP_PRINTF( file, " dev %u", hop->if_idx );
  }

  switch( hop->scope ) {
  case 0:
    break;
  case 200:
    WRAP_PRINT( file, " scope site" );
    break;
  case 253:
    WRAP_PRINT( file, " scope link" );
    break;
  case 254:
    WRAP_PRINT( file, " scope host" );
    break;
  default:
    WRAP_PRINTF( file, " scope %u", hop->scope );
    break;
  }

  if( hop->ip4_src ) {
    WRAP_PRINTF( file, " src " FD_IP4_ADDR_FMT, FD_IP4_ADDR_FMT_ARGS( hop->ip4_src ) );
  }

  if( key->prio ) {
    WRAP_PRINTF( file, " metric %u", key->prio );
  }

  WRAP_PRINT( file, "\n" );

  return 0;
}

int
fd_fib4_fprintf( fd_fib4_t const * fib,
                 void *            file_ ) {
  FILE * file = file_;
  fd_fib4_key_t const * key_tbl = fd_fib4_key_tbl_const( fib );
  fd_fib4_hop_t const * hop_tbl = fd_fib4_hop_tbl_const( fib );

  FD_COMPILER_MFENCE();
  ulong cnt        = fib->cnt;
  ulong generation = fib->generation;
  FD_COMPILER_MFENCE();

  for( ulong j=0UL; j<cnt; j++ ) {
    FD_COMPILER_MFENCE();
    fd_fib4_key_t key = key_tbl[j];
    fd_fib4_hop_t hop = hop_tbl[j];
    FD_COMPILER_MFENCE();
    ulong cur_gen = FD_VOLATILE_CONST( fib->generation );
    FD_COMPILER_MFENCE();
    if( FD_UNLIKELY( cur_gen!=generation ) ) {
      WRAP_PRINT( file, "=== TORN READ ===\n" );
      return 0;
    }
    fd_fib4_fprintf_route( &key, &hop, file );
  }

  /* Attempt to print the hashmap. */
  fd_fib4_hmap_t hmap[1];
  fd_fib4_hmap_entry_t * elems = fd_fib4_hmap_ele_mem( (fd_fib4_t *)fib );
  FD_TEST( fd_fib4_hmap_join( hmap, fd_fib4_hmap_mem( (fd_fib4_t *)fib ), elems ) );
  ulong elem_max  = fd_fib4_hmap_get_ele_max( fib->hmap_max );
  ulong lock_cnt  = fd_fib4_hmap_get_lock_cnt( elem_max );
  ulong ignored[ fd_fib4_hmap_lock_max( ) ];
  FD_TEST( fd_fib4_hmap_lock_range( hmap, 0, lock_cnt, FD_MAP_FLAG_BLOCKING | FD_MAP_FLAG_RDONLY, ignored )==FD_MAP_SUCCESS );

  // loop through the hmap elements
  for( ulong i=0; i<elem_max; i++ ) {
    if( elems[i].dst_addr!=0 ) {
      fd_fib4_key_t key;
      key.addr = fd_uint_bswap( elems[i].dst_addr );
      key.mask = 31;
      key.prio = 0;
      fd_fib4_fprintf_route( &key, &elems[i].next_hop, file );
    }
  }

  fd_fib4_hmap_unlock_range( hmap, 0, lock_cnt, ignored );

  return 0;
}

#undef WRAP_PRINT
#undef WRAP_PRINTF

#endif /* FD_HAS_HOSTED */

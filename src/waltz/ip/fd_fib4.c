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
  ulong hmap_footprint = fd_fib4_hmap_footprint( );
  if( !hmap_footprint ) return 0UL;

  return FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,
      alignof(fd_fib4_t),            sizeof(fd_fib4_t)                     ),
      alignof(fd_fib4_key_t),        route_max*sizeof(fd_fib4_key_t)       ),
      alignof(fd_fib4_hop_t),        route_max*sizeof(fd_fib4_hop_t)       ),
      fd_fib4_hmap_align(),          hmap_footprint                        ),
      alignof(fd_fib4_t) );
}

void *
fd_fib4_new( void * mem,
             ulong  route_max,
             ulong  route_peer_max ) {

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
  ulong  hmap_footprint     = fd_fib4_hmap_footprint(); FD_TEST( hmap_footprint );

  fd_fib4_t     * fib4          = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fib4_t),     sizeof(fd_fib4_t)               );
  fd_fib4_key_t * keys          = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fib4_key_t), route_max*sizeof(fd_fib4_key_t) );
  fd_fib4_hop_t * vals          = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fib4_hop_t), route_max*sizeof(fd_fib4_hop_t) );
  void          * fib4_hmap_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_fib4_hmap_align(),   hmap_footprint                  );
  FD_SCRATCH_ALLOC_FINI( l, alignof(fd_fib4_t) );

  fd_memset( fib4, 0, sizeof(fd_fib4_t)               );
  fd_memset( keys, 0, route_max*sizeof(fd_fib4_key_t) );
  fd_memset( vals, 0, route_max*sizeof(fd_fib4_hop_t) );

  FD_TEST( fd_fib4_hmap_new( fib4_hmap_mem ) );

  fib4->cnt              = 1UL;   // first route entry is 0.0.0.0/0
  fib4->max              = route_max;
  fib4->hop_off          = (ulong)vals - (ulong)fib4;
  fib4->hmap_offset      = (ulong)fib4_hmap_mem - (ulong)fib4;
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

  /* MAYBE switch to map_dynamic so we don't have to oversize the map */
  fd_fib4_hmap_clear( fd_fib4_hmap( fib4 ) );
  fib4->hmap_cnt = 0;
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
   Fails if the map capacity has hit configured hmap_max. Returns 0 on success,
   or 1 on failure.
*/

static int
_fd_fib4_hmap_insert( fd_fib4_t *     fib,
                     uint            ip4_dst,
                     fd_fib4_hop_t * hop ) {

  if( FD_UNLIKELY( fib->hmap_cnt>=fib->hmap_max ) ) return 1;
  FD_TEST( hop );

  fd_fib4_hmap_entry_t * map = fd_fib4_hmap( fib );
  fd_fib4_hmap_entry_t * entry = fd_fib4_hmap_insert( map, ip4_dst );
  FD_TEST( entry );

  /* TODO - atomically write hop */
  entry->next_hop = *hop;
  fib->hmap_cnt++;
  return 0;
}

int
fd_fib4_insert( fd_fib4_t *     fib,
                uint            ip4_dst,
                int             prefix,
                uint            prio,
                fd_fib4_hop_t * hop ) {

  if( ip4_dst!=0 && prefix==32 ) {
    if( _fd_fib4_hmap_insert( fib, ip4_dst, hop ) ) return 1;
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
    fd_fib4_hmap_entry_t const * map   = fd_fib4_hmap_const( fib );

    fd_fib4_hop_t entry = fd_fib4_hmap_query_atomic( map, ip4_dst );
    if( entry.rtype!=FD_FIB4_RTYPE_UNSPEC ) {
      *out = entry;
      return out;
    }
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
  /* TODO: fix this */
  // fd_fib4_hmap_t hmap[1];
  // fd_fib4_hmap_entry_t * elems = fd_fib4_hmap_ele_mem( (fd_fib4_t *)fib );
  // FD_TEST( fd_fib4_hmap_join( hmap, fd_fib4_hmap_mem( (fd_fib4_t *)fib ), elems ) );
  // ulong elem_max = fd_fib4_hmap_get_ele_max( fib->hmap_max );
  // for( ulong i=0; i<elem_max; i++ ) {
  //   ulong * lock = hmap->lock+fd_fib4_hmap_ele_lock( hmap, i );
  //   fd_fib4_hmap_entry_t e;
  //   for(;;) {
  //     ulong ver = fd_fib4_hmap_private_try( lock );
  //     e = FD_VOLATILE_CONST( elems[ i ] );
  //     if( FD_LIKELY( fd_fib4_hmap_private_test( lock, 1UL, &ver, 0UL, 1UL )==FD_MAP_SUCCESS ) ) break;
  //   }
  //   if( e.dst_addr!=0 ) {
  //     fd_fib4_key_t key;
  //     key.addr = fd_uint_bswap( e.dst_addr );
  //     key.mask = 31;
  //     key.prio = 0;
  //     fd_fib4_fprintf_route( &key, &e.next_hop, file );
  //   }
  // }

  return 0;
}

#undef WRAP_PRINT
#undef WRAP_PRINTF

#endif /* FD_HAS_HOSTED */

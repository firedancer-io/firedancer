#include "fd_fib4.h"
#include "fd_fib4_private.h"
#include "../../util/net/fd_ip4.h"  /* for printing ip4 addrs */
#define SORT_NAME sort_fib4_key
#define SORT_KEY_T fd_fib4_key_t
#define SORT_BEFORE(a,b) ( ((a).mask_bits<(b).mask_bits) || \
                         ( ((a).mask_bits==(b).mask_bits) && ((a).prio<(b).prio) ) || \
                         ( ((a).mask_bits==(b).mask_bits) && ((a).prio==(b).prio) && ((a).addr<(b).addr) ) )
#include "../../util/tmpl/fd_sort.c"

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
  int   lg_slot_cnt    = fd_fib4_hmap_est_lg_slot_cnt( route_peer_max ); FD_TEST( lg_slot_cnt>0 );
  ulong hmap_footprint = fd_fib4_hmap_footprint( lg_slot_cnt );
  if( FD_UNLIKELY( !hmap_footprint ) ) return 0UL;

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
  int   fib_lg_slot_cnt = fd_fib4_hmap_est_lg_slot_cnt( route_peer_max ); FD_TEST( fib_lg_slot_cnt>0 );
  ulong hmap_footprint  = fd_fib4_hmap_footprint( fib_lg_slot_cnt );
  if( FD_UNLIKELY( !hmap_footprint ) ) {
    FD_LOG_WARNING(( "invalid fd_fib4_hmap_footprint" ));
    return NULL;
  }

  fd_fib4_t     * fib4          = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fib4_t),     sizeof(fd_fib4_t)               );
  fd_fib4_key_t * keys          = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fib4_key_t), route_max*sizeof(fd_fib4_key_t) );
  fd_fib4_hop_t * vals          = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fib4_hop_t), route_max*sizeof(fd_fib4_hop_t) );
  void          * fib4_hmap_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_fib4_hmap_align(),   hmap_footprint                  );
  FD_SCRATCH_ALLOC_FINI( l, alignof(fd_fib4_t) );

  fd_memset( fib4, 0, sizeof(fd_fib4_t)               );
  fd_memset( keys, 0, route_max*sizeof(fd_fib4_key_t) );
  fd_memset( vals, 0, route_max*sizeof(fd_fib4_hop_t) );

  /* hmap_footprint!=0 --> lg_slot_cnt > 0  */
  fd_fib4_hmap_entry_t * map = fd_fib4_hmap_join(
                                 fd_fib4_hmap_new( fib4_hmap_mem, fib_lg_slot_cnt, route_peer_seed )
                               );
  FD_TEST( map );

  fib4->cnt              = 1UL;   // first route entry is 0.0.0.0/0
  fib4->max              = route_max;
  fib4->hop_off          = (ulong)vals - (ulong)fib4;
  fib4->hmap_join_offset = (ulong)map - (ulong)fib4;
  fib4->hmap_max         = route_peer_max;
  fib4->hmap_cnt         = 0;
  keys[0].prio           = UINT_MAX;
  vals[0].rtype          = FD_FIB4_RTYPE_THROW;
  keys[0].mask_bits      = 32;

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
   Fails if the map capacity has hit configured hmap_max. Returns 1 on success,
   or 0 on failure. Assumes we are the only writer.
*/

static inline int
fd_fib4_hmap_insert_entry( fd_fib4_t *     fib,
                           uint            ip4_dst,
                           fd_fib4_hop_t * hop ) {

  if( FD_UNLIKELY( fib->hmap_cnt>=fib->hmap_max ) ) return 0;
  FD_TEST( hop );

  fd_fib4_hmap_entry_t * map   = fd_fib4_hmap( fib );
  fd_fib4_hmap_entry_t * entry = fd_fib4_hmap_insert( map, ip4_dst );
  if( FD_UNLIKELY( !entry ) ) {
    /* update existing entry */
    entry = fd_fib4_hmap_query( map, ip4_dst, NULL );
  }
  FD_TEST( entry );

  fd_fib4_hmap_entry_t to_enter = {
    .dst_addr = ip4_dst,
    .hash     = fd_uint_hash( ip4_dst ),
    .next_hop = *hop
  };
  fd_fib4_hmap_entry_st( entry, &to_enter );

  fib->hmap_cnt++;
  return 1;
}

int
fd_fib4_insert( fd_fib4_t *     fib,
                uint            ip4_dst,
                int             prefix,
                uint            prio,
                fd_fib4_hop_t * hop ) {

  FD_TEST( hop );
  if( ip4_dst!=0 && prefix==32 ) {
    if( fd_fib4_hmap_insert_entry( fib, ip4_dst, hop ) ) return 1;
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

  ulong old_cnt = fib->cnt;
  fib->cnt      = old_cnt+1UL;

  uint mask = prefix>0 ? fd_uint_mask( 32-prefix, 31 ) : 0U;

  fd_fib4_key_t new_key = (fd_fib4_key_t){
    .addr      = fd_uint_bswap( ip4_dst ) & mask,
    .mask      = mask,
    .prio      = prio,
    .mask_bits = fd_uint_find_lsb_w_default( mask, 32 )
  };

  fd_fib4_key_t * key_tbl = fd_fib4_key_tbl( fib );
  fd_fib4_hop_t * hop_tbl = fd_fib4_hop_tbl( fib );

  /* Maintain sorted order for indices [1,cnt) by (mask_bits, prio) ascending.
     Find the intended location and shift the rest down */
  ulong n_sorted = fd_ulong_sat_sub( old_cnt, 1 ); /* number of existing sorted elems in [1,idx) */
  ulong idx; /* loc to insert new entry */
  if( FD_LIKELY( n_sorted>0UL ) ) {
    ulong rnk = sort_fib4_key_split( key_tbl + 1UL, n_sorted, new_key );
    ulong pos = 1UL + rnk;
    for( ulong dst=old_cnt; dst>pos; dst-- ) { /* n_sorted>0 <> idx>0 */
      key_tbl[ dst ] = key_tbl[ dst-1 ];
      hop_tbl[ dst ] = hop_tbl[ dst-1 ];
    }
    idx = pos;
  } else {
    idx = old_cnt;
  }

  key_tbl[ idx ] = new_key;
  hop_tbl[ idx ] = *hop;

  FD_COMPILER_MFENCE();
  fib->generation = generation+2UL;
  FD_COMPILER_MFENCE();

  return 1;
}

fd_fib4_hop_t
fd_fib4_lookup( fd_fib4_t  * fib,
                uint         ip4_dst,
                ulong        flags ) {
  if( FD_UNLIKELY( flags ) ) {
    return fd_fib4_hop_tbl_const( fib )[0]; /* dead route */
  }

  if( fib->hmap_cnt>0 ) {
    fd_fib4_hmap_entry_t * map      = fd_fib4_hmap ( fib );
    fd_fib4_hop_t          next_hop = fd_fib4_hmap_query_hop( map, ip4_dst );
    if( next_hop.rtype!=FD_FIB4_RTYPE_UNSPEC ) {
      return next_hop;
    }
  }

  ip4_dst = fd_uint_bswap( ip4_dst );
  fd_fib4_key_t const * keys = fd_fib4_key_tbl_const( fib );

  ulong generation = FD_VOLATILE_CONST( fib->generation );
  if( FD_UNLIKELY( generation&0x1UL ) ) { /* writer is mid-update */
    return fd_fib4_hop_blackhole;
  }
  FD_COMPILER_MFENCE();

  /* The table [1,cnt) is sorted by increasing mask_bits then prio.
     Return the first match, which is guaranteed to be optimal. */
  ulong cnt = fib->cnt;
  ulong j   = 1UL;
  while( j<cnt ) {
    if( (ip4_dst & keys[j].mask)==keys[j].addr ) {
      break;
    }
    j++;
  }

  ulong         idx = j==cnt ? 0UL : j;
  fd_fib4_hop_t out = fd_fib4_hop_tbl_const( fib )[ idx ];

  FD_COMPILER_MFENCE();
  if( FD_UNLIKELY( FD_VOLATILE_CONST( fib->generation )!=generation ) ) {
    return fd_fib4_hop_blackhole; /* torn read */
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
  fd_fib4_hmap_entry_t const * map = fd_fib4_hmap_const( fib );
  ulong elem_max = fd_fib4_hmap_slot_cnt( map );
  for( ulong i=0; i<elem_max; i++ ) {
    fd_fib4_hmap_entry_t e = FD_VOLATILE_CONST( map[ i ] );
    if( e.dst_addr!=0 ) {
      fd_fib4_key_t key;
      key.addr = fd_uint_bswap( e.dst_addr );
      key.mask = 31;
      key.prio = 0;
      fd_fib4_fprintf_route( &key, &e.next_hop, file );
    }
  }

  return 0;
}

#undef WRAP_PRINT
#undef WRAP_PRINTF

#endif /* FD_HAS_HOSTED */

#include "fd_fib4.h"
#include "fd_fib4_private.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"

static const fd_fib4_hop_t
fd_fib4_hop_blackhole = {
  .rtype = FD_FIB4_RTYPE_BLACKHOLE
};

FD_FN_CONST ulong
fd_fib4_align( void ) {
  return alignof(fd_fib4_t);
}

FD_FN_CONST ulong
fd_fib4_footprint( ulong route_max ) {
  if( route_max==0 || route_max>UINT_MAX ) return 0UL;
  return FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,
      alignof(fd_fib4_t),     sizeof(fd_fib4_t)               ),
      alignof(fd_fib4_key_t), route_max*sizeof(fd_fib4_key_t) ),
      alignof(fd_fib4_hop_t), route_max*sizeof(fd_fib4_hop_t) ),
      fd_fib4_hmap_align(), fd_fib4_hmap_footprint( FIB4_HMAP_ELE_MAX, FIB4_HMAP_LOCK_CNT, FIB4_HMAP_PROBE_MAX  ) ),
      alignof(fd_fib4_hmap_entry_t), FIB4_HMAP_ELE_MAX*sizeof(fd_fib4_hmap_entry_t) ),
      alignof(fd_fib4_t) );
}

void *
fd_fib4_new( void * mem,
             ulong  route_max ) {

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

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_fib4_t *     fib4     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fib4_t),     sizeof(fd_fib4_t)               );
  fd_fib4_key_t * keys     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fib4_key_t), route_max*sizeof(fd_fib4_key_t) );
  fd_fib4_hop_t * vals     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fib4_hop_t), route_max*sizeof(fd_fib4_hop_t) );
  void * fib4_hmap_mem     = FD_SCRATCH_ALLOC_APPEND( l, fd_fib4_hmap_align(), fd_fib4_hmap_footprint( FIB4_HMAP_ELE_MAX, FIB4_HMAP_LOCK_CNT, FIB4_HMAP_PROBE_MAX ) );
  void * fib4_hmap_ele_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fib4_hmap_entry_t), FIB4_HMAP_ELE_MAX*sizeof(fd_fib4_hmap_entry_t) );
  FD_TEST( fib4_hmap_mem );
  FD_TEST( fib4_hmap_ele_mem );
  FD_SCRATCH_ALLOC_FINI( l, alignof(fd_fib4_t) );

  fd_memset( fib4, 0, sizeof(fd_fib4_t)               );
  fd_memset( keys, 0, route_max*sizeof(fd_fib4_key_t) );
  fd_memset( vals, 0, route_max*sizeof(fd_fib4_hop_t) );
  fd_memset( fib4_hmap_ele_mem, 0, FIB4_HMAP_ELE_MAX*sizeof(fd_fib4_hmap_entry_t) );

  FD_TEST( fd_fib4_hmap_new( fib4_hmap_mem, FIB4_HMAP_ELE_MAX, FIB4_HMAP_LOCK_CNT, FIB4_HMAP_PROBE_MAX, FIB4_HMAP_SEED ) );

  fib4->max              = route_max;
  fib4->hop_off          = (ulong)vals - (ulong)fib4;
  fib4->hmap_offset      = (ulong)fib4_hmap_mem - (ulong)fib4;
  fib4->hmap_elem_offset = (ulong)fib4_hmap_ele_mem - (ulong)fib4;
  fib4->hmap_cnt         = 0;
  keys[0].prio           = UINT_MAX;
  vals[0].rtype          = FD_FIB4_RTYPE_THROW;

  fd_fib4_clear( fib4 );

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
  ulong ignored[ fd_fib4_hmap_lock_max( ) ];
  fd_fib4_hmap_lock_range( hmap, 0, fd_fib4_hmap_lock_cnt( hmap ), FD_MAP_FLAG_BLOCKING, ignored );
  fd_fib4_hmap_new( fd_fib4_hmap_mem( fib4 ), FIB4_HMAP_ELE_MAX, FIB4_HMAP_LOCK_CNT, FIB4_HMAP_PROBE_MAX, FIB4_HMAP_SEED );
  fd_memset( fd_fib4_hmap_ele_mem( fib4 ), 0, FIB4_HMAP_ELE_MAX*sizeof(fd_fib4_hmap_entry_t) );
}

FD_FN_PURE ulong
fd_fib4_max( fd_fib4_t const * fib ) {
  return fib->max;
}

FD_FN_PURE ulong
fd_fib4_cnt( fd_fib4_t const * fib ) {
  return fib->cnt+fib->hmap_cnt;
}

ulong
fd_fib4_free_cnt( fd_fib4_t const * fib ) {
  if( FD_UNLIKELY( fib->cnt > fib->max ) ) FD_LOG_ERR(( "invalid fib4 state: cnt>max" ));
  return fib->max - fib->cnt;
}

fd_fib4_hop_t *
fd_fib4_append( fd_fib4_t * fib,
                uint        ip4_dst,
                int         prefix,
                uint        prio ) {

  ulong const generation = fib->generation;

  if( FD_UNLIKELY( fib->cnt>=fib->max ) ) {
    FD_LOG_WARNING(( "Failed to insert route, route table is full (%lu max)", fib->max ));
    return NULL;
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

  return entry;
}

int
fd_fib4_hmap_insert( fd_fib4_t * fib,
                     uint ip4_dst,
                     fd_fib4_hop_t hop ) {

  if( FD_UNLIKELY( fib->hmap_cnt>=FIB4_HMAP_ELE_MAX ) ) return 0;

  fd_fib4_hmap_t hmap[1];
  FD_TEST( fd_fib4_hmap_join( hmap, fd_fib4_hmap_mem( fib ), fd_fib4_hmap_ele_mem( fib ) ) );

  uint key = ip4_dst;
  fd_fib4_hmap_query_t query[1];
  fd_fib4_hmap_entry_t sentinel[1];
  int err = fd_fib4_hmap_prepare( hmap, &key, sentinel, query, FD_MAP_FLAG_BLOCKING );
  if( FD_UNLIKELY(err) ) FD_LOG_ERR(( "fd_fib4_hmap_insert failed. err: %d", err ));

  fd_fib4_hmap_entry_t * ele = fd_fib4_hmap_query_ele( query );
  ele->dst_addr              = ip4_dst;
  ele->next_hop              = hop;
  fib->hmap_cnt              += 1;

  fd_fib4_hmap_publish( query );

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
        out->rtype=FD_FIB4_RTYPE_THROW;
        return out;
      }
      *out = next_hop;
      return out;

    } else if( FD_UNLIKELY( find_err==FD_MAP_ERR_AGAIN ) ) {
      out->rtype=FD_FIB4_RTYPE_THROW;
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

  return 0;
}

#undef WRAP_PRINT
#undef WRAP_PRINTF

#endif /* FD_HAS_HOSTED */

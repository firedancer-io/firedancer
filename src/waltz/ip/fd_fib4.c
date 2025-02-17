#include "fd_fib4.h"
#include "fd_fib4_private.h"
#include "../../util/fd_util.h"

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
  return FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,
      alignof(fd_fib4_t),     sizeof(fd_fib4_t)               ),
      alignof(fd_fib4_key_t), route_max*sizeof(fd_fib4_key_t) ),
      alignof(fd_fib4_hop_t), route_max*sizeof(fd_fib4_hop_t) ),
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
  fd_fib4_t *     fib4 = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fib4_t),     sizeof(fd_fib4_t)               );
  fd_fib4_key_t * keys = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fib4_key_t), route_max*sizeof(fd_fib4_key_t) );
  fd_fib4_hop_t * vals = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fib4_hop_t), route_max*sizeof(fd_fib4_hop_t) );
  FD_SCRATCH_ALLOC_FINI( l, alignof(fd_fib4_t) );

  fd_memset( fib4, 0, sizeof(fd_fib4_t)               );
  fd_memset( keys, 0, route_max*sizeof(fd_fib4_key_t) );
  fd_memset( vals, 0, route_max*sizeof(fd_fib4_hop_t) );
  fib4->max     = route_max;
  fib4->hop_off = (ulong)vals - (ulong)fib4;
  keys[0].prio  = UINT_MAX;
  vals[0].rtype = FD_FIB4_RTYPE_THROW;

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
}

FD_FN_PURE ulong
fd_fib4_max( fd_fib4_t const * fib ) {
  return fib->max;
}

FD_FN_PURE ulong
fd_fib4_cnt( fd_fib4_t const * fib ) {
  return fib->cnt;
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

fd_fib4_hop_t const *
fd_fib4_lookup( fd_fib4_t const * fib,
                fd_fib4_hop_t *   out,
                uint              ip4_dst,
                ulong             flags ) {
  if( FD_UNLIKELY( flags ) ) {
    return fd_fib4_hop_tbl_const( fib ) + 0; /* dead route */
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

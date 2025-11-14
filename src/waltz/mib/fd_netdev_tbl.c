#include "fd_netdev_tbl.h"
#include "../../util/fd_util.h"

struct fd_netdev_tbl_private {
  ulong               magic;
  ulong               dev_off;
  ulong               bond_off;
  fd_netdev_tbl_hdr_t hdr;
};

FD_FN_CONST ulong
fd_netdev_tbl_align( void ) {
  return FD_NETDEV_TBL_ALIGN;
}

FD_FN_CONST ulong
fd_netdev_tbl_footprint( ulong dev_max,
                         ulong bond_max ) {
  if( FD_UNLIKELY( dev_max ==0UL || dev_max >USHORT_MAX ) ) return 0UL;
  if( FD_UNLIKELY( bond_max==0UL || bond_max>USHORT_MAX ) ) return 0UL;
  return FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT, \
      alignof(fd_netdev_tbl_t),  sizeof(fd_netdev_tbl_t)             ),   \
      alignof(fd_netdev_t),      sizeof(fd_netdev_t)      * dev_max  ),   \
      alignof(fd_netdev_bond_t), sizeof(fd_netdev_bond_t) * bond_max ),   \
      FD_NETDEV_TBL_ALIGN );
}

void *
fd_netdev_tbl_new( void * shmem,
                   ulong  dev_max,
                   ulong  bond_max ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, FD_NETDEV_TBL_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !dev_max || dev_max>USHORT_MAX ) ) {
    FD_LOG_WARNING(( "invalid dev_max" ));
    return NULL;
  }

  if( FD_UNLIKELY( !bond_max || bond_max>USHORT_MAX ) ) {
    FD_LOG_WARNING(( "invalid bond_max" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_netdev_tbl_t *  tbl  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_netdev_tbl_t),  sizeof(fd_netdev_tbl_t) );
  fd_netdev_t *      dev  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_netdev_t),      sizeof(fd_netdev_t)      * dev_max  );
  fd_netdev_bond_t * bond = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_netdev_bond_t), sizeof(fd_netdev_bond_t) * bond_max );
  FD_SCRATCH_ALLOC_FINI( l, FD_NETDEV_TBL_ALIGN );

  *tbl = (fd_netdev_tbl_t) {
    .magic    = FD_NETDEV_TBL_MAGIC,
    .dev_off  = (ulong)dev  - (ulong)tbl,
    .bond_off = (ulong)bond - (ulong)tbl,
    .hdr = {
      .dev_max  = (ushort)dev_max,
      .bond_max = (ushort)bond_max,
      .dev_cnt  = 0,
      .bond_cnt = 0,
    }
  };

  fd_netdev_tbl_join_t join[1];
  fd_netdev_tbl_join( join, shmem );
  fd_netdev_tbl_reset( join );
  fd_netdev_tbl_leave( join );

  return tbl;
}

fd_netdev_tbl_join_t *
fd_netdev_tbl_join( void * ljoin,
                    void * shtbl ) {

  if( FD_UNLIKELY( !shtbl ) ) {
    FD_LOG_WARNING(( "NULL shtbl" ));
    return NULL;
  }

  fd_netdev_tbl_join_t * join = ljoin;
  fd_netdev_tbl_t *      tbl  = shtbl;

  if( FD_UNLIKELY( tbl->magic!=FD_NETDEV_TBL_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  *join = (fd_netdev_tbl_join_t) {
    .hdr      = &tbl->hdr,
    .dev_tbl  = (fd_netdev_t      *)( (ulong)tbl + tbl->dev_off  ),
    .bond_tbl = (fd_netdev_bond_t *)( (ulong)tbl + tbl->bond_off ),
  };

  return join;
}

void *
fd_netdev_tbl_leave( fd_netdev_tbl_join_t * join ) {
  return join;
}

void *
fd_netdev_tbl_delete( void * shtbl ) {

  if( FD_UNLIKELY( !shtbl ) ) {
    FD_LOG_WARNING(( "NULL shtbl" ));
    return NULL;
  }

  fd_netdev_tbl_t * tbl = shtbl;
  tbl->magic = 0UL;
  return tbl;
}

void
fd_netdev_tbl_reset( fd_netdev_tbl_join_t * tbl ) {
  tbl->hdr->dev_cnt  = 0;
  tbl->hdr->bond_cnt = 0;
  for( ulong j=0UL; j<(tbl->hdr->dev_max); j++ ) {
    tbl->dev_tbl[j] = (fd_netdev_t) {
      .master_idx    = -1,
      .slave_tbl_idx = -1
    };
  }
  fd_memset( tbl->bond_tbl, 0, sizeof(fd_netdev_bond_t) * tbl->hdr->bond_max );
}

fd_netdev_t *
fd_netdev_tbl_query( fd_netdev_tbl_join_t * tbl,
                     uint                  if_idx ) {
  fd_netdev_t * dev     = tbl->dev_tbl;
  for( ushort j=0U; j<tbl->hdr->dev_cnt; j++, dev++ ) {
    if( dev->if_idx==if_idx ) return dev;
  }
  return NULL;
}

#if FD_HAS_HOSTED

#include <errno.h>
#include <stdio.h>
#include "../../util/net/fd_eth.h"

#define WRAP_PRINT(file,str) if( FD_UNLIKELY( fputs( (str), (file) )<0 ) ) return errno
#define WRAP_PRINTF(file,...) if( FD_UNLIKELY( fprintf( (file), __VA_ARGS__ )<0 ) ) return errno

int
fd_netdev_tbl_fprintf( fd_netdev_tbl_join_t const * tbl,
                       void *                       file_ ) {
  FILE * file = file_;
  for( ulong j=0UL; j<(tbl->hdr->dev_cnt); j++ ) {
    fd_netdev_t const * dev = &tbl->dev_tbl[j];
    if( !dev->oper_status ) continue;
    WRAP_PRINTF( file,
        "%lu: %s: mtu %u state (%i-%s)",
        j, dev->name, dev->mtu,
        dev->oper_status, fd_oper_status_cstr( dev->oper_status ) );
    if( dev->slave_tbl_idx>=0 ) {
      WRAP_PRINT( file, " master" );
    }
    WRAP_PRINTF( file,
        "\n    link " FD_ETH_MAC_FMT "\n",
        FD_ETH_MAC_FMT_ARGS( dev->mac_addr ) );
    if( dev->slave_tbl_idx>=0 && tbl->bond_tbl[ dev->slave_tbl_idx ].slave_cnt ) {
      fd_netdev_bond_t * bond = &tbl->bond_tbl[ dev->slave_tbl_idx ];
      WRAP_PRINTF( file, "    slaves (%u):", bond->slave_cnt );
      for( ulong k=0UL; k<(bond->slave_cnt); k++ ) {
        WRAP_PRINTF( file, " %u-%s", bond->slave_idx[k], tbl->dev_tbl[ bond->slave_idx[k] ].name );
      }
      WRAP_PRINT( file, "\n" );
    }
  }
  return 0;
}

#undef WRAP_PRINT
#undef WRAP_PRINTF

#endif /* FD_HAS_HOSTED */

char const *
fd_oper_status_cstr( uint oper_status ) {
  switch( oper_status ) {
  case FD_OPER_STATUS_UP:               return "up";
  case FD_OPER_STATUS_DOWN:             return "down";
  case FD_OPER_STATUS_TESTING:          return "testing";
  case FD_OPER_STATUS_DORMANT:          return "dormant";
  case FD_OPER_STATUS_NOT_PRESENT:      return "not present";
  case FD_OPER_STATUS_LOWER_LAYER_DOWN: return "lower layer down";
  case FD_OPER_STATUS_UNKNOWN: /* fallthrough */
  default:
    return "unknown";
  }
}

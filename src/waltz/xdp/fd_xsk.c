#if !defined(__linux__)
#error "fd_xsk requires Linux operating system with XDP support"
#endif

#include <errno.h>
#include <stdio.h> /* snprintf */
#include <unistd.h>
#include <sys/mman.h> /* mmap */
#include <sys/types.h>
#include <sys/socket.h> /* sendto */

#include "../../util/log/fd_log.h"
#include "fd_xsk.h"

/* Join/leave *********************************************************/

/* fd_xsk_mmap_offset_cstr: Returns a cstr describing the given offset
   param (6th argument of mmap(2)) assuming fd (5th param of mmap(2)) is
   an XSK file descriptor.  Returned cstr is valid until next call. */
static char const *
fd_xsk_mmap_offset_cstr( long mmap_off ) {
  switch( mmap_off ) {
  case XDP_PGOFF_RX_RING:              return "XDP_PGOFF_RX_RING";
  case XDP_PGOFF_TX_RING:              return "XDP_PGOFF_TX_RING";
  case XDP_UMEM_PGOFF_FILL_RING:       return "XDP_UMEM_PGOFF_FILL_RING";
  case XDP_UMEM_PGOFF_COMPLETION_RING: return "XDP_UMEM_PGOFF_COMPLETION_RING";
  default: {
    static char buf[ 19UL ];
    snprintf( buf, 19UL, "0x%lx", (ulong)mmap_off );
    return buf;
  }
  }
}

/* fd_xsk_mmap_ring maps the given XSK ring into the local address space
   and populates fd_ring_desc_t.  Every successful call to this function
   should eventually be paired with a call to fd_xsk_munmap_ring(). */
static int
fd_xsk_mmap_ring( fd_xdp_ring_t * ring,
                  int             xsk_fd,
                  long            map_off,
                  ulong           elem_sz,
                  ulong           depth,
                  struct xdp_ring_offset const * ring_offset ) {
  /* TODO what is ring_offset->desc ? */
  /* TODO: mmap was originally called with MAP_POPULATE,
           but this symbol isn't available with this build */

  /* sanity check */
  if( depth > (ulong)UINT_MAX ) {
    return -1;
  }

  ulong map_sz = ring_offset->desc + depth*elem_sz;

  void * res = mmap( NULL, map_sz, PROT_READ|PROT_WRITE, MAP_SHARED, xsk_fd, map_off );
  if( FD_UNLIKELY( res==MAP_FAILED ) ) {
    FD_LOG_WARNING(( "mmap(NULL, %lu, PROT_READ|PROT_WRITE, MAP_SHARED, xsk_fd, %s) failed (%i-%s)",
                     map_sz, fd_xsk_mmap_offset_cstr( map_off ), errno, fd_io_strerror( errno ) ));
    return -1;
  }

  /* TODO add unit test asserting that cached prod/cons seq gets
          cleared on join */
  fd_memset( ring, 0, sizeof(fd_xdp_ring_t) );

  ring->mem    = res;
  ring->map_sz = map_sz;
  ring->depth  = (uint)depth;
  ring->ptr    = (void *)( (ulong)res + ring_offset->desc     );
  ring->flags  = (uint *)( (ulong)res + ring_offset->flags    );
  ring->prod   = (uint *)( (ulong)res + ring_offset->producer );
  ring->cons   = (uint *)( (ulong)res + ring_offset->consumer );

  return 0;
}

/* fd_xsk_munmap_ring unmaps the given XSK ring from the local address
   space and zeroes fd_ring_desc_t. */
static void
fd_xsk_munmap_ring( fd_xdp_ring_t * ring,
                    long             map_off ) {
  if( FD_UNLIKELY( !ring->mem ) ) return;

  void * mem = ring->mem;
  ulong  sz  = ring->map_sz;

  fd_memset( ring, 0, sizeof(fd_xdp_ring_t) );

  if( FD_UNLIKELY( 0!=munmap( mem, sz ) ) )
    FD_LOG_WARNING(( "munmap(%p, %lu) on %s ring failed (%i-%s)",
                     mem, sz, fd_xsk_mmap_offset_cstr( map_off ), errno, fd_io_strerror( errno ) ));
}

/* fd_xsk_cleanup undoes a (partial) join by releasing all active kernel
   objects, such as mapped memory regions and file descriptors.  Assumes
   that no join to `xsk` is currently being used. */

fd_xsk_t *
fd_xsk_fini( fd_xsk_t * xsk ) {
  /* Undo memory mappings */

  fd_xsk_munmap_ring( &xsk->ring_rx, XDP_PGOFF_RX_RING              );
  fd_xsk_munmap_ring( &xsk->ring_tx, XDP_PGOFF_TX_RING              );
  fd_xsk_munmap_ring( &xsk->ring_fr, XDP_UMEM_PGOFF_FILL_RING       );
  fd_xsk_munmap_ring( &xsk->ring_cr, XDP_UMEM_PGOFF_COMPLETION_RING );

  /* Release XSK */

  if( FD_LIKELY( xsk->xsk_fd>=0 ) ) {
    /* Clear XSK descriptors */
    fd_memset( &xsk->offsets, 0, sizeof(struct xdp_mmap_offsets) );
    /* Close XSK */
    close( xsk->xsk_fd );
    xsk->xsk_fd = -1;
  }

  return xsk;
}

/* fd_xsk_setup_umem: Initializes xdp_umem_reg and hooks up XSK with
   UMEM rings via setsockopt(). Retrieves xdp_mmap_offsets via
   getsockopt().  Returns 0 on success, -1 on failure. */
static int
fd_xsk_setup_umem( fd_xsk_t *              xsk,
                   fd_xsk_params_t const * params ) {

  /* Initialize xdp_umem_reg */
  struct xdp_umem_reg umem_reg = {
    .addr       = (ulong)params->umem_addr,
    .len        = params->umem_sz,
    .chunk_size = (uint)params->frame_sz,
  };

  /* Register UMEM region */
  int res;
  res = setsockopt( xsk->xsk_fd, SOL_XDP, XDP_UMEM_REG,
                    &umem_reg, sizeof(struct xdp_umem_reg) );
  if( FD_UNLIKELY( res!=0 ) ) {
    FD_LOG_WARNING(( "setsockopt(SOL_XDP,XDP_UMEM_REG(addr=%p,len=%lu,chunk_size=%lu)) failed (%i-%s)",
                     (void *)umem_reg.addr, (ulong)umem_reg.len, (ulong)umem_reg.chunk_size,
                     errno, fd_io_strerror( errno ) ));
    return -1;
  }

  /* Set ring frame counts */
# define FD_SET_XSK_RING_DEPTH(name, var)                                 \
    do {                                                                  \
      res = setsockopt( xsk->xsk_fd, SOL_XDP, name, &(var), 8UL );        \
      if( FD_UNLIKELY( res!=0 ) ) {                                       \
        FD_LOG_WARNING(( "setsockopt(SOL_XDP," #name ",%lu) failed (%i-%s)", \
                         var, errno, fd_io_strerror( errno ) ));          \
        return -1;                                                        \
      }                                                                   \
    } while(0)
  FD_SET_XSK_RING_DEPTH( XDP_UMEM_FILL_RING,       params->fr_depth );
  FD_SET_XSK_RING_DEPTH( XDP_RX_RING,              params->rx_depth );
  FD_SET_XSK_RING_DEPTH( XDP_TX_RING,              params->tx_depth );
  FD_SET_XSK_RING_DEPTH( XDP_UMEM_COMPLETION_RING, params->cr_depth );
# undef FD_SET_XSK_RING_DEPTH

  /* Request ring offsets */
  socklen_t offsets_sz = sizeof(struct xdp_mmap_offsets);
  res = getsockopt( xsk->xsk_fd, SOL_XDP, XDP_MMAP_OFFSETS,
                    &xsk->offsets, &offsets_sz );
  if( FD_UNLIKELY( res!=0 ) ) {
    FD_LOG_WARNING(( "getsockopt(SOL_XDP, XDP_MMAP_OFFSETS) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return -1;
  }

  /* OK */
  return 0;
}

/* fd_xsk_init: Creates and configures an XSK socket object, and
   attaches to a preinstalled XDP program.  The various steps are
   implemented in fd_xsk_setup_{...}. */

fd_xsk_t *
fd_xsk_init( fd_xsk_t *              xsk,
             fd_xsk_params_t const * params ) {

  if( FD_UNLIKELY( !xsk ) ) { FD_LOG_WARNING(( "NULL xsk" )); return NULL; }
  memset( xsk, 0, sizeof(fd_xsk_t) );

  if( FD_UNLIKELY( !params->if_idx ) ) { FD_LOG_WARNING(( "zero if_idx" )); return NULL; }
  if( FD_UNLIKELY( (!params->fr_depth) | (!params->rx_depth) |
                   (!params->tx_depth) | (!params->cr_depth) ) ) {
    FD_LOG_WARNING(( "invalid {fr,rx,tx,cr}_depth" ));
    return NULL;
  }
  if( FD_UNLIKELY( !params->umem_addr ) ) {
    FD_LOG_WARNING(( "NULL umem_addr" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)params->umem_addr, 4096UL ) ) ) {
    FD_LOG_WARNING(( "misaligned params->umem_addr" ));
    return NULL;
  }
  if( FD_UNLIKELY( !params->frame_sz || !fd_ulong_is_pow2( params->frame_sz ) ) ) {
    FD_LOG_WARNING(( "invalid frame_sz" ));
    return NULL;
  }

  xsk->if_idx      = params->if_idx;
  xsk->if_queue_id = params->if_queue_id;

  /* Create XDP socket (XSK) */

  xsk->xsk_fd = socket( AF_XDP, SOCK_RAW, 0 );
  if( FD_UNLIKELY( xsk->xsk_fd<0 ) ) {
    FD_LOG_WARNING(( "Failed to create XSK (%i-%s)", errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  /* Associate UMEM region of fd_xsk_t with XSK via setsockopt() */

  if( FD_UNLIKELY( 0!=fd_xsk_setup_umem( xsk, params ) ) ) goto fail;

  /* Map XSK rings into local address space */

  if( FD_UNLIKELY( 0!=fd_xsk_mmap_ring( &xsk->ring_rx, xsk->xsk_fd, XDP_PGOFF_RX_RING,              sizeof(struct xdp_desc), params->rx_depth, &xsk->offsets.rx ) ) ) goto fail;
  if( FD_UNLIKELY( 0!=fd_xsk_mmap_ring( &xsk->ring_tx, xsk->xsk_fd, XDP_PGOFF_TX_RING,              sizeof(struct xdp_desc), params->tx_depth, &xsk->offsets.tx ) ) ) goto fail;
  if( FD_UNLIKELY( 0!=fd_xsk_mmap_ring( &xsk->ring_fr, xsk->xsk_fd, XDP_UMEM_PGOFF_FILL_RING,       sizeof(ulong),           params->fr_depth, &xsk->offsets.fr ) ) ) goto fail;
  if( FD_UNLIKELY( 0!=fd_xsk_mmap_ring( &xsk->ring_cr, xsk->xsk_fd, XDP_UMEM_PGOFF_COMPLETION_RING, sizeof(ulong),           params->cr_depth, &xsk->offsets.cr ) ) ) goto fail;

  /* Bind XSK to queue on network interface */

  uint flags = XDP_USE_NEED_WAKEUP | params->bind_flags;
  struct sockaddr_xdp sa = {
    .sxdp_family   = PF_XDP,
    .sxdp_ifindex  = xsk->if_idx,
    .sxdp_queue_id = xsk->if_queue_id,
    /* See extended commentary below for details on XDP_USE_NEED_WAKEUP
       flag. */
    .sxdp_flags    = (ushort)flags
  };

  char if_name[ IF_NAMESIZE ] = {0};

  if( FD_UNLIKELY( 0!=bind( xsk->xsk_fd, (void *)&sa, sizeof(struct sockaddr_xdp) ) ) ) {
    FD_LOG_WARNING(( "bind( PF_XDP, ifindex=%u (%s), queue_id=%u, flags=%x ) failed (%i-%s)",
                     xsk->if_idx, if_indextoname( xsk->if_idx, if_name ),
                     xsk->if_queue_id, flags,
                     errno, fd_io_strerror( errno ) ));
    goto fail;
  }

  /* We've seen that some popular Intel NICs seem to have a bug that
     prevents them from working in SKB mode with certain kernel
     versions.  We can identify them by sendto returning ENXIO or EINVAL
     in newer versions.  The core of the problem is that the kernel
     calls the generic ndo_bpf pointer instead of the driver-specific
     version.  This means that the driver's pointer to the BPF program
     never gets set, yet the driver's wakeup function gets called. */
  if( FD_UNLIKELY( -1==sendto( xsk->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0 ) ) ) {
    if( FD_LIKELY( errno==ENXIO || errno==EINVAL ) ) {
      FD_LOG_ERR(( "xsk sendto failed xsk_fd=%d (%i-%s).  This likely indicates "
                   "a bug with your NIC driver.  Try switching XDP mode using "
                   "net.xdp.xdp_mode in the configuration TOML.\n"
                   "Certain Intel NICs with certain driver/kernel combinations "
                   "are known to exhibit this issue in skb mode but work in drv "
                   "mode.", xsk->xsk_fd, errno, fd_io_strerror( errno ) ));
    } else {
      FD_LOG_WARNING(( "xsk sendto failed xsk_fd=%d (%i-%s)", xsk->xsk_fd, errno, fd_io_strerror( errno ) ));
    }
  }

  /* XSK successfully configured.  Traffic will arrive in XSK after
     configuring an XDP program to forward packets via XDP_REDIRECT.
     This requires providing the XSK file descriptor to the program via
     XSKMAP and is done in a separate step. */

  FD_LOG_INFO(( "AF_XDP socket initialized: bind( PF_XDP, ifindex=%u (%s), queue_id=%u, flags=%x ) success",
                xsk->if_idx, if_indextoname( xsk->if_idx, if_name ), xsk->if_queue_id, flags ));

  return xsk;

fail:
  fd_xsk_fini( xsk );
  return NULL;
}

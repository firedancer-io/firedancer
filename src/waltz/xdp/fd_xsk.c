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
#include "fd_xsk_private.h"

ulong
fd_xsk_align( void ) {
  return FD_XSK_ALIGN;
}

static ulong
fd_xsk_umem_footprint( ulong frame_sz,
                       ulong fr_depth,
                       ulong rx_depth,
                       ulong tx_depth,
                       ulong cr_depth ) {
  /* TODO overflow checks */
  ulong sz = 0UL;
  sz+=fd_ulong_align_up( fr_depth*frame_sz, FD_XSK_ALIGN );
  sz+=fd_ulong_align_up( rx_depth*frame_sz, FD_XSK_ALIGN );
  sz+=fd_ulong_align_up( tx_depth*frame_sz, FD_XSK_ALIGN );
  sz+=fd_ulong_align_up( cr_depth*frame_sz, FD_XSK_ALIGN );
  return sz;
}

ulong
fd_xsk_footprint( ulong frame_sz,
                  ulong fr_depth,
                  ulong rx_depth,
                  ulong tx_depth,
                  ulong cr_depth ) {

  /* Linux 4.18 requires XSK frames to be 2048-byte aligned and no
     larger than page size. */
  if( FD_UNLIKELY( frame_sz!=2048UL && frame_sz!=4096UL ) ) return 0UL;
  if( FD_UNLIKELY( fr_depth==0UL ) ) return 0UL;
  if( FD_UNLIKELY( rx_depth==0UL ) ) return 0UL;
  if( FD_UNLIKELY( tx_depth==0UL ) ) return 0UL;
  if( FD_UNLIKELY( cr_depth==0UL ) ) return 0UL;

  /* TODO overflow checks */
  return fd_ulong_align_up( sizeof(fd_xsk_t), FD_XSK_UMEM_ALIGN )
       + fd_xsk_umem_footprint( frame_sz, fr_depth, rx_depth, tx_depth, cr_depth );
}

/* New/delete *********************************************************/

void *
fd_xsk_new( void *       shmem,
            ulong        frame_sz,
            ulong        fr_depth,
            ulong        rx_depth,
            ulong        tx_depth,
            ulong        cr_depth ) {

  /* Validate arguments */

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_xsk_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  fd_xsk_t * xsk = (fd_xsk_t *)shmem;

  ulong footprint = fd_xsk_footprint( frame_sz, fr_depth, rx_depth, tx_depth, cr_depth );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "invalid footprint for config" ));
    return NULL;
  }

  /* Reset fd_xsk_t state.  No need to clear UMEM area */

  fd_memset( xsk, 0, sizeof(fd_xsk_t) );

  xsk->xsk_fd         = -1;
  xsk->xdp_map_fd     = -1;
  xsk->xdp_udp_map_fd = -1;

  /* Copy config */

  xsk->params.frame_sz = frame_sz;
  xsk->params.fr_depth = fr_depth;
  xsk->params.rx_depth = rx_depth;
  xsk->params.tx_depth = tx_depth;
  xsk->params.cr_depth = cr_depth;

  /* Derive offsets (TODO overflow check) */

  ulong xsk_off = 0UL;
  xsk_off+=fr_depth*frame_sz;
  xsk_off+=rx_depth*frame_sz;
  xsk_off+=tx_depth*frame_sz;
  xsk_off+=cr_depth*frame_sz;
  xsk->params.umem_sz = xsk_off;

  /* Mark object as valid */

  FD_COMPILER_MFENCE();
  FD_VOLATILE( xsk->magic ) = FD_XSK_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)xsk;
}

void *
fd_xsk_delete( void * shxsk ) {

  if( FD_UNLIKELY( !shxsk ) ) {
    FD_LOG_WARNING(( "NULL shxsk" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shxsk, fd_xsk_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shxsk" ));
    return NULL;
  }

  fd_xsk_t * xsk = (fd_xsk_t *)shxsk;

  if( FD_UNLIKELY( xsk->magic!=FD_XSK_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( xsk->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)xsk;
}

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
fd_xsk_mmap_ring( fd_ring_desc_t * ring,
                  int              xsk_fd,
                  long             map_off,
                  ulong            elem_sz,
                  ulong            depth,
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
  if( FD_UNLIKELY( !res ) ) {
    FD_LOG_WARNING(( "mmap(NULL, %lu, PROT_READ|PROT_WRITE, MAP_SHARED, xsk_fd, %s) failed (%i-%s)",
                     map_sz, fd_xsk_mmap_offset_cstr( map_off ), errno, fd_io_strerror( errno ) ));
    return -1;
  }

  /* TODO add unit test asserting that cached prod/cons seq gets
          cleared on join */
  fd_memset( ring, 0, sizeof(fd_ring_desc_t) );

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
fd_xsk_munmap_ring( fd_ring_desc_t * ring,
                    long             map_off ) {
  if( FD_UNLIKELY( !ring->mem ) ) return;

  void * mem = ring->mem;
  ulong  sz  = ring->map_sz;

  fd_memset( ring, 0, sizeof(fd_ring_desc_t) );

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

  /* Release eBPF map FDs */

  if( FD_LIKELY( xsk->xdp_map_fd>=0 ) ) {
    close( xsk->xdp_map_fd );
    xsk->xdp_map_fd = -1;
  }
  if( FD_LIKELY( xsk->xdp_udp_map_fd>=0 ) ) {
    close( xsk->xdp_udp_map_fd );
    xsk->xdp_udp_map_fd = -1;
  }

  /* Release XSK */

  if( FD_LIKELY( xsk->xsk_fd>=0 ) ) {
    /* Clear XSK descriptors */
    fd_memset( &xsk->offsets, 0, sizeof(struct xdp_mmap_offsets) );
    fd_memset( &xsk->umem,    0, sizeof(struct xdp_umem_reg)     );
    /* Close XSK */
    close( xsk->xsk_fd );
    xsk->xsk_fd = -1;
  }

  return xsk;
}

/* fd_xsk_setup_umem: Initializes xdp_umem_reg and hooks up XSK with
   UMEM rings via setsockopt(). Retrieves xdp_mmap_offsets via
   getsockopt().  Returns 1 on success, 0 on failure. */
static int
fd_xsk_setup_umem( fd_xsk_t * xsk ) {
  /* Find byte offset of UMEM area */
  ulong umem_off = fd_ulong_align_up( sizeof(fd_xsk_t), FD_XSK_UMEM_ALIGN );

  /* Initialize xdp_umem_reg */
  xsk->umem.headroom   = 0; /* TODO no need for headroom for now */
  xsk->umem.addr       = (ulong)xsk + umem_off;
  xsk->umem.chunk_size = (uint)xsk->params.frame_sz;
  xsk->umem.len        =       xsk->params.umem_sz;

  /* Register UMEM region */
  int res;
  res = setsockopt( xsk->xsk_fd, SOL_XDP, XDP_UMEM_REG,
                    &xsk->umem, sizeof(struct xdp_umem_reg) );
  if( FD_UNLIKELY( res!=0 ) ) {
    FD_LOG_WARNING(( "setsockopt(SOL_XDP, XDP_UMEM_REG) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return -1;
  }

  /* Set ring frame counts */
# define FD_SET_XSK_RING_DEPTH(name, var)                                 \
    do {                                                                  \
      res = setsockopt( xsk->xsk_fd, SOL_XDP, name, &(var), 8UL );        \
      if( FD_UNLIKELY( res!=0 ) ) {                                       \
        FD_LOG_WARNING(( "setsockopt(SOL_XDP, " #name ") failed (%i-%s)", \
                         errno, fd_io_strerror( errno ) ));               \
        return -1;                                                        \
      }                                                                   \
    } while(0)
  FD_SET_XSK_RING_DEPTH( XDP_UMEM_FILL_RING,       xsk->params.fr_depth );
  FD_SET_XSK_RING_DEPTH( XDP_RX_RING,              xsk->params.rx_depth );
  FD_SET_XSK_RING_DEPTH( XDP_TX_RING,              xsk->params.tx_depth );
  FD_SET_XSK_RING_DEPTH( XDP_UMEM_COMPLETION_RING, xsk->params.cr_depth );
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
fd_xsk_init( fd_xsk_t * xsk,
             uint       if_idx,
             uint       if_queue,
             uint       bind_flags ) {

  if( FD_UNLIKELY( !xsk ) ) { FD_LOG_WARNING(( "NULL xsk" )); return NULL; }

  /* Create XDP socket (XSK) */

  xsk->xsk_fd = socket( AF_XDP, SOCK_RAW, 0 );
  if( FD_UNLIKELY( xsk->xsk_fd<0 ) ) {
    FD_LOG_WARNING(( "Failed to create XSK (%i-%s)", errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  /* Associate UMEM region of fd_xsk_t with XSK via setsockopt() */

  if( FD_UNLIKELY( 0!=fd_xsk_setup_umem( xsk ) ) ) goto fail;

  /* Map XSK rings into local address space */

  if( FD_UNLIKELY( 0!=fd_xsk_mmap_ring( &xsk->ring_rx, xsk->xsk_fd, XDP_PGOFF_RX_RING,              sizeof(struct xdp_desc), xsk->params.rx_depth, &xsk->offsets.rx ) ) ) goto fail;
  if( FD_UNLIKELY( 0!=fd_xsk_mmap_ring( &xsk->ring_tx, xsk->xsk_fd, XDP_PGOFF_TX_RING,              sizeof(struct xdp_desc), xsk->params.tx_depth, &xsk->offsets.tx ) ) ) goto fail;
  if( FD_UNLIKELY( 0!=fd_xsk_mmap_ring( &xsk->ring_fr, xsk->xsk_fd, XDP_UMEM_PGOFF_FILL_RING,       sizeof(ulong),           xsk->params.fr_depth, &xsk->offsets.fr ) ) ) goto fail;
  if( FD_UNLIKELY( 0!=fd_xsk_mmap_ring( &xsk->ring_cr, xsk->xsk_fd, XDP_UMEM_PGOFF_COMPLETION_RING, sizeof(ulong),           xsk->params.cr_depth, &xsk->offsets.cr ) ) ) goto fail;

  /* Bind XSK to queue on network interface */

  uint flags = XDP_USE_NEED_WAKEUP | bind_flags;
  struct sockaddr_xdp sa = {
    .sxdp_family   = PF_XDP,
    .sxdp_ifindex  = if_idx,
    .sxdp_queue_id = if_queue,
    /* See extended commentary below for details on on
       XDP_USE_NEED_WAKEUP flag. */
    .sxdp_flags    = (ushort)flags
  };

  char if_name[ IF_NAMESIZE ] = {0};

  if( FD_UNLIKELY( 0!=bind( xsk->xsk_fd, (void *)&sa, sizeof(struct sockaddr_xdp) ) ) ) {
    FD_LOG_WARNING(( "bind( PF_XDP, ifindex=%u (%s), queue_id=%u, flags=%x ) failed (%i-%s)",
                     if_idx, if_indextoname( if_idx, if_name ), if_queue, flags, errno, fd_io_strerror( errno ) ));
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
                   "tiles.net.xdp_mode in the configuration TOML, and then running\n"
                   "fdctl configure fini xdp --config path_to_configuration_toml.\n"
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

  xsk->if_idx      = if_idx;
  xsk->if_queue_id = if_queue;

  FD_LOG_INFO(( "AF_XDP socket initialized: bind( PF_XDP, ifindex=%u (%s), queue_id=%u, flags=%x ) success",
                if_idx, if_indextoname( if_idx, if_name ), if_queue, flags ));

  return xsk;

fail:
  fd_xsk_fini( xsk );
  return NULL;
}

fd_xsk_t *
fd_xsk_join( void * shxsk ) {
  /* TODO: Joining the same fd_xsk_t from two threads is invalid.
           Document that and add a lock. */

  /* Argument checks */

  if( FD_UNLIKELY( !shxsk ) ) {
    FD_LOG_WARNING(( "NULL shxsk" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shxsk, fd_xsk_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shxsk" ));
    return NULL;
  }

  /* fd_xsk_t state coherence check.  A successful call to fd_xsk_new()
     should not allow for any of these fail conditions. */

  fd_xsk_t * xsk = (fd_xsk_t *)shxsk;

  if( FD_UNLIKELY( xsk->magic!=FD_XSK_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic (not an fd_xsk_t?)" ));
    return NULL;
  }

  return xsk;
}

void *
fd_xsk_leave( fd_xsk_t * xsk ) {

  if( FD_UNLIKELY( !xsk ) ) {
    FD_LOG_WARNING(( "NULL xsk" ));
    return NULL;
  }

  return (void *)xsk;
}

/* Public helper methods **********************************************/

void *
fd_xsk_umem_laddr( fd_xsk_t * xsk ) {
  return (void *)xsk->umem.addr;
}

FD_FN_PURE int
fd_xsk_fd( fd_xsk_t * const xsk ) {
  return xsk->xsk_fd;
}

FD_FN_PURE uint
fd_xsk_ifidx( fd_xsk_t * const xsk ) {
  return xsk->if_idx;
}

FD_FN_PURE uint
fd_xsk_ifqueue( fd_xsk_t * const xsk ) {
  return xsk->if_queue_id;
}

/* RX/TX implementation ***********************************************/

FD_FN_CONST fd_xsk_params_t const *
fd_xsk_get_params( fd_xsk_t const * xsk ) {
  return &xsk->params;
}

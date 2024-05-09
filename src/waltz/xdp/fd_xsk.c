#if !defined(__linux__)
#error "fd_xsk requires Linux operating system with XDP support"
#endif

#include <linux/if_xdp.h>
#include <linux/limits.h>

#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <unistd.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>

#include "fd_xsk_private.h"
#include "fd_xdp_redirect_user.h"

/* TODO move this into more appropriate header file
   and set based on architecture, etc. */
#define FD_ACQUIRE FD_COMPILER_MFENCE
#define FD_RELEASE FD_COMPILER_MFENCE

/* Set to 1 to trace packet events to debug log */

#if 0
#define TRACE_PACKET(...) FD_LOG_DEBUG(( __VA_ARGS__ ))
#else
#define TRACE_PACKET(...)
#endif

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

/* Bind/unbind ********************************************************/

void *
fd_xsk_bind( void *       shxsk,
             char const * app_name,
             char const * ifname,
             uint         ifqueue ) {

  /* Argument checks */

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
    FD_LOG_WARNING(( "bad magic (not an fd_xsk_t?)" ));
    return NULL;
  }

  /* Check if app_name is a valid cstr */

  if( FD_UNLIKELY( !app_name ) ) {
    FD_LOG_WARNING(( "NULL app_name" ));
    return NULL;
  }
  ulong app_name_len = fd_cstr_nlen( app_name, NAME_MAX );
  if( FD_UNLIKELY( app_name_len==0UL ) ) {
    FD_LOG_WARNING(( "missing app_name" ));
    return NULL;
  }
  if( FD_UNLIKELY( app_name_len==NAME_MAX ) ) {
    FD_LOG_WARNING(( "app_name not a cstr or exceeds NAME_MAX" ));
    return NULL;
  }

  /* Check if ifname is a valid cstr */

  if( FD_UNLIKELY( !ifname ) ) {
    FD_LOG_WARNING(( "NULL ifname" ));
    return NULL;
  }
  ulong if_name_len = fd_cstr_nlen( ifname, IF_NAMESIZE );
  if( FD_UNLIKELY( if_name_len==0UL ) ) {
    FD_LOG_WARNING(( "missing ifname" ));
    return NULL;
  }
  if( FD_UNLIKELY( if_name_len==IF_NAMESIZE ) ) {
    FD_LOG_WARNING(( "ifname not a cstr or exceeds IF_NAMESIZE" ));
    return NULL;
  }

  /* Check if interface exists */

  if( FD_UNLIKELY( 0==if_nametoindex( ifname ) ) ) {
    FD_LOG_WARNING(( "Network interface %s does not exist", ifname ));
    return NULL;
  }

  /* Assign */

  fd_memcpy( xsk->app_name_cstr, app_name, app_name_len+1UL );
  fd_memcpy( xsk->if_name_cstr,  ifname,   if_name_len +1UL );
  xsk->if_queue_id = ifqueue;

  return shxsk;
}

void *
fd_xsk_unbind( void * shxsk ) {
  /* Argument checks */

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
    FD_LOG_WARNING(( "bad magic (not an fd_xsk_t?)" ));
    return NULL;
  }

  /* Reset */

  fd_memset( xsk->if_name_cstr, 0, IF_NAMESIZE );
  xsk->if_queue_id = UINT_MAX;

  return shxsk;
}

/* New/delete *********************************************************/

void *
fd_xsk_new( void *       shmem,
            ulong        frame_sz,
            ulong        fr_depth,
            ulong        rx_depth,
            ulong        tx_depth,
            ulong        cr_depth,
            int          zero_copy ) {
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

  fd_memset( xsk, 0, footprint );

  xsk->xsk_fd         = -1;
  xsk->xdp_map_fd     = -1;
  xsk->xdp_udp_map_fd = -1;

  /* Copy config */

  xsk->params.frame_sz = frame_sz;
  xsk->params.fr_depth = fr_depth;
  xsk->params.rx_depth = rx_depth;
  xsk->params.tx_depth = tx_depth;
  xsk->params.cr_depth = cr_depth;
  xsk->params.zerocopy = zero_copy ? XDP_ZEROCOPY : XDP_COPY;

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
static void
fd_xsk_cleanup( fd_xsk_t * xsk ) {
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
static int
fd_xsk_init( fd_xsk_t * xsk ) {
  /* Validate XDP zero copy flag */

  switch( xsk->params.zerocopy ) {
  case 0:
  case XDP_COPY:
  case XDP_ZEROCOPY:
    break;  /* okay */
  default:
    FD_LOG_WARNING(( "invalid zerocopy flag: %#x", xsk->params.zerocopy ));
    return -1;
  }

  /* Find interface index */

  if( FD_UNLIKELY( !xsk->if_name_cstr[0] ) ) {
    FD_LOG_WARNING(( "not bound to any interface" ));
    return -1;
  }
  uint if_idx = if_nametoindex( xsk->if_name_cstr );
  if( FD_UNLIKELY( if_idx )==0 ) {
    FD_LOG_WARNING(( "if_nametoindex(%s) failed (%i-%s)", xsk->if_name_cstr, errno, fd_io_strerror( errno ) ));
    return -1;
  }
  xsk->if_idx = if_idx;

  /* Create XDP socket (XSK) */

  xsk->xsk_fd = socket( AF_XDP, SOCK_RAW, 0 );
  if( FD_UNLIKELY( xsk->xsk_fd<0 ) ) {
    FD_LOG_WARNING(( "Failed to create XSK (%i-%s)", errno, fd_io_strerror( errno ) ));
    return -1;
  }

  /* Associate UMEM region of fd_xsk_t with XSK via setsockopt() */

  if( FD_UNLIKELY( 0!=fd_xsk_setup_umem( xsk ) ) ) return -1;

  /* Map XSK rings into local address space */

  if( FD_UNLIKELY( 0!=fd_xsk_mmap_ring( &xsk->ring_rx, xsk->xsk_fd, XDP_PGOFF_RX_RING,              sizeof(struct xdp_desc), xsk->params.rx_depth, &xsk->offsets.rx ) ) ) return 0;
  if( FD_UNLIKELY( 0!=fd_xsk_mmap_ring( &xsk->ring_tx, xsk->xsk_fd, XDP_PGOFF_TX_RING,              sizeof(struct xdp_desc), xsk->params.tx_depth, &xsk->offsets.tx ) ) ) return 0;
  if( FD_UNLIKELY( 0!=fd_xsk_mmap_ring( &xsk->ring_fr, xsk->xsk_fd, XDP_UMEM_PGOFF_FILL_RING,       sizeof(ulong),           xsk->params.fr_depth, &xsk->offsets.fr ) ) ) return 0;
  if( FD_UNLIKELY( 0!=fd_xsk_mmap_ring( &xsk->ring_cr, xsk->xsk_fd, XDP_UMEM_PGOFF_COMPLETION_RING, sizeof(ulong),           xsk->params.cr_depth, &xsk->offsets.cr ) ) ) return 0;

  /* Bind XSK to queue on network interface */

  struct sockaddr_xdp sa = {
    .sxdp_family   = PF_XDP,
    .sxdp_ifindex  = xsk->if_idx,
    .sxdp_queue_id = xsk->if_queue_id,
    /* See extended commentary below for details on on
       XDP_USE_NEED_WAKEUP flag. */
    .sxdp_flags    = XDP_USE_NEED_WAKEUP | (ushort)xsk->params.zerocopy
  };

  if( FD_UNLIKELY( 0!=bind( xsk->xsk_fd, (void *)&sa, sizeof(struct sockaddr_xdp) ) ) ) {
    FD_LOG_WARNING(( "Unable to bind to interface %s queue %u (%i-%s)",
                     xsk->if_name_cstr, xsk->if_queue_id, errno, fd_io_strerror( errno ) ));
    return -1;
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

  FD_LOG_INFO(( "xsk bind() success" ));

  /* XSK successfully configured.  Traffic will arrive in XSK after
     configuring an XDP program to forward packets via XDP_REDIRECT.
     This requires providing the XSK file descriptor to the program via
     XSKMAP and is done in a separate step. */

  return 0;
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

  /* Setup XSK */

  if( FD_UNLIKELY( 0!=fd_xsk_init( xsk ) ) ) {
    FD_LOG_WARNING(( "XSK setup failed" ));
    if( xsk->xsk_fd >= 0 )
      close( xsk->xsk_fd );
    return NULL;
  }

  /* Attach XSK to eBPF program */

  if( FD_UNLIKELY( 0!=fd_xsk_activate( xsk ) ) ) {
    FD_LOG_WARNING(( "fd_xsk_activate(%p) failed", (void *)xsk ));
    if( xsk->xsk_fd >= 0 )
      close( xsk->xsk_fd );
    return NULL;
  }

  /* XSK is ready for use */

  return xsk;
}

void *
fd_xsk_leave( fd_xsk_t * xsk ) {

  if( FD_UNLIKELY( !xsk ) ) {
    FD_LOG_WARNING(( "NULL xsk" ));
    return NULL;
  }

  fd_xsk_cleanup( xsk );

  return (void *)xsk;
}

/* Public helper methods **********************************************/

void *
fd_xsk_umem_laddr( fd_xsk_t * xsk ) {
  return (void *)xsk->umem.addr;
}

FD_FN_CONST char const *
fd_xsk_app_name( fd_xsk_t * const xsk ) {
  return xsk->app_name_cstr;
}

FD_FN_PURE int
fd_xsk_fd( fd_xsk_t * const xsk ) {
  return xsk->xsk_fd;
}

FD_FN_PURE uint
fd_xsk_ifidx( fd_xsk_t * const xsk ) {
  return xsk->if_idx;
}

FD_FN_PURE char const *
fd_xsk_ifname( fd_xsk_t * const xsk ) {
  /* cstr coherence check */
  ulong len = fd_cstr_nlen( xsk->if_name_cstr, IF_NAMESIZE );
  if( FD_UNLIKELY( len==0UL || len==IF_NAMESIZE ) ) return NULL;

  return xsk->if_name_cstr;
}

FD_FN_PURE uint
fd_xsk_ifqueue( fd_xsk_t * const xsk ) {
  return xsk->if_queue_id;
}

/* RX/TX implementation ***********************************************/

ulong
fd_xsk_rx_enqueue( fd_xsk_t * xsk,
                   ulong *    offset,
                   ulong      count ) {
  /* to make frames available for receive, we enqueue onto the fill ring */

  /* fill ring */
  fd_ring_desc_t * fill = &xsk->ring_fr;

  /* fetch cached consumer, producer */
  uint prod = fill->cached_prod;
  uint cons = fill->cached_cons;

  /* assuming frame sizes are powers of 2 */
  ulong frame_mask = xsk->params.frame_sz - 1UL;

  /* ring capacity */
  uint cap  = fill->depth;

  /* if not enough for batch, update cache */
  if( cap - ( prod - cons ) < count ) {
    cons = fill->cached_cons = FD_VOLATILE_CONST( *fill->cons );
  }

  /* sz is min( available, count ) */
  ulong sz = cap - ( prod - cons );
  if( sz > count ) sz = count;

  /* set ring[j] to the specified indices */
  ulong * ring = fill->frame_ring;
  uint    mask = fill->depth - 1U;
  for( ulong j = 0; j < sz; ++j ) {
    uint k = prod & mask;
    ring[k] = offset[j] & ~frame_mask;

    prod++;
  }

  /* ensure data is visible before producer index */
  FD_RELEASE();

  /* update producer */
                fill->cached_prod   = prod;
  FD_VOLATILE( *fill->prod        ) = prod;

  /* Be sure to see additional comments below about the TX path.

     XDP by default operates in a mode where if it runs out of buffers
     to stick arriving packets into (a/k/a the fill ring is empty) then
     the driver will busy spin waiting for the fill ring to be
     replenished, so it can pick that up and start writing incoming
     packets again.

     Some applications don't like this, because if the driver is pinning
     a core waiting for the fill ring, the application might be trying
     to use that core to replenish it and never get a chance, leading to
     a kind of CPU pinned deadlock.

     So the kernel introduced a new flag to fix this,
     XDP_USE_NEED_WAKEUP.  The way this flag works is that if it's set,
     then the driver won't busy loop when it runs out of fill ring
     entries, it'll just park itself and wait for a notification from
     the kernel that there are new entries available to use.

     So the application needs to tell the kernel to wake the driver,
     when there are new fill ring entries, which it can do by calling
     recvmsg on the XSK file descriptor.  This is, according to the
     kernel docs, a performance win for applications where the driver
     would busy loop on its own core as well, since it allows you to
     avoid spurious syscalls in the TX path (see the comments on that
     below), and we should only rarely need to invoke the syscall here,
     since it requires running out of frames in the fill ring.

     That situation describes us (we pin all cores specially), so this
     is really just a super minor performance optimization for the TX
     path, to sometimes avoid a `sendto` syscall. But anyway...

     This flag requires special driver support to actually be faster. If
     the driver does not support then the kernel will default to
     rx_need_wakeup always returning false, tx_need_wakeup always
     returning true, and the driver busy spinning same as it did before,
     the application doesn't need to know about driver support or not.

     Finally, note that none of this is what we actually want.  What we
     want is to never call any of this stuff, and just have the driver
     spin two cores for us permanently, one for the TX path and one for
     the RX path.  Then we never need to notify, never need to make
     syscalls, and the performance would be even better.  Sadly, this
     is not possible. */
  if( FD_UNLIKELY( fd_xsk_rx_need_wakeup( xsk ) ) ) {
    struct msghdr _ignored[ 1 ] = { 0 };
    if( FD_UNLIKELY( -1==recvmsg( xsk->xsk_fd, _ignored, MSG_DONTWAIT ) ) ) {
      if( FD_UNLIKELY( errno!=EAGAIN ) ) {
        FD_LOG_WARNING(( "xsk recvmsg failed xsk_fd=%d (%i-%s)", xsk->xsk_fd, errno, fd_io_strerror( errno ) ));
      }
    }
  }

  return sz;
}

ulong
fd_xsk_rx_enqueue2( fd_xsk_t *            xsk,
                    fd_xsk_frame_meta_t * meta,
                    ulong                 count ) {
  /* to make frames available for receive, we enqueue onto the fill ring */

  /* fill ring */
  fd_ring_desc_t * fill = &xsk->ring_fr;

  /* fetch cached consumer, producer */
  uint prod = fill->cached_prod;
  uint cons = fill->cached_cons;

  /* assuming frame sizes are powers of 2 */
  ulong frame_mask = xsk->params.frame_sz - 1UL;

  /* ring capacity */
  ulong cap  = fill->depth;

  /* if not enough for batch, update cache */
  if( cap - ( prod - cons ) < count ) {
    cons = fill->cached_cons = FD_VOLATILE_CONST( *fill->cons );
  }

  /* sz is min( available, count ) */
  ulong sz = cap - ( prod - cons );
  if( sz > count ) sz = count;

  /* set ring[j] to the specified indices */
  ulong * ring = fill->frame_ring;
  uint    mask = fill->depth - 1;
  for( ulong j = 0; j < sz; ++j ) {
    uint k = prod & mask;
    ring[k] = meta[j].off & ~frame_mask;

    prod++;
  }

  /* ensure data is visible before producer index */
  FD_RELEASE();

  /* update producer */
                fill->cached_prod   = prod;
  FD_VOLATILE( *fill->prod        ) = prod;

  /* See the corresponding comments in fd_xsk_rx_enqueue */
  if( FD_UNLIKELY( fd_xsk_rx_need_wakeup( xsk ) ) ) {
    struct msghdr _ignored[ 1 ] = { 0 };
    if( FD_UNLIKELY( -1==recvmsg( xsk->xsk_fd, _ignored, MSG_DONTWAIT ) ) ) {
      if( FD_UNLIKELY( errno!=EAGAIN ) ) {
        FD_LOG_WARNING(( "xsk recvmsg failed xsk_fd=%d (%i-%s)", xsk->xsk_fd, errno, fd_io_strerror( errno ) ));
      }
    }
  }

  return sz;
}

ulong
fd_xsk_tx_enqueue( fd_xsk_t *            xsk,
                   fd_xsk_frame_meta_t * meta,
                   ulong                 count,
                   int                   flush ) {
  /* to submit frames for tx, we enqueue onto the tx ring */

  /* tx ring */
  fd_ring_desc_t * tx = &xsk->ring_tx;

  /* fetch cached consumer, producer */
  uint prod = tx->cached_prod;
  uint cons = tx->cached_cons;

  /* ring capacity */
  uint cap  = tx->depth;

  /* if not enough for batch, update cache */
  if( cap - ( prod - cons ) < (uint)count ) {
    cons = tx->cached_cons = FD_VOLATILE_CONST( *tx->cons );
  }

  /* sz is min( available, count ) */
  uint sz = cap - ( prod - cons );
  if( sz > (uint)count ) sz = (uint)count;

  /* set ring[j] to the specified indices */
  struct xdp_desc * ring = tx->packet_ring;
  uint   mask            = tx->depth - 1;

  TRACE_PACKET( "tx packets ring=%p seq=%u cnt=%u", (void *)ring, prod, sz );
  for( ulong j = 0; j < sz; ++j ) {
    ulong k = prod & mask;
    ring[k].addr    = meta[j].off;
    ring[k].len     = meta[j].sz;
    ring[k].options = 0;

    prod++;
  }

  /* ensure data is visible before producer index */
  FD_RELEASE();

  tx->cached_prod = prod;

  if( flush ) {
    /* update producer */
    FD_VOLATILE( *tx->prod ) = prod;

    /* In the TX path of XDP, we always need to call sendto to inform
       the kernel there are new messages in the TX ring and it should
       wake the driver (how else would they know? there is no kthread
       polling for it).

       There is a small optimization: if the XDP_USE_NEED_WAKEUP flag is
       provided, then we can ask the kernel if a wakeup is needed.  Why
       wouldn't it be?  Just for a very special case: if the driver is
       already about to be woken up, because it has a completion IRQ
       already scheduled.  The only effect of this is to save a syscall
       in certain cases so it's a somewhat minor optimization.

       None the less, we enable XDP_USE_NEED_WAKEUP, so we might as well
       check this and save a syscall rather than calling sendto always.

       Notice that XDP_USE_NEED_WAKEUP is an optimization, and it
       requires special driver support.  In the case that the driver
       does not support this, the kernel will default to always
       returning true from the need wakeup, so it reverts to the
       non-optimized behavior.

       The flush argument here allows us to coalesce transactions
       together, and isn't really related to the `sendto` syscall, but
       we only call `sendto` if flush is true, because otherwise there
       are no new TX messages in the ring and waking up the driver will
       have no effect. */
    if( fd_xsk_tx_need_wakeup( xsk ) ) {
      if( FD_UNLIKELY( -1==sendto( xsk->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0 ) ) ) {
        if( FD_UNLIKELY( errno!=EAGAIN ) ) {
          FD_LOG_WARNING(( "xsk sendto failed xsk_fd=%d (%i-%s)", xsk->xsk_fd, errno, fd_io_strerror( errno ) ));
        }
      }
    }
  }

  return sz;
}

ulong
fd_xsk_rx_complete( fd_xsk_t *            xsk,
                    fd_xsk_frame_meta_t * batch,
                    ulong                 capacity ) {
  /* rx ring */
  fd_ring_desc_t * rx = &xsk->ring_rx;

  uint prod = rx->cached_prod;
  uint cons = rx->cached_cons;

  /* how many frames are available? */
  uint avail = prod - cons;

  /* should we update the cache */
  if( (ulong)avail < capacity ) {
    /* we update cons (and keep cache up to date)
       they update prod
       so only need to fetch actual prod */
    prod = rx->cached_prod = FD_VOLATILE_CONST( *rx->prod );
    avail = prod - cons;
  }

  ulong sz = avail;
  if( sz > capacity ) sz = capacity;

  uint              mask = rx->depth - 1;
  struct xdp_desc * ring = rx->packet_ring;

  TRACE_PACKET( "rx packets ring=%p seq=%u cnt=%lu", (void *)ring, cons, sz );
  for( ulong j = 0; j < sz; ++j ) {
    ulong k = cons & mask;
    batch[j].off   = ring[k].addr;
    batch[j].sz    = ring[k].len;
    batch[j].flags = 0;

    cons++;
  }

  FD_RELEASE();

                rx->cached_cons   = cons;
  FD_VOLATILE( *rx->cons        ) = cons;

  return sz;
}

ulong
fd_xsk_tx_complete( fd_xsk_t * xsk, ulong * batch, ulong capacity ) {
  /* cr ring */
  fd_ring_desc_t * cr = &xsk->ring_cr;

  uint prod = cr->cached_prod;
  uint cons = cr->cached_cons;

  /* how many frames are available? */
  uint avail = prod - cons;

  /* should we update the cache */
  if( (ulong)avail < capacity ) {
    /* we update cons (and keep cache up to date)
       they update prod
       so only need to fetch actual prod */
    prod = cr->cached_prod = FD_VOLATILE_CONST( *cr->prod );
    avail = prod - cons;
  }

  ulong sz = avail;
  if( sz > capacity ) sz = capacity;

  uint    mask = cr->depth - 1;
  ulong * ring = cr->frame_ring;
  for( ulong j = 0; j < sz; ++j ) {
    ulong k = cons & mask;
    batch[j] = ring[k];

    cons++;
  }

  FD_RELEASE();

                cr->cached_cons   = cons;
  FD_VOLATILE( *cr->cons        ) = cons;

  return sz;
}

ulong
fd_xsk_tx_complete2( fd_xsk_t *            xsk,
                     fd_xsk_frame_meta_t * batch,
                     ulong                 capacity ) {
  /* cr ring */
  fd_ring_desc_t * cr = &xsk->ring_cr;

  uint prod = cr->cached_prod;
  uint cons = cr->cached_cons;

  /* how many frames are available? */
  uint avail = prod - cons;

  /* should we update the cache */
  if( (ulong)avail < capacity ) {
    /* we update cons (and keep cache up to date)
       they update prod
       so only need to fetch actual prod */
    prod = cr->cached_prod = FD_VOLATILE_CONST( *cr->prod );
    avail = prod - cons;
  }

  ulong sz = avail;
  if( sz > capacity ) sz = capacity;

  uint    mask = cr->depth - 1;
  ulong * ring = cr->frame_ring;
  for( ulong j = 0; j < sz; ++j ) {
    ulong k = cons & mask;
    batch[j].off = ring[k];

    cons++;
  }

  FD_RELEASE();

                cr->cached_cons   = cons;
  FD_VOLATILE( *cr->cons        ) = cons;

  return sz;
}

FD_FN_CONST fd_xsk_params_t const *
fd_xsk_get_params( fd_xsk_t const * xsk ) {
  return &xsk->params;
}

#if !defined(__linux__)
#error "fd_xdp_redirect_user requires Linux operating system with XDP support"
#endif

#define _DEFAULT_SOURCE
#include "fd_xdp_redirect_user.h"
#include "fd_xdp_redirect_prog.h"
#include "fd_xdp_license.h"
#include "../ebpf/fd_ebpf.h"
#include "../../util/fd_util.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>

/* fd_xdp_redirect_prog is eBPF ELF object containing the XDP program.
   It is embedded into this program. */
FD_IMPORT_BINARY( fd_xdp_redirect_prog, "src/waltz/xdp/fd_xdp_redirect_prog.o" );

fd_xdp_session_t *
fd_xdp_session_init( fd_xdp_session_t * session ) {

  *session = (fd_xdp_session_t) {
    .udp_dsts_map_fd = -1
  };

  /* Create UDP dsts map */

  union bpf_attr attr = {
    .map_type    = BPF_MAP_TYPE_HASH,
    .map_name    = "fd_xdp_udp_dsts",
    .key_size    = 8U,
    .value_size  = 4U,
    .max_entries = FD_XDP_UDP_MAP_CNT,
  };
  int udp_dsts_map_fd = (int)bpf( BPF_MAP_CREATE, &attr, sizeof(union bpf_attr) );
  if( FD_UNLIKELY( udp_dsts_map_fd<0 ) ) {
    FD_LOG_WARNING(( "bpf_map_create(BPF_MAP_TYPE_HASH,\"fd_xdp_udp_dsts\",8U,4U,%u) failed (%i-%s)",
                     FD_XDP_UDP_MAP_CNT, errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  session->udp_dsts_map_fd = udp_dsts_map_fd;
  return session;
}

fd_xdp_session_t *
fd_xdp_session_fini( fd_xdp_session_t * session ) {
  if( session->udp_dsts_map_fd >= 0 ) {
    close( session->udp_dsts_map_fd );
    session->udp_dsts_map_fd = -1;
  }
  return 0;
}

#define EBPF_KERN_LOG_BUFSZ (32768UL)
char ebpf_kern_log[ EBPF_KERN_LOG_BUFSZ ];

/* Define some kernel uapi constants in case the user is compiling
   with older kernel headers.  This is especially a problem on Ubuntu
   20.04 which supports these functions, but doesn't have them in
   the default headers. */
#ifndef BPF_LINK_CREATE
#define BPF_LINK_CREATE (28)
#endif

#ifndef BPF_XDP
#define BPF_XDP (37)
#endif

struct __attribute__((aligned(8))) bpf_link_create {
  uint prog_fd;
  uint target_ifindex;
  uint attach_type;
  uint flags;
};

fd_xdp_link_session_t *
fd_xdp_link_session_init( fd_xdp_link_session_t *  link_session,
                          fd_xdp_session_t const * session,
                          uint                     if_idx,
                          uint                     xdp_mode ) {

  uchar const * prog_elf    = fd_xdp_redirect_prog;
  ulong         prog_elf_sz = fd_xdp_redirect_prog_sz;

  *link_session = (fd_xdp_link_session_t) {
    .xsk_map_fd    = -1,
    .prog_fd       = -1,
    .prog_link_fd  = -1
  };

  int udp_dsts_map_fd = session->udp_dsts_map_fd;

  /* Validate arguments */

  if( FD_UNLIKELY( (xdp_mode & ~(uint)(XDP_FLAGS_SKB_MODE|XDP_FLAGS_DRV_MODE|XDP_FLAGS_HW_MODE) ) ) ) {
    FD_LOG_WARNING(( "unsupported xdp_mode %#x", xdp_mode ));
    return NULL;
  }

  /* Create mutable copy of ELF */

  uchar elf_copy[ 2048UL ];
  if( FD_UNLIKELY( prog_elf_sz>2048UL ) ) {
    FD_LOG_WARNING(( "ELF too large: %lu bytes", prog_elf_sz ));
    return NULL;
  }
  fd_memcpy( elf_copy, prog_elf, prog_elf_sz );

  /* Create and pin XSK map to BPF FS */

  union bpf_attr attr = {
    .map_type    = BPF_MAP_TYPE_XSKMAP,
    .key_size    = 4U,
    .value_size  = 4U,
    .max_entries = FD_XDP_XSKS_MAP_CNT,
    .map_name    = "fd_xdp_xsks"
  };
  int xsk_map_fd = (int)bpf( BPF_MAP_CREATE, &attr, sizeof(union bpf_attr) );
  if( FD_UNLIKELY( xsk_map_fd<0 ) ) {
    FD_LOG_WARNING(( "Failed to create XSKMAP (%i-%s)", errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  /* Link BPF bytecode */

  fd_ebpf_sym_t syms[ 2 ] = {
    { .name = "fd_xdp_udp_dsts", .value = (uint)udp_dsts_map_fd },
    { .name = "fd_xdp_xsks",     .value = (uint)xsk_map_fd      }
  };
  fd_ebpf_link_opts_t opts = {
    .section = "xdp",
    .sym     = syms,
    .sym_cnt = 2UL
  };
  fd_ebpf_link_opts_t * res =
    fd_ebpf_static_link( &opts, elf_copy, prog_elf_sz );

  if( FD_UNLIKELY( !res ) ) {
    FD_LOG_WARNING(( "Failed to link eBPF bytecode" ));
    close( xsk_map_fd );
    return NULL;
  }

  /* Load eBPF program into kernel */

  attr = (union bpf_attr) {
    .prog_type = BPF_PROG_TYPE_XDP,
    .insn_cnt  = (uint) ( res->bpf_sz / 8UL ),
    .insns     = (ulong)( res->bpf ),
    .license   = (ulong)FD_LICENSE,
    /* Verifier logs */
    .log_level = 6,
    .log_size  = EBPF_KERN_LOG_BUFSZ,
    .log_buf   = (ulong)ebpf_kern_log
  };
  int prog_fd = (int)bpf( BPF_PROG_LOAD, &attr, sizeof(union bpf_attr) );
  if( FD_UNLIKELY( prog_fd<0 ) ) {
    FD_LOG_WARNING(( "bpf(BPF_PROG_LOAD, insns=%p, insn_cnt=%lu) failed (%i-%s)",
                     (void *)res->bpf, res->bpf_sz / 8UL, errno, fd_io_strerror( errno ) ));
    FD_LOG_NOTICE(( "eBPF verifier log:\n%s", ebpf_kern_log ));
    close( xsk_map_fd );
    return NULL;
  }

  /* Install program to device */

  struct bpf_link_create link_create = {
    .prog_fd        = (uint)prog_fd,
    .target_ifindex = if_idx,
    .attach_type    = BPF_XDP,
    .flags          = xdp_mode
  };

  int prog_link_fd = (int)bpf( BPF_LINK_CREATE, fd_type_pun( &link_create ), sizeof(struct bpf_link_create) );
  if( FD_UNLIKELY( -1==prog_link_fd ) ) {
    if( FD_LIKELY( errno==ENOSYS ) ) {
      FD_LOG_WARNING(( "BPF_LINK_CREATE is not supported by your kernel (%i-%s). Firedancer requires a Linux "
                       "kernel version of v5.7 or newer to support fast XDP networking.  Please upgrade to a newer "
                       "kernel version.", errno, fd_io_strerror( errno ) ));
    } else if( FD_LIKELY( errno==EINVAL ) ) {
      char if_name[ IF_NAMESIZE ] = {0};
      FD_LOG_WARNING(( "BPF_LINK_CREATE failed on interface %s (%i-%s).  This likely means the network device "
                       "does not have support for XDP.  If the device is a bonding device, you will need "
                       "a kernel version of v5.15 or newer.  For other devices, see the list of kernel "
                       "support at https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#xdp",
                       if_indextoname( if_idx, if_name ), errno, fd_io_strerror( errno ) ));
    } else {
      FD_LOG_WARNING(( "BPF_LINK_CREATE failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    close( prog_fd );
    close( xsk_map_fd );
    return NULL;
  }

  link_session->xsk_map_fd   = xsk_map_fd;
  link_session->prog_fd      = prog_fd;
  link_session->prog_link_fd = prog_link_fd;

  return link_session;
}

void
fd_xdp_link_session_fini( fd_xdp_link_session_t * session ) {
  if( session->prog_link_fd >= 0 ) {
    close( session->prog_link_fd );
    session->prog_link_fd = -1;
  }
  if( session->prog_fd >= 0 ) {
    close( session->prog_fd );
    session->prog_fd = -1;
  }
  if( session->xsk_map_fd >= 0 ) {
    close( session->xsk_map_fd );
    session->xsk_map_fd = -1;
  }
}

int
fd_xdp_listen_udp_port( fd_xdp_session_t * session,
                        uint               ip4_dst_addr,
                        ushort             udp_dst_port,
                        uint               proto ) {

  int udp_dsts_fd = session->udp_dsts_map_fd;

  uint value = proto;
  ulong key   = fd_xdp_udp_dst_key( ip4_dst_addr, (ushort)udp_dst_port );
  if( FD_UNLIKELY( 0!=fd_bpf_map_update_elem( udp_dsts_fd, &key, &value, 0UL ) ) ) {
    FD_LOG_WARNING(( "bpf_map_update_elem(fd=%d,key=%#lx,value=%#x,flags=0) failed (%i-%s)",
                    udp_dsts_fd, key, value, errno, fd_io_strerror( errno ) ));
    return -1;
  }

  return 0;
}

int
fd_xdp_release_udp_port( fd_xdp_session_t * sesssion,
                         uint               ip4_dst_addr,
                         uint               udp_dst_port ) {

  int udp_dsts_fd = sesssion->udp_dsts_map_fd;

  ulong key = fd_xdp_udp_dst_key( ip4_dst_addr, udp_dst_port );
  if( FD_UNLIKELY( 0!=fd_bpf_map_delete_elem( udp_dsts_fd, &key ) ) ) {
    /* TODO: Gracefully handle error where given key does not exist.
             In that case, should return 0 here as per method description. */
    FD_LOG_WARNING(( "bpf_map_delete_elem(fd=%d,key=%#lx) failed (%i-%s)", udp_dsts_fd, key, errno, fd_io_strerror( errno ) ));
    return -1;
  }

  return 0;
}

int
fd_xdp_clear_listeners( fd_xdp_session_t * sesssion ) {

  int udp_dsts_fd = sesssion->udp_dsts_map_fd;

  /* First pass: Iterate keys in map and delete each element */

  ulong key = 0UL; /* FIXME: This fails if the key is zero, i.e. 0.0.0.0:0 */
  ulong next_key;
  for(;;) {
    /* Get next element */

    int res = fd_bpf_map_get_next_key( udp_dsts_fd, &key, &next_key );
    if( FD_UNLIKELY( res!=0 ) ) {
      if( FD_LIKELY( errno==ENOENT ) )
        break;
      FD_LOG_WARNING(( "bpf_map_get_next_key(%#lx) failed (%i-%s)", key, errno, fd_io_strerror( errno ) ));
      return -1;
    }

    /* Delete element ignoring errors */

    if( FD_UNLIKELY( 0!=fd_bpf_map_delete_elem( udp_dsts_fd, &next_key ) ) )
      FD_LOG_WARNING(( "bpf_map_delete_elem(%#lx) failed (%i-%s)", next_key, errno, fd_io_strerror( errno ) ));
  }

  /* Second pass: Check whether all keys have been deleted */

  key = 0UL;
  if( FD_UNLIKELY( 0==fd_bpf_map_get_next_key( udp_dsts_fd, &key, &next_key )
                || errno!=ENOENT ) ) {
    FD_LOG_WARNING(( "Failed to clear map of all entries" ));
    return -1;
  }

  /* Clean up */

  return 0;
}

fd_xsk_t *
fd_xsk_activate( fd_xsk_t * xsk,
                 int        xsk_map_fd ) {

  uint key   = fd_xsk_ifqueue( xsk );
  int  value = fd_xsk_fd     ( xsk );
  if( FD_UNLIKELY( 0!=fd_bpf_map_update_elem( xsk_map_fd, &key, &value, BPF_ANY ) ) ) {
    FD_LOG_WARNING(( "bpf_map_update_elem(fd=%d,key=%u,value=%#x,flags=%#x) failed (%i-%s)",
                     xsk_map_fd, key, (uint)value, (uint)BPF_ANY, errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  FD_LOG_INFO(( "Attached to XDP on interface %u queue %u",
                fd_xsk_ifidx( xsk ), fd_xsk_ifqueue( xsk ) ));
  return xsk;
}

fd_xsk_t *
fd_xsk_deactivate( fd_xsk_t * xsk,
                   int        xsk_map_fd ) {

  uint key = fd_xsk_ifqueue( xsk );
  if( FD_UNLIKELY( 0!=fd_bpf_map_delete_elem( xsk_map_fd, &key ) ) ) {
    FD_LOG_WARNING(( "bpf_map_delete_elem(fd=%d,key=%u) failed (%i-%s)", xsk_map_fd, key, errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  FD_LOG_INFO(( "Detached from XDP on interface %u queue %u",
                fd_xsk_ifidx( xsk ), fd_xsk_ifqueue( xsk ) ));
  return xsk;
}

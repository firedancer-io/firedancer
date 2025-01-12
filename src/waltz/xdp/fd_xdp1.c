#define _GNU_SOURCE
#include "fd_xdp1.h"

#include "fd_xdp_license.h"
#include "../ebpf/fd_ebpf.h"

#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/if_link.h>

/* fd_xdp_redirect_prog is eBPF ELF object containing the XDP program.
   It is embedded into this program. */

FD_IMPORT_BINARY( fd_xdp_redirect_prog2, "src/waltz/xdp/fd_xdp_redirect_prog.o" );

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

fd_xdp_fds_t
fd_xdp_install( uint           if_idx,
                uint           ip_addr,
                ulong          ports_cnt,
                ushort const * ports,
                char const *   xdp_mode ) {
  union bpf_attr attr = {
    .map_type    = BPF_MAP_TYPE_HASH,
    .map_name    = "fd_xdp_udp_dsts",
    .key_size    = 8U,
    .value_size  = 4U,
    .max_entries = 64U,
  };
  int udp_dsts_map_fd = (int)bpf( BPF_MAP_CREATE, &attr, sizeof(union bpf_attr) );
  if( FD_UNLIKELY( -1==udp_dsts_map_fd ) ) FD_LOG_ERR(( "bpf_map_create(BPF_MAP_TYPE_HASH,\"fd_xdp_udp_dsts\",8U,4U,64U) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  for( ulong bind_id=0UL; bind_id<ports_cnt; bind_id++ ) {
    ushort port = (ushort)ports[bind_id];
    if( FD_UNLIKELY( !port ) ) continue;  /* port 0 implies drop */

    uint value = 1U;
    ulong key  = ((ulong)(ip_addr)<<16 ) | fd_ushort_bswap( port );
    union bpf_attr attr = {
      .map_fd   = (uint)udp_dsts_map_fd,
      .key      = (ulong)&key,
      .value    = (ulong)&value,
      .flags    = 0UL
    };

    if( FD_UNLIKELY( -1L==bpf( BPF_MAP_UPDATE_ELEM, &attr, sizeof(union bpf_attr) ) ) ) {
      FD_LOG_ERR(( "bpf_map_update_elem(fd=%d,key=%#lx,value=%#x,flags=0) failed (%i-%s)",
                    udp_dsts_map_fd, key, value, errno, fd_io_strerror( errno ) ));
    }
  }

  uint uxdp_mode = 0;
  if(      FD_LIKELY( !strcmp( xdp_mode, "skb" ) ) ) uxdp_mode = XDP_FLAGS_SKB_MODE;
  else if( FD_LIKELY( !strcmp( xdp_mode, "drv" ) ) ) uxdp_mode = XDP_FLAGS_DRV_MODE;
  else if( FD_LIKELY( !strcmp( xdp_mode, "hw"  ) ) ) uxdp_mode = XDP_FLAGS_HW_MODE;
  else FD_LOG_ERR(( "unknown XDP mode `%.4s`", xdp_mode ));

  /* Create mutable copy of ELF */

  uchar elf_copy[ 2048UL ];
  if( FD_UNLIKELY( fd_xdp_redirect_prog2_sz>2048UL ) ) FD_LOG_ERR(( "ELF too large: %lu bytes", fd_xdp_redirect_prog2_sz ));
  fd_memcpy( elf_copy, fd_xdp_redirect_prog2, fd_xdp_redirect_prog2_sz );

  /* Create XSK map */

  union bpf_attr attr2 = {
    .map_type    = BPF_MAP_TYPE_XSKMAP,
    .key_size    = 4U,
    .value_size  = 4U,
    .max_entries = 256U,
    .map_name    = "fd_xdp_xsks"
  };
  int xsk_map_fd = (int)bpf( BPF_MAP_CREATE, &attr2, sizeof(union bpf_attr) );
  if( FD_UNLIKELY( -1==xsk_map_fd ) ) FD_LOG_ERR(( "Failed to create XSKMAP (%i-%s)", errno, fd_io_strerror( errno ) ));

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
    fd_ebpf_static_link( &opts, elf_copy, fd_xdp_redirect_prog2_sz );

  if( FD_UNLIKELY( !res ) ) FD_LOG_ERR(( "Failed to link eBPF bytecode" ));

  /* Load eBPF program into kernel */

  char ebpf_kern_log[ 32768UL ];
  attr = (union bpf_attr) {
    .prog_type = BPF_PROG_TYPE_XDP,
    .insn_cnt  = (uint) ( res->bpf_sz / 8UL ),
    .insns     = (ulong)( res->bpf ),
    .license   = (ulong)FD_LICENSE,
    /* Verifier logs */
    .log_level = 6,
    .log_size  = 32768UL,
    .log_buf   = (ulong)ebpf_kern_log
  };
  int prog_fd = (int)bpf( BPF_PROG_LOAD, &attr, sizeof(union bpf_attr) );
  if( FD_UNLIKELY( -1==prog_fd ) ) {
    FD_LOG_WARNING(( "bpf(BPF_PROG_LOAD, insns=%p, insn_cnt=%lu) failed (%i-%s)",
                     (void *)res->bpf, res->bpf_sz / 8UL, errno, fd_io_strerror( errno ) ));
    FD_LOG_ERR(( "eBPF verifier log:\n%s", ebpf_kern_log ));
  }

  /* Install program to device */

  struct bpf_link_create link_create = {
    .prog_fd        = (uint)prog_fd,
    .target_ifindex = if_idx,
    .attach_type    = BPF_XDP,
    .flags          = uxdp_mode
  };

  int prog_link_fd = (int)bpf( BPF_LINK_CREATE, fd_type_pun( &link_create ), sizeof(struct bpf_link_create) );
  if( FD_UNLIKELY( -1==prog_link_fd ) ) {
    if( FD_LIKELY( errno==ENOSYS ) ) {
      FD_LOG_ERR(( "BPF_LINK_CREATE is not supported by your kernel (%i-%s). Firedancer requires a Linux "
                   "kernel version of v5.7 or newer to support fast XDP networking.  Please upgrade to a newer "
                   "kernel version.", errno, fd_io_strerror( errno ) ));
    } else if( FD_LIKELY( errno==EINVAL ) ) {
      char if_name[ IF_NAMESIZE ] = {0};
      FD_LOG_ERR(( "BPF_LINK_CREATE failed on interface %s (%i-%s).  This likely means the network device "
                   "does not have support for XDP.  If the device is a bonding device, you will need "
                   "a kernel version of v5.15 or newer.  For other devices, see the list of kernel "
                   "support at https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#xdp",
                   if_indextoname( if_idx, if_name ), errno, fd_io_strerror( errno ) ));
    } else {
      FD_LOG_ERR(( "BPF_LINK_CREATE failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
  }

  if( FD_UNLIKELY( -1==close( udp_dsts_map_fd ) ) ) FD_LOG_ERR(( "close(%d) failed (%i-%s)", udp_dsts_map_fd, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==close( prog_fd ) ) ) FD_LOG_ERR(( "close(%d) failed (%i-%s)", xsk_map_fd, errno, fd_io_strerror( errno ) ));

  return (fd_xdp_fds_t){
    .xsk_map_fd   = xsk_map_fd,
    .prog_link_fd = prog_link_fd,
  };
}

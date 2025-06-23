#define _GNU_SOURCE
#include "fd_xdp1.h"

#include "fd_xdp_license.h"
#include "../ebpf/fd_linux_bpf.h"
#include "../ebpf/fd_ebpf_asm.h"

#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/if_link.h>

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

ulong
fd_xdp_gen_program( ulong          code_buf[ 512 ],
                    int            xsks_fd,
                    uint           listen_ip4_addr,
                    ushort const * ports,
                    ulong          ports_cnt ) {
  if( FD_UNLIKELY( ports_cnt>16UL ) ) {
    FD_LOG_ERR(( "Too many XDP UDP ports (%lu)", ports_cnt ));
  }

  ulong * code = code_buf;
  *(code++) = FD_EBPF( ldxw, r2, r1, 0         );  // r2 = xdp_md->data
  *(code++) = FD_EBPF( ldxw, r3, r1, 4         );  // r3 = xdp_md->data_end
  *(code++) = FD_EBPF( mov64_reg, r4, r2       );
  *(code++) = FD_EBPF( add64_imm, r4, 42       );
  *(code++) = FD_EBPF( jgt_reg, r4, r3, +1     );  // if r2+42 > r3 goto lbl_pass
  *(code++) = FD_EBPF( ldxh, r5, r2, 12        );
  *(code++) = FD_EBPF( jne_imm, r5, 0x0008, +1 );  // if eth_hdr->net_type != IP4 goto lbl_pass
  if( listen_ip4_addr!=0 ) {
    *(code++) = FD_EBPF( ldxw, r5, r2, 30 );
    *(code++) = FD_EBPF( jne_imm, r5, listen_ip4_addr, +1 );  // if eth_hdr->daddr != listen_ip4_addr goto lbl_pass
  }
  *(code++) = FD_EBPF( ldxb, r5, r2, 23        );
  *(code++) = FD_EBPF( jne_imm, r5, 17, +1     );  // if ip4_hdr->protocol != UDP goto lbl_pass
  *(code++) = FD_EBPF( ldxb, r5, r2, 14        );
  *(code++) = FD_EBPF( and64_imm, r5, 0x0f     );
  *(code++) = FD_EBPF( lsh64_imm, r5, 2        );  // r5 = ip4_hdr->ihl*4
  *(code++) = FD_EBPF( add64_reg, r2, r5       );
  *(code++) = FD_EBPF( mov64_reg, r4, r2       );
  *(code++) = FD_EBPF( add64_imm, r4, 22       );
  *(code++) = FD_EBPF( jgt_reg, r4, r3, +1     );  // if udp_hdr+1 > r3 goto lbl_pass
  *(code++) = FD_EBPF( ldxh, r4, r2, 16        );  // r4 = udp_hdr->dst_port
  for( ulong i=0UL; i<ports_cnt; i++ ) {
    ushort port = (ushort)fd_ushort_bswap( ports[ i ] );
    if( !port ) continue;
    *(code++) = FD_EBPF( jeq_imm, r4, port, +2 ); // if dst_port == ports[i] goto lbl_redirect
  }
  ulong * lbl_pass = code;
  *(code++) = FD_EBPF( mov64_imm, r0, XDP_PASS );
  *(code++) = FD_EBPF_exit;                       // return XDP_PASS
  ulong * lbl_redirect = code;
  *(code++) = FD_EBPF( ldxw, r2, r1, 16        ); // r2 = xdp_md->rx_queue_index
  *(code++) = FD_EBPF( lddw, r1, xsks_fd       ); // r1 = xsk_map_fd ll
  *(code++) = 0;
  *(code++) = FD_EBPF( mov64_imm, r3, 0        ); // r3 = 0
  *(code++) = FD_EBPF( call, 0x33              );
  *(code++) = FD_EBPF_exit;                       // return bpf_redirect_map(r1,r2,r3)
  // ulong * lbl_drop = code;
  // *(code++) = FD_EBPF( mov64_imm, r0, XDP_DROP );
  // *(code++) = FD_EBPF_exit;
  ulong * code_end = code;
  ulong   code_cnt = (ulong)( code_end-code_buf );

  FD_LOG_HEXDUMP_DEBUG(( "XDP program", code_buf, code_cnt*sizeof(ulong) ));

  /* Fill in jump labels */

  for( ulong i=0UL; i<code_cnt; i++ ) {
    if( (code_buf[ i ] & 0x05)==0x05 ) {
      ulong * jmp_target;
      uint    jmp_label = (code_buf[ i ]>>16) & 0xFFFF;
      switch( jmp_label ) {
      case 0: continue;
      case 1: jmp_target = lbl_pass;     break;
      case 2: jmp_target = lbl_redirect; break;
      // case 3: jmp_target = lbl_drop;     break;
      default: FD_LOG_ERR(( "Invalid jump instruction (%016lx)", fd_ulong_bswap( code_buf[ i ] ) ));
      }
      long   off   = jmp_target-code_buf-(long)i-1;
      ushort off_u = (ushort)(short)off;
      code_buf[ i ] = (code_buf[ i ] & 0xFFFFFFFF0000FFFF) | ((ulong)off_u<<16UL);
    }
  }

  return code_cnt;
}

fd_xdp_fds_t
fd_xdp_install( uint           if_idx,
                uint           listen_ip4_addr,
                ulong          ports_cnt,
                ushort const * ports,
                char const *   xdp_mode ) {
  /* Check args */

  uint uxdp_mode = 0;
  if(      !strcmp( xdp_mode, "skb"     ) ) uxdp_mode = XDP_FLAGS_SKB_MODE;
  else if( !strcmp( xdp_mode, "drv"     ) ) uxdp_mode = XDP_FLAGS_DRV_MODE;
  else if( !strcmp( xdp_mode, "hw"      ) ) uxdp_mode = XDP_FLAGS_HW_MODE;
  else if( !strcmp( xdp_mode, "generic" ) ) uxdp_mode = 0U;
  else FD_LOG_ERR(( "unknown XDP mode `%s`", xdp_mode ));

  uint true_port_cnt = 0U;
  for( ulong i=0UL; i<ports_cnt; i++ ) true_port_cnt += !!ports[ i ];
  if( FD_UNLIKELY( !true_port_cnt ) ) FD_LOG_ERR(( "XDP program is not listening on any UDP ports" ));

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

  /* Load eBPF program into kernel */

  ulong code_buf[ 512 ];
  ulong code_cnt = fd_xdp_gen_program( code_buf, xsk_map_fd, listen_ip4_addr, ports, ports_cnt );

  char ebpf_kern_log[ 32768UL ];
  union bpf_attr attr = {
    .prog_type = BPF_PROG_TYPE_XDP,
    .insn_cnt  = (uint)code_cnt,
    .insns     = (ulong)code_buf,
    .license   = (ulong)FD_LICENSE,
    /* Verifier logs */
    .log_level = 6,
    .log_size  = 32768UL,
    .log_buf   = (ulong)ebpf_kern_log
  };
  int prog_fd = (int)bpf( BPF_PROG_LOAD, &attr, sizeof(union bpf_attr) );
  if( FD_UNLIKELY( -1==prog_fd ) ) {
    FD_LOG_WARNING(( "bpf(BPF_PROG_LOAD) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
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

  if( FD_UNLIKELY( -1==close( prog_fd ) ) ) FD_LOG_ERR(( "close(%d) failed (%i-%s)", xsk_map_fd, errno, fd_io_strerror( errno ) ));

  return (fd_xdp_fds_t){
    .xsk_map_fd   = xsk_map_fd,
    .prog_link_fd = prog_link_fd,
  };
}

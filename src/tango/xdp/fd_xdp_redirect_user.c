#if !defined(__linux__)
#error "fd_xdp_redirect_user requires Linux operating system with XDP support"
#endif

#define _DEFAULT_SOURCE
#include "fd_xdp_redirect_user.h"
#include "fd_xdp_redirect_prog.h"
#include "fd_xdp_license.h"
#include "../../ballet/ebpf/fd_ebpf.h"
#include "../../util/fd_util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>

/* fd_xdp_validate_name_cstr: Validates whether the path component cstr
   s is well-formed and fits into the buffer of sz bufsz.  Returns 0 on
   success and -1 on error.  Reasons for error are logged to
   FD_LOG_WARNING tagged with the given name. */
static int
fd_xdp_validate_name_cstr( char const * s,
                           ulong        bufsz,
                           char const * name ) {
  if( FD_UNLIKELY( !s ) ) {
    FD_LOG_WARNING(( "NULL %s", name ));
    return -1;
  }
  if( FD_UNLIKELY( s[0]=='\0' ) ) {
    FD_LOG_WARNING(( "empty %s", name ));
    return -1;
  }
  if( FD_UNLIKELY( fd_cstr_nlen( s, bufsz )==bufsz ) ) {
    FD_LOG_WARNING(( "oversz %s", name ));
    return -1;
  }
  if( FD_UNLIKELY( strchr( s, '/' ) ) ) {
    FD_LOG_WARNING(( "%s contains '/'", name ));
    return -1;
  }
  return 0;
}

static void
fd_xdp_reperm( char const * path,
               uint         mode,
               int          uid,
               int          gid,
               int          is_dir ) {

  if( FD_UNLIKELY( 0!=chown( path, (uint)uid, (uint)gid ) ) ) {
    FD_LOG_WARNING(( "chown(%s,%u,%u) failed (%d-%s)",
                     path, uid, gid, errno, fd_io_strerror( errno ) ));
    return;
  }

  mode &= fd_uint_if( is_dir, 0777, 0666 );
  if( FD_UNLIKELY( 0!=chmod( path, mode ) ) ) {
    FD_LOG_WARNING(( "chown(%s,%u,%u) failed (%d-%s)",
                     path, uid, gid, errno, fd_io_strerror( errno ) ));
    return;
  }
}

int
fd_xdp_init( char const * app_name,
             uint         mode,
             int          uid,
             int          gid ) {
  /* Validate arguments */

  if( FD_UNLIKELY( 0!=fd_xdp_validate_name_cstr( app_name, NAME_MAX, "app_name" ) ) )
    return -1;

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
    return -1;
  }

  /* Pin UDP dsts map to BPF FS */

  char path[ PATH_MAX ];
  snprintf( path, PATH_MAX, "/sys/fs/bpf/%s", app_name );

  if( FD_UNLIKELY( 0!=mkdir( path, mode ) && errno!=EEXIST ) ) {
    FD_LOG_WARNING(( "mkdir(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    close( udp_dsts_map_fd );
    return -1;
  }

  fd_xdp_reperm( path, mode, uid, gid, 1 );

  snprintf( path, PATH_MAX, "/sys/fs/bpf/%s/udp_dsts", app_name );
  if( FD_UNLIKELY( 0!=fd_bpf_obj_pin( udp_dsts_map_fd, path ) ) ) {
    FD_LOG_WARNING(( "bpf_obj_pin(%u,%s) failed (%i-%s)", udp_dsts_map_fd, path, errno, fd_io_strerror( errno ) ));
    close( udp_dsts_map_fd );
    return -1;
  }

  fd_xdp_reperm( path, mode, uid, gid, 0 );

  FD_LOG_NOTICE(( "Activated XDP environment at /sys/fs/bpf/%s", app_name ));

  close( udp_dsts_map_fd );
  return 0;
}

static DIR *
fd_opendirat( int          fd,
              char const * name ) {
  int subfd = openat( fd, name, 0 );
  if( FD_UNLIKELY( subfd<0 ) ) return NULL;

  return fdopendir( subfd );
}

int
fd_xdp_fini( char const * app_name ) {
  /* Validate arguments */

  if( FD_UNLIKELY( 0!=fd_xdp_validate_name_cstr( app_name, NAME_MAX, "app_name" ) ) )
    return -1;

  /* Open BPF FS dir */

  int bpffs_dir = open( "/sys/fs/bpf", 0 );
  if( FD_UNLIKELY( bpffs_dir<0 ) ) {
    FD_LOG_WARNING(( "open(/sys/fs/bpf) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return -1;
  }

  /* Open app dir in BPF FS */

  DIR * app_dir = fd_opendirat( bpffs_dir, app_name );
  if( FD_UNLIKELY( !app_dir ) ) {
    if( FD_LIKELY( errno==ENOENT ) ) {
      FD_LOG_INFO(( "skipping XDP destroy as /sys/fs/bpf/%s does not exist", app_name ));
    }
    FD_LOG_WARNING(( "open(/sys/fs/bpf/%s) failed (%i-%s)", app_name, errno, fd_io_strerror( errno ) ));
    return -1;
  }

  /* List interfaces */

  struct dirent * iface_ent;
  while( (iface_ent = readdir( app_dir )) ) {
    if( iface_ent->d_type    != 4 /*DT_DIR*/ ) continue;
    if( iface_ent->d_name[0] == '.'          ) continue;
    /* Remove each iface */
    if( FD_UNLIKELY( 0!=fd_xdp_unhook_iface( app_name, iface_ent->d_name ) ) )
      FD_LOG_WARNING(( "fd_xdp_unhook_iface(%s,%s) failed", app_name, iface_ent->d_name ));
  }

  /* Remove UDP dst map */

  unlinkat( dirfd( app_dir ), "udp_dsts", 0 );

  /* Remove app dir */

  closedir( app_dir );
  unlinkat( bpffs_dir, app_name, AT_REMOVEDIR );

  /* Clean up */

  close( bpffs_dir );
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

int
fd_xdp_hook_iface( char const * app_name,
                   char const * ifname,
                   uint         xdp_mode,
                   void const * prog_elf,
                   ulong        prog_elf_sz ) {

  /* Validate arguments */

  if( FD_UNLIKELY( 0!=fd_xdp_validate_name_cstr( app_name, NAME_MAX, "app_name" ) ) )
    return -1;
  if( FD_UNLIKELY( 0!=fd_xdp_validate_name_cstr( ifname, IF_NAMESIZE, "ifname" ) ) )
    return -1;

  if( FD_UNLIKELY( !prog_elf ) ) {
    FD_LOG_WARNING(( "NULL prog_elf" ));
    return -1;
  }
  if( FD_UNLIKELY( prog_elf_sz==0UL ) ) {
    FD_LOG_WARNING(( "zero prog_elf_sz" ));
    return -1;
  }
  if( FD_UNLIKELY( (xdp_mode & ~(uint)(XDP_FLAGS_SKB_MODE|XDP_FLAGS_DRV_MODE|XDP_FLAGS_HW_MODE) ) ) ) {
    FD_LOG_WARNING(( "unsupported xdp_mode %#x", xdp_mode ));
    return -1;
  }

  /* Create mutable copy of ELF */

  uchar elf_copy[ 2048UL ];
  if( FD_UNLIKELY( prog_elf_sz>2048UL ) ) {
    FD_LOG_WARNING(( "ELF too large: %lu bytes", prog_elf_sz ));
    return -1;
  }
  fd_memcpy( elf_copy, prog_elf, prog_elf_sz );

  /* Find interface */

  uint ifidx = if_nametoindex( ifname );
  if( FD_UNLIKELY( ifidx==0U ) ) {
    FD_LOG_WARNING(( "if_nametoindex(%s) failed (%i-%s)", ifname, errno, fd_io_strerror( errno ) ));
    return -1;
  }

  /* Find uid, gid, mode of install dir */

  char path[ PATH_MAX ];

  snprintf( path, PATH_MAX, "/sys/fs/bpf/%s", app_name );

  struct stat install_stat = {0};
  if( FD_UNLIKELY( 0!=stat( path, &install_stat ) ) ) {
    FD_LOG_WARNING(( "stat(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return -1;
  }

  /* Create dirs */

  snprintf( path, PATH_MAX, "/sys/fs/bpf/%s/%s", app_name, ifname );
  int rc = mkdir( path, install_stat.st_mode & 0777 );
  if( FD_UNLIKELY( rc!=0 && errno!=EEXIST ) ) {
    FD_LOG_WARNING(( "mkdir(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return -1;
  }

  fd_xdp_reperm( path, install_stat.st_mode, (int)install_stat.st_uid, (int)install_stat.st_gid, 1 );

  /* Find UDP dsts map fd */

  snprintf( path, PATH_MAX, "/sys/fs/bpf/%s/udp_dsts", app_name );

  int udp_dsts_map_fd = fd_bpf_obj_get( path );
  if( FD_UNLIKELY( udp_dsts_map_fd<0 ) ) {
    FD_LOG_WARNING(( "bpf_obj_get(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return -1;
  }

  /* Create and pin XSK map to BPF FS */

  union bpf_attr attr = {
    .map_type    = BPF_MAP_TYPE_XSKMAP,
    .key_size    = 4U,
    .value_size  = 4U,
    .max_entries = FD_XDP_XSKS_MAP_CNT,
    .map_name    = "fd_xdp_xsks"
  };
  int xsks_fd = (int)bpf( BPF_MAP_CREATE, &attr, sizeof(union bpf_attr) );
  if( FD_UNLIKELY( xsks_fd<0 ) ) {
    FD_LOG_WARNING(( "Failed to create XSKMAP (%i-%s)", errno, fd_io_strerror( errno ) ));
    close( udp_dsts_map_fd );
    return -1;
  }

  snprintf( path, PATH_MAX, "/sys/fs/bpf/%s/%s/xsks", app_name, ifname );
  if( FD_UNLIKELY( 0!=fd_bpf_obj_pin( xsks_fd, path ) ) ) {
    FD_LOG_WARNING(( "bpf_obj_pin(xsks_fd,%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    close( xsks_fd );
    close( udp_dsts_map_fd );
    return -1;
  }

  fd_xdp_reperm( path, install_stat.st_mode, (int)install_stat.st_uid, (int)install_stat.st_gid, 0 );

  /* Link BPF bytecode */

  fd_ebpf_sym_t syms[ 2 ] = {
    { .name = "fd_xdp_udp_dsts", .value = (uint)udp_dsts_map_fd },
    { .name = "fd_xdp_xsks",     .value = (uint)xsks_fd         }
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
    close( xsks_fd );
    close( udp_dsts_map_fd );
    return -1;
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
    return -1;
  }

  /* Pin eBPF program */

  snprintf( path, PATH_MAX, "/sys/fs/bpf/%s/%s/xdp_prog", app_name, ifname );
  if( FD_UNLIKELY( 0!=fd_bpf_obj_pin( prog_fd, path ) ) ) {
    FD_LOG_WARNING(( "bpf_obj_pin(prog_fd,%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    close( prog_fd );
    close( xsks_fd );
    close( udp_dsts_map_fd );
    return -1;
  }

  fd_xdp_reperm( path, install_stat.st_mode, (int)install_stat.st_uid, (int)install_stat.st_gid, 0 );

  /* Install program to device */
  struct bpf_link_create link_create = {
    .prog_fd        = (uint)prog_fd,
    .target_ifindex = ifidx,
    .attach_type    = BPF_XDP,
    .flags          = xdp_mode
  };

  int prog_link_fd = (int)bpf( BPF_LINK_CREATE, fd_type_pun( &link_create ), sizeof(struct bpf_link_create) );
  if( FD_UNLIKELY( -1==prog_link_fd ) ) {
    if( FD_LIKELY( errno==ENOSYS ) ) {
      FD_LOG_WARNING(( "BPF_LINK_CREATE is not supported by your kernel. "
                       "Please upgrade to a newer kernel version." ));
    } else {
      FD_LOG_WARNING(( "BPF_LINK_CREATE failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    close( prog_link_fd );
    close( prog_fd );
    close( xsks_fd );
    close( udp_dsts_map_fd );
    return -1;
  }

  /* Pin program link */

  snprintf( path, PATH_MAX, "/sys/fs/bpf/%s/%s/xdp_link", app_name, ifname );
  if( FD_UNLIKELY( 0!=fd_bpf_obj_pin( prog_link_fd, path ) ) ) {
    FD_LOG_WARNING(( "Failed to pin XDP link (%i-%s)", errno, fd_io_strerror( errno ) ));
    return -1;
  }

  fd_xdp_reperm( path, install_stat.st_mode, (int)install_stat.st_uid, (int)install_stat.st_gid, 0 );

  FD_TEST( !close( prog_link_fd ) );
  FD_TEST( !close( prog_fd ) );
  FD_TEST( !close( xsks_fd ) );
  FD_TEST( !close( udp_dsts_map_fd ) );

  return 0;
}

int
fd_xdp_unhook_iface( char const * app_name,
                     char const * ifname ) {
  /* Validate arguments */

  if( FD_UNLIKELY( 0!=fd_xdp_validate_name_cstr( app_name, NAME_MAX, "app_name" ) ) )
    return -1;
  if( FD_UNLIKELY( 0!=fd_xdp_validate_name_cstr( ifname, IF_NAMESIZE, "ifname" ) ) )
    return -1;

  /* Note that we deliberately do not check whether the given ifname is
     a valid network device name.  BPF FS files can stick around even if
     the underlying netdev disappears. */

  /* Open BPF FS */

  char path[ PATH_MAX ];
  snprintf( path, PATH_MAX, "/sys/fs/bpf/%s/%s", app_name, ifname );

  int dir_fd = open( path, 0 );
  if( FD_UNLIKELY( dir_fd<0 ) ) {
    if( FD_LIKELY( errno==ENOENT ) ) {
      /* No need to clean up if dir does not exist */
      FD_LOG_INFO(( "skipping XDP unpin as %s does not exist", path ));
      close( dir_fd );
      return 0;
    }
    FD_LOG_WARNING(( "open(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return -1;
  }

  /* Remove pinned maps */

  if( FD_UNLIKELY( 0!=unlinkat( dir_fd, "xsks", 0 ) && errno != ENOENT ) ) {
    FD_LOG_WARNING(( "unlinkat(\"%s\",\"xsks\",0) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    close( dir_fd );
    return -1;
  }

  /* Remove pinned program */

  if( FD_UNLIKELY( 0!=unlinkat( dir_fd, "xdp_prog", 0 ) && errno != ENOENT ) ) {
    FD_LOG_WARNING(( "unlinkat(\"%s\",\"xdp_prog\",0) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    close( dir_fd );
    return -1;
  }

  /* Remove pinned program link */

  if( FD_UNLIKELY( 0!=unlinkat( dir_fd, "xdp_link", 0 ) && errno != ENOENT ) ) {
    FD_LOG_WARNING(( "unlinkat(\"%s\",\"xdp_link\",0) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    close( dir_fd );
    return -1;
  }

  /* Clean up */

  close( dir_fd );
  if( FD_UNLIKELY( -1==rmdir( path ) ) )
    FD_LOG_WARNING(( "rmdir(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  return 0;
}

static int
fd_xdp_get_udp_dsts_map( char const * app_name ) {
  char path[ PATH_MAX ];
  snprintf( path, PATH_MAX, "/sys/fs/bpf/%s/udp_dsts", app_name );

  int udp_dsts_fd = fd_bpf_obj_get( path );
  if( FD_UNLIKELY( udp_dsts_fd<0 ) ) {
    FD_LOG_WARNING(( "bpf_obj_get(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return -1;
  }

  return udp_dsts_fd;
}

int
fd_xdp_listen_udp_ports( char const * app_name,
                         uint         ip4_dst_addr,
                         ulong        udp_dst_ports_sz,
                         ushort *     udp_dst_ports,
                         uint         proto ) {
  /* Validate arguments */

  if( FD_UNLIKELY( 0!=fd_xdp_validate_name_cstr( app_name, NAME_MAX, "app_name" ) ) )
    return -1;

  /* Open map */

  int udp_dsts_fd = fd_xdp_get_udp_dsts_map( app_name );
  if( FD_UNLIKELY( udp_dsts_fd<0 ) ) return -1;

  /* Insert element */

  uint value = proto;
  for( ulong i=0; i<udp_dst_ports_sz; i++ ) {
    ulong key   = fd_xdp_udp_dst_key( ip4_dst_addr, udp_dst_ports[i] );

    if( FD_UNLIKELY( 0!=fd_bpf_map_update_elem( udp_dsts_fd, &key, &value, 0UL ) ) ) {
      FD_LOG_WARNING(( "bpf_map_update_elem(fd=%d,key=%#lx,value=%#x,flags=0) failed (%i-%s)",
                      udp_dsts_fd, key, value, errno, fd_io_strerror( errno ) ));
      close( udp_dsts_fd );
      return -1;
    }
  }

  /* Clean up */

  close( udp_dsts_fd );
  return 0;
}

int
fd_xdp_release_udp_port( char const * app_name,
                         uint         ip4_dst_addr,
                         uint         udp_dst_port ) {
  /* Validate arguments */

  if( FD_UNLIKELY( 0!=fd_xdp_validate_name_cstr( app_name, NAME_MAX, "app_name" ) ) )
    return -1;

  /* Open map */

  int udp_dsts_fd = fd_xdp_get_udp_dsts_map( app_name );
  if( FD_UNLIKELY( udp_dsts_fd<0 ) ) return -1;

  /* Delete element */

  ulong key = fd_xdp_udp_dst_key( ip4_dst_addr, udp_dst_port );

  if( FD_UNLIKELY( 0!=fd_bpf_map_delete_elem( udp_dsts_fd, &key ) ) ) {
    /* TODO: Gracefully handle error where given key does not exist.
             In that case, should return 0 here as per method description. */

    FD_LOG_WARNING(( "bpf_map_delete_elem(fd=%d,key=%#lx) failed (%i-%s)", udp_dsts_fd, key, errno, fd_io_strerror( errno ) ));
    close( udp_dsts_fd );
    return -1;
  }

  /* Clean up */

  close( udp_dsts_fd );
  return 0;
}

int
fd_xdp_clear_listeners( char const * app_name ) {
  /* Validate arguments */

  if( FD_UNLIKELY( 0!=fd_xdp_validate_name_cstr( app_name, NAME_MAX, "app_name" ) ) )
    return -1;

  /* Open map */

  int udp_dsts_fd = fd_xdp_get_udp_dsts_map( app_name );
  if( FD_UNLIKELY( udp_dsts_fd<0 ) ) return -1;

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
      close( udp_dsts_fd );
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
    close( udp_dsts_fd );
    return -1;
  }

  /* Clean up */

  close( udp_dsts_fd );
  return 0;
}

static int
fd_xdp_get_xsks_map( char const * app_name,
                     char const * ifname ) {
  char path[ PATH_MAX ];
  snprintf( path, PATH_MAX, "/sys/fs/bpf/%s/%s/xsks", app_name, ifname );

  int xsks_fd = fd_bpf_obj_get( path );
  if( FD_UNLIKELY( xsks_fd<0 ) ) {
    FD_LOG_WARNING(( "bpf_obj_get(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return -1;
  }

  return xsks_fd;
}

int
fd_xsk_activate( fd_xsk_t * xsk ) {
  int xsks_fd = fd_xdp_get_xsks_map( fd_xsk_app_name( xsk ), fd_xsk_ifname( xsk ) );
  if( FD_UNLIKELY( xsks_fd<0 ) ) return -1;

  uint key   = fd_xsk_ifqueue( xsk );
  int  value = fd_xsk_fd     ( xsk );
  if( FD_UNLIKELY( 0!=fd_bpf_map_update_elem( xsks_fd, &key, &value, BPF_ANY ) ) ) {
    FD_LOG_WARNING(( "bpf_map_update_elem(fd=%d,key=%u,value=%#x,flags=%#x) failed (%i-%s)",
                     xsks_fd, key, value, BPF_ANY, errno, fd_io_strerror( errno ) ));
    close( xsks_fd );
    return -1;
  }

  FD_LOG_NOTICE(( "Attached to XDP instance %s on interface %s queue %u",
                  fd_xsk_app_name( xsk ), fd_xsk_ifname( xsk ), fd_xsk_ifqueue( xsk ) ));

  close( xsks_fd );
  return 0;
}

int
fd_xsk_deactivate( fd_xsk_t * xsk ) {
  int xsks_fd = fd_xdp_get_xsks_map( fd_xsk_app_name( xsk ), fd_xsk_ifname( xsk ) );
  if( FD_UNLIKELY( xsks_fd<0 ) ) return -1;

  uint key = fd_xsk_ifqueue( xsk );
  if( FD_UNLIKELY( 0!=fd_bpf_map_delete_elem( xsks_fd, &key ) ) ) {
    FD_LOG_WARNING(( "bpf_map_delete_elem(fd=%d,key=%u) failed (%i-%s)", xsks_fd, key, errno, fd_io_strerror( errno ) ));
    close( xsks_fd );
    return -1;
  }

  FD_LOG_NOTICE(( "Detached from %s XDP instance on interface %s queue %u",
                  fd_xsk_app_name( xsk ), fd_xsk_ifname( xsk ), fd_xsk_ifqueue( xsk ) ));

  close( xsks_fd );
  return 0;
}

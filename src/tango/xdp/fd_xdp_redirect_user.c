#if !defined(__linux__) || !FD_HAS_LIBBPF
#error "fd_xdp_redirect_user requires Linux operating system with XDP support"
#endif

#include "fd_xdp_redirect_user.h"
#include "fd_xdp_redirect_prog.h"
#include "../../util/fd_util.h"

#define _DEFAULT_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

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
  if( FD_UNLIKELY( strnlen( s, bufsz )==bufsz ) ) {
    FD_LOG_WARNING(( "oversz %s", name ));
    return -1;
  }
  if( FD_UNLIKELY( strchr( s, '/' ) ) ) {
    FD_LOG_WARNING(( "%s contains '/'", name ));
    return -1;
  }
  return 0;
}


int
fd_xdp_init( char const * app_name ) {
  /* Validate arguments */

  if( FD_UNLIKELY( 0!=fd_xdp_validate_name_cstr( app_name, NAME_MAX, "app_name" ) ) )
    return -1;

  /* Create UDP dsts map */

  struct bpf_map_create_opts map_create_opts = { .sz = sizeof(struct bpf_map_create_opts) };
  int udp_dsts_map_fd = bpf_map_create(
      /* map_type    */ BPF_MAP_TYPE_HASH,
      /* map_name    */ "firedancer_udp_dsts",
      /* key_size    */ 8U,
      /* value_size  */ 4U,
      /* max_entries */ FD_XDP_UDP_MAP_CNT,
      /* opts        */ &map_create_opts );
  if( FD_UNLIKELY( udp_dsts_map_fd<0 ) ) {
    FD_LOG_WARNING(( "bpf_map_create(BPF_MAP_TYPE_HASH,\"firedancer_udp_dsts\",8U,4U,%u,%p) failed (%d-%s)",
                     FD_XDP_UDP_MAP_CNT, (void *)&map_create_opts, errno, strerror( errno ) ));
    return -1;
  }

  /* Pin UDP dsts map to BPF FS */

  char path[ PATH_MAX ];
  snprintf( path, PATH_MAX, "/sys/fs/bpf/%s", app_name );

  if( FD_UNLIKELY( 0!=mkdir( path, 0777UL ) && errno!=EEXIST ) ) {
    FD_LOG_WARNING(( "mkdir(%s) failed (%d-%s)",
                     path, errno, strerror( errno ) ));
    close( udp_dsts_map_fd );
    return -1;
  }

  snprintf( path, PATH_MAX, "/sys/fs/bpf/%s/udp_dsts", app_name );
  if( FD_UNLIKELY( 0!=bpf_obj_pin( udp_dsts_map_fd, path ) ) ) {
    FD_LOG_WARNING(( "bpf_obj_pin(%u,%s) failed (%d-%s)",
                     udp_dsts_map_fd, path, errno, strerror( errno ) ));
    close( udp_dsts_map_fd );
    return -1;
  }

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
    FD_LOG_WARNING(( "open(/sys/fs/bpf) failed (%d-%s)", errno, strerror( errno ) ));
    return -1;
  }

  /* Open app dir in BPF FS */

  DIR * app_dir = fd_opendirat( bpffs_dir, app_name );
  if( FD_UNLIKELY( !app_dir ) ) {
    if( FD_LIKELY( errno==ENOENT ) ) {
      FD_LOG_INFO(( "skipping XDP destroy as /sys/fs/bpf/%s does not exist", app_name ));
    }
    FD_LOG_WARNING(( "open(/sys/fs/bpf/%s) failed (%d-%s)", app_name, errno, strerror( errno ) ));
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


int
fd_xdp_hook_iface( char const * app_name,
                   char const * ifname,
                   uint         xdp_mode,
                   int          priority,
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

  /* Find interface */

  uint ifidx = if_nametoindex( ifname );
  if( FD_UNLIKELY( ifidx==0U ) ) {
    FD_LOG_WARNING(( "if_nametoindex(%s) failed (%d-%s)",
                     ifname, errno, strerror( errno ) ));
    return -1;
  }

  /* Find pinned UDP dsts map fd */

  char path[ PATH_MAX ];
  snprintf( path, PATH_MAX, "/sys/fs/bpf/%s/udp_dsts", app_name );

  int udp_dsts_map_fd = bpf_obj_get( path );
  if( FD_UNLIKELY( udp_dsts_map_fd<0 ) ) {
    FD_LOG_WARNING(( "bpf_obj_get(%s) failed (%d-%s)",
                     path, errno, strerror( errno ) ));
    return -1;
  }

  /* Load and relocate eBPF object file.
     Create eBPF maps as implied by BTF data. */

  struct bpf_object_open_opts open_opts = {
    .sz          = sizeof(struct bpf_object_open_opts),
    .object_name = "fd_xdp_redirect_prog",
  };

  struct bpf_object * obj = bpf_object__open_mem( prog_elf, prog_elf_sz, &open_opts );
  if( FD_UNLIKELY( !obj ) ) {
    FD_LOG_WARNING(( "bpf_object__open_mem(%p,%lu) failed (%d-%s)",
                     prog_elf, prog_elf_sz, errno, strerror( errno ) ));
    close( udp_dsts_map_fd );
    return -1;
  }

  /* Load XDP program from object file */

  struct bpf_program * prog = bpf_object__find_program_by_name( obj, "firedancer_redirect" );
  if( FD_UNLIKELY( !prog ) ) {
    FD_LOG_WARNING(( "bpf_object__find_program_by_name(%p,\"firedancer_redirect\") failed (%d-%s)",
                     (void *)obj, errno, strerror( errno ) ));
    bpf_object__close( obj );
    close( udp_dsts_map_fd );
    return -1;
  }

  /* Load UDP dsts map from object file.
     Replace previously created map with shared pinned map (kinda ugly) */

  struct bpf_map * udp_dsts_map = bpf_object__find_map_by_name( obj, "firedancer_udp_dsts" );
  if( FD_UNLIKELY( !udp_dsts_map ) ) {
    FD_LOG_WARNING(( "bpf_object__find_map_by_name(%p,\"firedancer_udp_dsts\") failed (%d-%s)",
                     (void *)obj, errno, strerror( errno ) ));
    bpf_object__close( obj );
    close( udp_dsts_map_fd );
    return -1;
  }

  if( FD_UNLIKELY( 0!=bpf_map__reuse_fd( udp_dsts_map, udp_dsts_map_fd ) ) ) {
    FD_LOG_WARNING(( "bpf_map__reuse_fd(%p,%u) failed (%d-%s)",
                     (void *)udp_dsts_map, udp_dsts_map_fd, errno, strerror( errno ) ));
    bpf_object__close( obj );
    close( udp_dsts_map_fd );
    return -1;
  }

  close( udp_dsts_map_fd );

  /* Load XSK map from object file. */

  struct bpf_map * xsks_map = bpf_object__find_map_by_name( obj, "firedancer_xsks" );
  if( FD_UNLIKELY( !xsks_map ) ) {
    FD_LOG_WARNING(( "bpf_object__find_map_by_name(%p,\"firedancer_xsks\") failed (%d-%s)",
                     (void *)obj, errno, strerror( errno ) ));
    bpf_object__close( obj );
    return -1;
  }

  /* Load eBPF object into kernel. */

  if( FD_UNLIKELY( 0!=bpf_object__load( obj ) ) ) {
    FD_LOG_WARNING(( "bpf_object__load(%p) failed (%d-%s)",
                     (void *)obj, errno, strerror( errno ) ));
    bpf_object__close( obj );
    return -1;
  }

  /* Attach program to interface */

  /* TODO: Set XDP program priority */
  (void)priority;

  struct bpf_link * link = bpf_program__attach_xdp( prog, (int)ifidx );
  if( FD_UNLIKELY( !link ) ) {
    FD_LOG_WARNING(( "bpf_program__attach_xdp(%p, %u) failed (%d-%s)",
                     (void *)obj, xdp_mode, errno, strerror( errno ) ));
    bpf_object__close( obj );
    return -1;
  }

  /* Pin program to BPF FS */

  snprintf( path, PATH_MAX, "/sys/fs/bpf/%s/%s", app_name, ifname );
  if( FD_UNLIKELY( 0!=mkdir( path, 0777UL ) && errno!=EEXIST ) ) {
    FD_LOG_WARNING(( "mkdir(%s) failed (%d-%s)",
                     path, errno, strerror( errno ) ));
    bpf_object__close( obj );
    return -1;
  }

  snprintf( path, PATH_MAX, "/sys/fs/bpf/%s/%s/xdp_prog", app_name, ifname );
  if( FD_UNLIKELY( 0!=bpf_program__pin( prog, path ) ) ) {
    FD_LOG_WARNING(( "bpf_program__pin(%p,%s) failed (%d-%s)",
                     (void *)prog, path, errno, strerror( errno ) ));
    bpf_object__close( obj );
    return -1;
  }

  /* Pin XSK map to BPF FS */

  snprintf( path, PATH_MAX, "/sys/fs/bpf/%s/%s/xsks", app_name, ifname );
  if( FD_UNLIKELY( 0!=bpf_map__pin( xsks_map, path ) ) ) {
    FD_LOG_WARNING(( "bpf_map__pin(%p,%s) failed (%d-%s)",
                     (void *)xsks_map, path, errno, strerror( errno ) ));
    bpf_object__close( obj );
    return -1;
  }

  /* Pin program link to BPF FS */

  snprintf( path, PATH_MAX, "/sys/fs/bpf/%s/%s/xdp_link", app_name, ifname );
  if( FD_UNLIKELY( 0!=bpf_link__pin( link, path ) ) ) {
    FD_LOG_WARNING(( "bpf_link__pin(%p,%s) failed (%d-%s)",
                     (void *)link, path, errno, strerror( errno ) ));
    bpf_object__close( obj );
    return -1;
  }

  /* Release temporary resources */

  bpf_object__close( obj );

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
    FD_LOG_WARNING(( "open(%s) failed (%d-%s)", path, errno, strerror( errno ) ));
    return -1;
  }

  /* Remove pinned maps */

  if( FD_UNLIKELY( 0!=unlinkat( dir_fd, "xsks", 0 ) ) ) {
    FD_LOG_WARNING(( "unlinkat(\"%s\",\"xsks\",0) failed (%d-%s)",
                     path, errno, strerror( errno ) ));
    close( dir_fd );
    return -1;
  }

  /* Remove pinned program */

  if( FD_UNLIKELY( 0!=unlinkat( dir_fd, "xdp_prog", 0 ) ) ) {
    FD_LOG_WARNING(( "unlinkat(\"%s\",\"xdp_prog\",0) failed (%d-%s)",
                     path, errno, strerror( errno ) ));
    close( dir_fd );
    return -1;
  }

  /* Remove pinned program link */

  if( FD_UNLIKELY( 0!=unlinkat( dir_fd, "xdp_link", 0 ) ) ) {
    FD_LOG_WARNING(( "unlinkat(\"%s\",\"xdp_link\",0) failed (%d-%s)",
                     path, errno, strerror( errno ) ));
    close( dir_fd );
    return -1;
  }

  /* Clean up */

  close( dir_fd );
  rmdir( path );
  return 0;
}


static int
fd_xdp_get_udp_dsts_map( char const * app_name ) {
  char path[ PATH_MAX ];
  snprintf( path, PATH_MAX, "/sys/fs/bpf/%s/udp_dsts", app_name );

  int udp_dsts_fd = bpf_obj_get( path );
  if( FD_UNLIKELY( udp_dsts_fd<0 ) ) {
    FD_LOG_WARNING(( "bpf_obj_get(%s) failed (%d-%s)", path, errno, strerror( errno ) ));
    return -1;
  }

  return udp_dsts_fd;
}


int
fd_xdp_listen_udp_port( char const * app_name,
                        uint         ip4_dst_addr,
                        uint         udp_dst_port,
                        uint         proto ) {
  /* Validate arguments */

  if( FD_UNLIKELY( 0!=fd_xdp_validate_name_cstr( app_name, NAME_MAX, "app_name" ) ) )
    return -1;

  /* Open map */

  int udp_dsts_fd = fd_xdp_get_udp_dsts_map( app_name );
  if( FD_UNLIKELY( udp_dsts_fd<0 ) ) return -1;

  /* Insert element */

  ulong key   = fd_xdp_udp_dst_key( ip4_dst_addr, udp_dst_port );
  uint  value = proto;

  if( FD_UNLIKELY( 0!=bpf_map_update_elem( udp_dsts_fd, &key, &value, 0UL ) ) ) {
    FD_LOG_WARNING(( "bpf_map_update_elem(fd=%d,key=%#lx,value=%#x,flags=0) failed (%d-%s)",
                     udp_dsts_fd, key, value, errno, strerror( errno ) ));
    close( udp_dsts_fd );
    return -1;
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

  if( FD_UNLIKELY( 0!=bpf_map_delete_elem( udp_dsts_fd, &key ) ) ) {
    FD_LOG_WARNING(( "bpf_map_delete_elem(fd=%d,key=%#lx) failed (%d-%s)",
                     udp_dsts_fd, key, errno, strerror( errno ) ));
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

  int xsks_fd = bpf_obj_get( path );
  if( FD_UNLIKELY( xsks_fd<0 ) ) {
    FD_LOG_WARNING(( "bpf_obj_get(%s) failed (%d-%s)", path, errno, strerror( errno ) ));
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
  if( FD_UNLIKELY( 0!=bpf_map_update_elem( xsks_fd, &key, &value, 0UL ) ) ) {
    FD_LOG_WARNING(( "bpf_map_update_elem(fd=%d,key=%u,value=%#x,flags=0) failed (%d-%s)",
                     xsks_fd, key, value, errno, strerror( errno ) ));
    close( xsks_fd );
    return -1;
  }

  close( xsks_fd );
  return 0;
}

int
fd_xsk_deactivate( fd_xsk_t * xsk ) {
  int xsks_fd = fd_xdp_get_xsks_map( fd_xsk_app_name( xsk ), fd_xsk_ifname( xsk ) );
  if( FD_UNLIKELY( xsks_fd<0 ) ) return -1;

  uint key = fd_xsk_ifqueue( xsk );
  if( FD_UNLIKELY( 0!=bpf_map_delete_elem( xsks_fd, &key ) ) ) {
    FD_LOG_WARNING(( "bpf_map_delete_elem(fd=%d,key=%u) failed (%d-%s)",
                     xsks_fd, key, errno, strerror( errno ) ));
    close( xsks_fd );
    return -1;
  }

  close( xsks_fd );
  return 0;
}

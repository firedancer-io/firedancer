#define _GNU_SOURCE

#include "configure.h"
#include "../../../platform/fd_file_util.h"
#include "../../../platform/fd_sys_util.h"
#include "../../../../ballet/json/fd_jtok.h"
#include "../../../../disco/net/iavf/fd_iavf.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define NAME "iavf"

#define IAVF_SYSFS_ROOT "/sys"
#define IAVF_RUN_ROOT   "/run"

typedef struct {
  uchar mac[ 6 ];
  int   mac_valid;
  int   spoofchk;
  int   spoofchk_valid;
  int   trust;
  int   trust_valid;
  int   link_state_auto;
  int   link_state_valid;
} iavf_vf_policy_t;

static int
enabled( fd_config_t const * config ) {
  return !strcmp( config->net.provider, "iavf" );
}

static int
iavf_vfio_avail( void ) {
  struct stat st;
  return !stat( IAVF_SYSFS_ROOT "/bus/pci/drivers/vfio-pci", &st ) && S_ISDIR( st.st_mode );
}

static void
perm( fd_cap_chk_t *      chk,
      fd_config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "create an Intel SR-IOV Virtual Function and bind it to vfio-pci" );
}

static void
init_perm( fd_cap_chk_t *      chk,
           fd_config_t const * config ) {
  perm( chk, config );
  if( !iavf_vfio_avail() ) fd_cap_chk_cap( chk, NAME, CAP_SYS_MODULE, "run modprobe to load the vfio-pci kernel module" );
}

static int
iavf_hex( char c ) {
  if( c>='0' && c<='9' ) return c-'0';
  if( c>='a' && c<='f' ) return c-'a'+10;
  if( c>='A' && c<='F' ) return c-'A'+10;
  return -1;
}

static int
iavf_parse_mac( char const * text,
                uchar        mac[ 6 ] ) {
  if( FD_UNLIKELY( strlen( text )!=17UL ) ) return -1;
  for( ulong i=0UL; i<6UL; i++ ) {
    int hi = iavf_hex( text[ i*3UL     ] );
    int lo = iavf_hex( text[ i*3UL+1UL ] );
    if( FD_UNLIKELY( hi<0 || lo<0 || (i<5UL && text[ i*3UL+2UL ]!=':') ) ) return -1;
    mac[ i ] = (uchar)((hi<<4) | lo);
  }
  if( FD_UNLIKELY( !(mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]) || (mac[0] & 1U) ) ) return -1;
  return 0;
}

static void
iavf_path( char       path[ PATH_MAX ],
           char const * fmt,
           char const * pf_if,
           uint         vf_idx ) {
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, fmt, pf_if, vf_idx ) );
}

static int
iavf_pf_mac( fd_config_t const * config,
             uchar               mac[ 6 ] ) {
  char path[ PATH_MAX ];
  iavf_path( path, IAVF_SYSFS_ROOT "/class/net/%s/address", config->net.interface, 0U );

  char text[ 32 ];
  ulong text_sz;
  if( FD_UNLIKELY( !fd_file_util_read_cstr( path, text, sizeof(text), &text_sz ) ) ) return -1;
  if( text_sz && text[ text_sz-1UL ]=='\n' ) text[ --text_sz ] = '\0';
  if( FD_UNLIKELY( iavf_parse_mac( text, mac ) ) ) {
    errno = EBADMSG;
    return -1;
  }
  return 0;
}

static int
iavf_write( char const * path,
            char const * value ) {
  int fd = open( path, O_WRONLY | O_CLOEXEC );
  if( FD_UNLIKELY( fd<0 ) ) return -1;

  ulong value_sz = strlen( value );
  long written = write( fd, value, value_sz );
  if( FD_UNLIKELY( written<0 || (ulong)written!=value_sz ) ) {
    int err = written<0 ? errno : EIO;
    close( fd );
    errno = err;
    return -1;
  }
  return close( fd );
}

static char const *
iavf_basename( char const * path ) {
  char const * slash = strrchr( path, '/' );
  return slash ? slash+1 : path;
}

static int
iavf_pf_pci( fd_config_t const * config,
             char                pf_pci[ 13 ] ) {
  char path[ PATH_MAX ];
  iavf_path( path, IAVF_SYSFS_ROOT "/class/net/%s/device", config->net.interface, 0U );
  char resolved[ PATH_MAX ];
  if( FD_UNLIKELY( !realpath( path, resolved ) ) ) return -1;
  char const * pci = iavf_basename( resolved );
  if( FD_UNLIKELY( strlen( pci )!=12UL ) ) {
    errno = ENODEV;
    return -1;
  }
  fd_cstr_ncpy( pf_pci, pci, 13UL );
  return 0;
}

static int
iavf_vf_pci( fd_config_t const * config,
             char                vf_pci[ 13 ] ) {
  char path[ PATH_MAX ];
  iavf_path( path, IAVF_SYSFS_ROOT "/class/net/%s/device/virtfn%u", config->net.interface, config->net.iavf.vf_index );
  char resolved[ PATH_MAX ];
  if( FD_UNLIKELY( !realpath( path, resolved ) ) ) return -1;
  char const * pci = iavf_basename( resolved );
  if( FD_UNLIKELY( strlen( pci )!=12UL ) ) {
    errno = ENODEV;
    return -1;
  }
  fd_cstr_ncpy( vf_pci, pci, 13UL );
  return 0;
}

static int
iavf_driver( char const * pci,
             char         driver[ 32 ] ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, IAVF_SYSFS_ROOT "/bus/pci/devices/%s/driver", pci ) );
  char resolved[ PATH_MAX ];
  if( FD_UNLIKELY( !realpath( path, resolved ) ) ) return -1;
  char const * name = iavf_basename( resolved );
  if( FD_UNLIKELY( strlen( name )>=32UL ) ) {
    errno = ENAMETOOLONG;
    return -1;
  }
  fd_cstr_ncpy( driver, name, 32UL );
  return 0;
}

static int
iavf_pf_driver( fd_config_t const * config,
                char                driver[ 32 ] ) {
  char pf_pci[ 13 ];
  if( FD_UNLIKELY( iavf_pf_pci( config, pf_pci ) ) ) return -1;
  return iavf_driver( pf_pci, driver );
}

static int
iavf_numvfs( fd_config_t const * config,
             uint *              numvfs ) {
  char path[ PATH_MAX ];
  iavf_path( path, IAVF_SYSFS_ROOT "/class/net/%s/device/sriov_numvfs", config->net.interface, 0U );
  return fd_file_util_read_uint( path, numvfs );
}

static int
iavf_set_numvfs( fd_config_t const * config,
                 uint                numvfs ) {
  char path[ PATH_MAX ];
  iavf_path( path, IAVF_SYSFS_ROOT "/class/net/%s/device/sriov_numvfs", config->net.interface, 0U );
  return fd_file_util_write_uint( path, numvfs );
}

static int
iavf_validate_vf( fd_config_t const * config,
                  char const *        vf_pci ) {
  char pf_pci[ 13 ];
  if( FD_UNLIKELY( iavf_pf_pci( config, pf_pci ) ) ) return -1;

  char path[ PATH_MAX ];
  char resolved[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, IAVF_SYSFS_ROOT "/bus/pci/devices/%s/physfn", vf_pci ) );
  if( FD_UNLIKELY( !realpath( path, resolved ) ) ) return -1;
  if( FD_UNLIKELY( strcmp( iavf_basename( resolved ), pf_pci ) ) ) {
    FD_LOG_WARNING(( "VF %s belongs to PF %s, expected %s (%i-%s)", vf_pci, iavf_basename( resolved ), pf_pci, ENODEV, fd_io_strerror( ENODEV ) ));
    errno = ENODEV;
    return -1;
  }

  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, IAVF_SYSFS_ROOT "/bus/pci/devices/%s/iommu_group", vf_pci ) );
  if( FD_UNLIKELY( !realpath( path, resolved ) ) ) return -1;
  if( FD_UNLIKELY( !fd_cstr_printf_check( path, sizeof(path), NULL, "%s/devices", resolved ) ) ) {
    errno = ENAMETOOLONG;
    return -1;
  }

  DIR * dir = opendir( path );
  if( FD_UNLIKELY( !dir ) ) return -1;
  ulong device_cnt = 0UL;
  int matched = 0;
  for(;;) {
    errno = 0;
    struct dirent * entry = readdir( dir );
    if( !entry ) break;
    if( !strcmp( entry->d_name, "." ) || !strcmp( entry->d_name, ".." ) ) continue;
    device_cnt++;
    matched |= !strcmp( entry->d_name, vf_pci );
  }
  int err = errno;
  if( FD_UNLIKELY( closedir( dir ) && !err ) ) err = errno;
  if( FD_UNLIKELY( err ) ) {
    errno = err;
    return -1;
  }
  if( FD_UNLIKELY( device_cnt!=1UL || !matched ) ) {
    FD_LOG_WARNING(( "VF %s is not alone in its IOMMU group (%i-%s)", vf_pci, EXDEV, fd_io_strerror( EXDEV ) ));
    errno = EXDEV;
    return -1;
  }
  return 0;
}

static int
iavf_iommu_group( char const * vf_pci,
                  char         group[ 32 ] ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, IAVF_SYSFS_ROOT "/bus/pci/devices/%s/iommu_group", vf_pci ) );
  char resolved[ PATH_MAX ];
  if( FD_UNLIKELY( !realpath( path, resolved ) ) ) return -1;
  char const * name = iavf_basename( resolved );
  ulong name_sz = strlen( name );
  if( FD_UNLIKELY( !name_sz || name_sz>=32UL ) ) {
    errno = EBADMSG;
    return -1;
  }
  for( ulong i=0UL; i<name_sz; i++ ) {
    if( FD_UNLIKELY( name[i]<'0' || name[i]>'9' ) ) {
      errno = EBADMSG;
      return -1;
    }
  }
  fd_cstr_ncpy( group, name, 32UL );
  return 0;
}

static int
iavf_vfio_user( char const * vf_pci,
                uint *       user_pid ) {
  char group[ 32 ];
  if( FD_UNLIKELY( iavf_iommu_group( vf_pci, group ) ) ) return -1;
  char vfio_path[ 64 ];
  FD_TEST( fd_cstr_printf_check( vfio_path, sizeof(vfio_path), NULL, "/dev/vfio/%s", group ) );

  DIR * proc = opendir( "/proc" );
  if( FD_UNLIKELY( !proc ) ) return -1;
  int err = 0;
  for(;;) {
    errno = 0;
    struct dirent * process = readdir( proc );
    if( !process ) {
      err = errno;
      break;
    }
    char const * p = process->d_name;
    if( !*p ) continue;
    for( ; *p>='0' && *p<='9'; p++ ) {}
    if( *p ) continue;

    char fd_dir_path[ PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( fd_dir_path, sizeof(fd_dir_path), NULL, "/proc/%s/fd", process->d_name ) );
    DIR * fd_dir = opendir( fd_dir_path );
    if( !fd_dir ) {
      if( errno==ENOENT ) continue;
      err = errno;
      break;
    }
    for(;;) {
      errno = 0;
      struct dirent * fd_entry = readdir( fd_dir );
      if( !fd_entry ) {
        if( errno ) err = errno;
        break;
      }
      if( fd_entry->d_name[0]=='.' ) continue;
      char fd_path[ PATH_MAX ];
      FD_TEST( fd_cstr_printf_check( fd_path, sizeof(fd_path), NULL, "%s/%s", fd_dir_path, fd_entry->d_name ) );
      char target[ PATH_MAX ];
      long target_sz = readlink( fd_path, target, sizeof(target)-1UL );
      if( target_sz<0L ) {
        if( errno==ENOENT ) continue;
        err = errno;
        break;
      }
      target[ target_sz ] = '\0';
      if( strcmp( target, vfio_path ) ) continue;
      ulong pid = strtoul( process->d_name, NULL, 10 );
      if( FD_UNLIKELY( pid>UINT_MAX ) ) {
        err = ERANGE;
        break;
      }
      *user_pid = (uint)pid;
      if( FD_UNLIKELY( closedir( fd_dir ) && !err ) ) err = errno;
      if( FD_UNLIKELY( closedir( proc ) && !err ) ) err = errno;
      if( err ) {
        errno = err;
        return -1;
      }
      return 1;
    }
    if( FD_UNLIKELY( closedir( fd_dir ) && !err ) ) err = errno;
    if( err ) break;
  }
  if( FD_UNLIKELY( closedir( proc ) && !err ) ) err = errno;
  if( err ) {
    errno = err;
    return -1;
  }
  return 0;
}

static int
iavf_ip_run( char * const argv[],
             char *       output,
             ulong        output_cap,
             ulong *      output_sz ) {
  int pipefd[ 2 ];
  if( output && FD_UNLIKELY( pipe2( pipefd, O_CLOEXEC ) ) ) return -1;

  pid_t pid = fork();
  if( FD_UNLIKELY( pid<0 ) ) {
    int err = errno;
    if( output ) { close( pipefd[0] ); close( pipefd[1] ); }
    errno = err;
    return -1;
  }
  if( !pid ) {
    if( output ) {
      close( pipefd[0] );
      if( FD_UNLIKELY( dup2( pipefd[1], STDOUT_FILENO )<0 ) ) {
        FD_LOG_WARNING(( "dup2 for ip output failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        _exit( 1 );
      }
      if( pipefd[1]!=STDOUT_FILENO ) close( pipefd[1] );
    }
    char * const envp[] = { NULL };
    execve( "/sbin/ip", argv, envp );
    FD_LOG_WARNING(( "execve(/sbin/ip) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    _exit( 1 );
  }

  ulong len = 0UL;
  int read_err = 0;
  if( output ) {
    close( pipefd[1] );
    for(;;) {
      char buf[ 4096 ];
      long read_sz = read( pipefd[0], buf, sizeof(buf) );
      if( read_sz<0L ) {
        if( errno==EINTR ) continue;
        read_err = errno;
        break;
      }
      if( !read_sz ) break;
      if( (ulong)read_sz>output_cap-len ) read_err = EOVERFLOW;
      else if( !read_err ) {
        fd_memcpy( output+len, buf, (ulong)read_sz );
        len += (ulong)read_sz;
      }
    }
    if( FD_UNLIKELY( close( pipefd[0] ) && !read_err ) ) read_err = errno;
  }

  int status;
  while( FD_UNLIKELY( waitpid( pid, &status, 0 )<0 ) ) {
    if( errno==EINTR ) continue;
    return -1;
  }
  if( FD_UNLIKELY( read_err ) ) {
    errno = read_err;
    return -1;
  }
  if( FD_UNLIKELY( !WIFEXITED( status ) || WEXITSTATUS( status ) ) ) {
    /* ip and the child setup path report failures on stderr. */
    if( !WIFEXITED( status ) ) FD_LOG_WARNING(( "ip terminated, wait status %#x (%i-%s)", status, EIO, fd_io_strerror( EIO ) ));
    errno = EIO;
    return -1;
  }
  if( output_sz ) *output_sz = len;
  return 0;
}

static int
iavf_policy_set( fd_config_t const * config,
                 uchar const         mac[ 6 ] ) {
  char vf_idx[ 11 ];
  char mac_text[ 18 ];
  FD_TEST( fd_cstr_printf_check( vf_idx, sizeof(vf_idx), NULL, "%u", config->net.iavf.vf_index ) );
  FD_TEST( fd_cstr_printf_check( mac_text, sizeof(mac_text), NULL, "%02x:%02x:%02x:%02x:%02x:%02x",
                                 (uint)mac[0], (uint)mac[1], (uint)mac[2],
                                 (uint)mac[3], (uint)mac[4], (uint)mac[5] ) );
  char * argv[] = { "ip", "link", "set", "dev", (char *)config->net.interface,
                   "vf", vf_idx, "mac", mac_text, "spoofchk", "off",
                   "trust", "off", "state", "auto", NULL };
  FD_LOG_NOTICE(( "%sRUN: `/sbin/ip link set dev %s vf %s mac %s spoofchk off trust off state auto`%s",
                  fd_log_style_dim(), config->net.interface, vf_idx, mac_text, fd_log_style_normal() ));
  return iavf_ip_run( argv, NULL, 0UL, NULL );
}

static void
iavf_policy_parse_vf( fd_jtok_t *        j,
                      uint               vf_idx,
                      iavf_vf_policy_t * policy,
                      int *              found ) {
  iavf_vf_policy_t entry = {0};
  ulong entry_idx = ULONG_MAX;
  fd_jtok_str_t key;
  fd_jtok_obj_enter( j );
  while( fd_jtok_obj_next( j, &key ) ) {
    if( fd_jtok_str_eq( &key, "vf" ) ) fd_jtok_ulong( j, &entry_idx );
    else if( fd_jtok_str_eq( &key, "address" ) ) {
      char mac_text[ 18 ];
      fd_jtok_cstr( j, mac_text, sizeof(mac_text) );
      if( !fd_jtok_err( j ) ) entry.mac_valid = !iavf_parse_mac( mac_text, entry.mac );
    } else if( fd_jtok_str_eq( &key, "spoofchk" ) ) {
      fd_jtok_bool( j, &entry.spoofchk );
      entry.spoofchk_valid = 1;
    } else if( fd_jtok_str_eq( &key, "trust" ) ) {
      fd_jtok_bool( j, &entry.trust );
      entry.trust_valid = 1;
    } else if( fd_jtok_str_eq( &key, "link_state" ) ) {
      char state[ 16 ];
      fd_jtok_cstr( j, state, sizeof(state) );
      entry.link_state_auto = !strcmp( state, "auto" );
      entry.link_state_valid = 1;
    }
  }
  if( entry_idx==(ulong)vf_idx ) {
    *policy = entry;
    *found = 1;
  }
}

static int
iavf_policy_get( fd_config_t const * config,
                 iavf_vf_policy_t * policy ) {
  char output[ 16384 ];
  ulong output_sz;
  char * argv[] = { "ip", "-j", "link", "show", "dev", (char *)config->net.interface, NULL };
  if( FD_UNLIKELY( iavf_ip_run( argv, output, sizeof(output), &output_sz ) ) ) return -1;

  fd_jtok_t j[1];
  fd_jtok_init( j, output, output_sz );
  fd_jtok_arr_enter( j );
  ulong link_cnt = 0UL;
  int found = 0;
  char ifname[ IFNAMSIZ ] = {0};
  iavf_vf_policy_t result = {0};
  while( fd_jtok_arr_next( j ) ) {
    link_cnt++;
    fd_jtok_str_t key;
    fd_jtok_obj_enter( j );
    while( fd_jtok_obj_next( j, &key ) ) {
      if( fd_jtok_str_eq( &key, "ifname" ) ) fd_jtok_cstr( j, ifname, sizeof(ifname) );
      else if( fd_jtok_str_eq( &key, "vfinfo_list" ) ) {
        fd_jtok_arr_enter( j );
        while( fd_jtok_arr_next( j ) ) iavf_policy_parse_vf( j, config->net.iavf.vf_index, &result, &found );
      }
    }
  }
  if( FD_UNLIKELY( fd_jtok_fini( j ) || link_cnt!=1UL || strcmp( ifname, config->net.interface ) ) ) {
    errno = EBADMSG;
    return -1;
  }
  if( FD_UNLIKELY( !found ) ) {
    errno = ENODATA;
    return -1;
  }
  *policy = result;
  return 0;
}

static void
iavf_marker_path( fd_config_t const * config,
                  char                path[ PATH_MAX ] ) {
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, IAVF_RUN_ROOT "/firedancer-iavf-%s-%u.owned",
                                 config->net.interface, config->net.iavf.vf_index ) );
}

static int
iavf_marker_read( fd_config_t const * config,
                  char                vf_pci[ 13 ] ) {
  char path[ PATH_MAX ];
  iavf_marker_path( config, path );
  ulong len;
  char text[ 32 ];
  if( FD_UNLIKELY( !fd_file_util_read_cstr( path, text, sizeof(text), &len ) ) ) return -1;
  if( len && text[ len-1UL ]=='\n' ) text[ --len ] = '\0';
  if( FD_UNLIKELY( len!=12UL ) ) {
    errno = EBADMSG;
    return -1;
  }
  fd_cstr_ncpy( vf_pci, text, 13UL );
  return 0;
}

static int
iavf_marker_write( fd_config_t const * config,
                   char const *        vf_pci ) {
  char path[ PATH_MAX ];
  iavf_marker_path( config, path );
  int fd = open( path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600 );
  if( FD_UNLIKELY( fd<0 ) ) return -1;
  char text[ 16 ];
  ulong text_sz;
  FD_TEST( fd_cstr_printf_check( text, sizeof(text), &text_sz, "%s\n", vf_pci ) );
  long written = write( fd, text, text_sz );
  if( FD_UNLIKELY( written<0 || (ulong)written!=text_sz ) ) {
    int err = written<0 ? errno : EIO;
    close( fd );
    unlink( path );
    errno = err;
    return -1;
  }
  if( FD_UNLIKELY( close( fd ) ) ) {
    int err = errno;
    unlink( path );
    errno = err;
    return -1;
  }
  return 0;
}

static int
iavf_unbind( char const * vf_pci ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, IAVF_SYSFS_ROOT "/bus/pci/devices/%s/driver/unbind", vf_pci ) );
  return iavf_write( path, vf_pci );
}

static int
iavf_driver_override( char const * vf_pci,
                      char const * driver ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, IAVF_SYSFS_ROOT "/bus/pci/devices/%s/driver_override", vf_pci ) );
  return iavf_write( path, driver );
}

static int
iavf_bind_vfio( char const * vf_pci ) {
  struct stat st;
  if( FD_UNLIKELY( stat( IAVF_SYSFS_ROOT "/bus/pci/drivers/vfio-pci", &st ) ) ) return -1;

  char driver[ 32 ];
  int has_driver = !iavf_driver( vf_pci, driver );
  if( has_driver && !strcmp( driver, "vfio-pci" ) ) return 0;
  if( FD_UNLIKELY( iavf_driver_override( vf_pci, "vfio-pci" ) ) ) return -1;
  if( has_driver && FD_UNLIKELY( iavf_unbind( vf_pci ) ) ) return -1;
  if( FD_UNLIKELY( iavf_write( IAVF_SYSFS_ROOT "/bus/pci/drivers_probe", vf_pci ) ) ) return -1;
  if( FD_UNLIKELY( iavf_driver( vf_pci, driver ) ) ) return -1;
  if( FD_UNLIKELY( strcmp( driver, "vfio-pci" ) ) ) {
    FD_LOG_WARNING(( "VF %s bound to %s, expected vfio-pci (%i-%s)", vf_pci, driver, ENODEV, fd_io_strerror( ENODEV ) ));
    errno = ENODEV;
    return -1;
  }
  return 0;
}

static void
init( fd_config_t const * config ) {
  if( FD_UNLIKELY( config->net.iavf.vf_index ) ) FD_LOG_ERR(( "only VF 0 is supported" ));

  uchar mac[ 6 ];
  if( FD_UNLIKELY( iavf_pf_mac( config, mac ) ) ) {
    FD_LOG_ERR(( "PF %s MAC read failed (%i-%s)", config->net.interface, errno, fd_io_strerror( errno ) ));
  }

  char pf_driver[ 32 ];
  if( FD_UNLIKELY( iavf_pf_driver( config, pf_driver ) ) ) {
    FD_LOG_ERR(( "PF %s driver lookup failed (%i-%s)", config->net.interface, errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( strcmp( pf_driver, "ice" ) && strcmp( pf_driver, "i40e" ) ) ) {
    FD_LOG_ERR(( "PF %s driver %s unsupported, need ice or i40e", config->net.interface, pf_driver ));
  }

  uint totalvfs;
  char path[ PATH_MAX ];
  iavf_path( path, IAVF_SYSFS_ROOT "/class/net/%s/device/sriov_totalvfs", config->net.interface, 0U );
  if( FD_UNLIKELY( fd_file_util_read_uint( path, &totalvfs ) ) ) {
    FD_LOG_ERR(( "read(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( !totalvfs ) ) FD_LOG_ERR(( "PF %s has no SR-IOV support", config->net.interface ));

  uint numvfs;
  if( FD_UNLIKELY( iavf_numvfs( config, &numvfs ) ) ) {
    FD_LOG_ERR(( "PF %s VF count read failed (%i-%s)", config->net.interface, errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( numvfs ) ) {
    FD_LOG_ERR(( "PF %s already has %u VFs, refusing to replace them", config->net.interface, numvfs ));
  }

  if( FD_UNLIKELY( access( "/sbin/ip", X_OK ) ) ) FD_LOG_ERR(( "`/sbin/ip` unavailable (iproute2/iproute)" ));

  if( FD_UNLIKELY( !iavf_vfio_avail() ) ) {
    FD_LOG_NOTICE(( "%sRUN: `modprobe vfio-pci`%s", fd_log_style_dim(), fd_log_style_normal() ));
    if( FD_UNLIKELY( fd_sys_util_modprobe( "vfio-pci", 0 ) ) ) FD_LOG_ERR(( "vfio-pci module load failed" ));
    if( FD_UNLIKELY( !iavf_vfio_avail() ) ) FD_LOG_ERR(( "vfio-pci unavailable after module load" ));
  }

  if( FD_UNLIKELY( iavf_set_numvfs( config, 1U ) ) ) {
    FD_LOG_ERR(( "PF %s VF 0 creation failed (%i-%s)", config->net.interface, errno, fd_io_strerror( errno ) ));
  }

  char vf_pci[ 13 ];
  if( FD_UNLIKELY( iavf_vf_pci( config, vf_pci ) || iavf_validate_vf( config, vf_pci ) ) ) {
    FD_LOG_ERR(( "PF %s VF 0 lookup or validation failed (%i-%s)", config->net.interface, errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( iavf_marker_write( config, vf_pci ) ) ) {
    int marker_err = errno;
    if( FD_UNLIKELY( iavf_set_numvfs( config, 0U ) ) ) {
      FD_LOG_ERR(( "VF %s ownership write failed (%i-%s), rollback failed (%i-%s)",
                   vf_pci, marker_err, fd_io_strerror( marker_err ), errno, fd_io_strerror( errno ) ));
    }
    FD_LOG_ERR(( "VF %s ownership record failed (%i-%s)", vf_pci, marker_err, fd_io_strerror( marker_err ) ));
  }

  if( FD_UNLIKELY( iavf_policy_set( config, mac ) ) ) {
    FD_LOG_ERR(( "ip link set VF %u on %s failed (%i-%s)",
                 config->net.iavf.vf_index, config->net.interface, errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( iavf_bind_vfio( vf_pci ) ) ) {
    FD_LOG_ERR(( "VF %s bind to vfio-pci failed (%i-%s)", vf_pci, errno, fd_io_strerror( errno ) ));
  }

  fd_iavf_hw_pci_info_t pci_info[ 1 ];
  if( FD_UNLIKELY( fd_iavf_hw_pci_probe( pci_info, vf_pci ) ) ) {
    FD_LOG_ERR(( "VF %s PCI probe failed (%i-%s)", vf_pci, errno, fd_io_strerror( errno ) ));
  }
}

static int
fini( fd_config_t const * config,
      int                 pre_init FD_PARAM_UNUSED ) {
  uint numvfs;
  if( FD_UNLIKELY( iavf_numvfs( config, &numvfs ) ) ) {
    if( errno==ENOENT ) return 0;
    FD_LOG_ERR(( "PF %s VF count read failed (%i-%s)", config->net.interface, errno, fd_io_strerror( errno ) ));
  }
  if( !numvfs ) return 0;
  if( FD_UNLIKELY( numvfs>1U ) ) {
    FD_LOG_ERR(( "PF %s has %u VFs, refusing to remove any", config->net.interface, numvfs ));
  }

  char vf_pci[ 13 ];
  if( FD_UNLIKELY( iavf_vf_pci( config, vf_pci ) || iavf_validate_vf( config, vf_pci ) ) ) {
    FD_LOG_ERR(( "PF %s VF %u identification failed (%i-%s)",
                 config->net.interface, config->net.iavf.vf_index, errno, fd_io_strerror( errno ) ));
  }

  char owned_pci[ 13 ];
  if( FD_UNLIKELY( iavf_marker_read( config, owned_pci ) ) ) {
    if( errno==ENOENT ) return 0;
    FD_LOG_ERR(( "VF ownership marker read failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( strcmp( owned_pci, vf_pci ) ) ) {
    FD_LOG_ERR(( "VF ownership mismatch, marker %s, actual %s", owned_pci, vf_pci ));
  }

  uint user_pid;
  int in_use = iavf_vfio_user( vf_pci, &user_pid );
  if( FD_UNLIKELY( in_use<0 ) ) FD_LOG_ERR(( "VF %s use check failed (%i-%s)", vf_pci, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( in_use ) ) {
    FD_LOG_ERR(( "VF %s in use by PID %u, refusing to remove", vf_pci, user_pid ));
  }

  char driver[ 32 ];
  if( !iavf_driver( vf_pci, driver ) && FD_UNLIKELY( iavf_unbind( vf_pci ) ) ) {
    FD_LOG_ERR(( "VF %s unbind from %s failed (%i-%s)", vf_pci, driver, errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( iavf_set_numvfs( config, 0U ) ) ) {
    FD_LOG_ERR(( "VF %s removal failed (%i-%s)", vf_pci, errno, fd_io_strerror( errno ) ));
  }
  char marker[ PATH_MAX ];
  iavf_marker_path( config, marker );
  if( FD_UNLIKELY( unlink( marker ) && errno!=ENOENT ) ) {
    FD_LOG_ERR(( "VF ownership marker %s removal failed (%i-%s)", marker, errno, fd_io_strerror( errno ) ));
  }
  return 1;
}

static configure_result_t
check( fd_config_t const * config,
       int                 check_type FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( config->net.iavf.vf_index ) ) {
    PARTIALLY_CONFIGURED( "only VF 0 is supported" );
  }

  uchar expected_mac[ 6 ];
  if( FD_UNLIKELY( iavf_pf_mac( config, expected_mac ) ) ) {
    NOT_CONFIGURED( "PF %s MAC unreadable (%i-%s)", config->net.interface, errno, fd_io_strerror( errno ) );
  }

  char pf_driver[ 32 ];
  if( FD_UNLIKELY( iavf_pf_driver( config, pf_driver ) ) ) {
    NOT_CONFIGURED( "PF %s unavailable (%i-%s)", config->net.interface, errno, fd_io_strerror( errno ) );
  }
  if( FD_UNLIKELY( strcmp( pf_driver, "ice" ) && strcmp( pf_driver, "i40e" ) ) ) {
    PARTIALLY_CONFIGURED( "PF %s driver %s unsupported",
                          config->net.interface, pf_driver );
  }

  uint numvfs;
  if( FD_UNLIKELY( iavf_numvfs( config, &numvfs ) ) ) {
    NOT_CONFIGURED( "PF %s VF count unreadable (%i-%s)", config->net.interface, errno, fd_io_strerror( errno ) );
  }
  if( !numvfs ) NOT_CONFIGURED( "PF %s VF 0 missing", config->net.interface );

  char owned_pci[ 13 ];
  int marker_status = iavf_marker_read( config, owned_pci );
  if( FD_UNLIKELY( marker_status ) ) {
    if( errno!=ENOENT ) PARTIALLY_CONFIGURED( "PF %s VF ownership marker unreadable (%i-%s)", config->net.interface, errno, fd_io_strerror( errno ) );
    NOT_CONFIGURED( "PF %s has %u VFs not owned by Firedancer", config->net.interface, numvfs );
  }
  if( FD_UNLIKELY( numvfs>1U ) ) {
    PARTIALLY_CONFIGURED( "PF %s has %u VFs, expected one",
                          config->net.interface, numvfs );
  }

  char vf_pci[ 13 ];
  if( FD_UNLIKELY( iavf_vf_pci( config, vf_pci ) || iavf_validate_vf( config, vf_pci ) ) ) {
    PARTIALLY_CONFIGURED( "PF %s VF 0 lookup or validation failed (%i-%s)", config->net.interface, errno, fd_io_strerror( errno ) );
  }
  char driver[ 32 ];
  int has_driver = !iavf_driver( vf_pci, driver );
  if( FD_UNLIKELY( strcmp( owned_pci, vf_pci ) ) ) {
    PARTIALLY_CONFIGURED( "VF ownership mismatch, marker %s, actual %s", owned_pci, vf_pci );
  }
  if( FD_UNLIKELY( !has_driver || strcmp( driver, "vfio-pci" ) ) ) {
    PARTIALLY_CONFIGURED( "VF %s not bound to vfio-pci", vf_pci );
  }

  iavf_vf_policy_t policy[ 1 ];
  if( FD_UNLIKELY( access( "/sbin/ip", X_OK ) ) ) {
    PARTIALLY_CONFIGURED( "`/sbin/ip` unavailable (iproute2/iproute)" );
  }
  if( FD_UNLIKELY( iavf_policy_get( config, policy ) ) ) {
    PARTIALLY_CONFIGURED( "PF %s VF settings unreadable (%i-%s)", config->net.interface, errno, fd_io_strerror( errno ) );
  }
  if( FD_UNLIKELY( !policy->mac_valid ) ) PARTIALLY_CONFIGURED( "VF %s MAC missing", vf_pci );
  if( FD_UNLIKELY( memcmp( policy->mac, expected_mac, 6UL ) ) ) {
    PARTIALLY_CONFIGURED( "VF %s MAC differs from PF", vf_pci );
  }
  if( FD_UNLIKELY( !policy->spoofchk_valid || policy->spoofchk ) ) {
    PARTIALLY_CONFIGURED( "VF %s spoof checking not disabled", vf_pci );
  }
  if( FD_UNLIKELY( !policy->trust_valid || policy->trust ) ) {
    PARTIALLY_CONFIGURED( "VF %s trust not disabled", vf_pci );
  }
  if( FD_UNLIKELY( !policy->link_state_valid || !policy->link_state_auto ) ) {
    PARTIALLY_CONFIGURED( "VF %s link state not auto", vf_pci );
  }

  fd_iavf_hw_pci_info_t pci_info[ 1 ];
  if( FD_UNLIKELY( fd_iavf_hw_pci_probe( pci_info, vf_pci ) ) ) {
    PARTIALLY_CONFIGURED( "VF %s PCI probe failed (%i-%s)", vf_pci, errno, fd_io_strerror( errno ) );
  }
  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_iavf = {
  .name      = NAME,
  .enabled   = enabled,
  .init_perm = init_perm,
  .fini_perm = perm,
  .init      = init,
  .fini      = fini,
  .check     = check,
};

#undef NAME

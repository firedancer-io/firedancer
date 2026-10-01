#define _GNU_SOURCE

#include "configure.h"
#include "fd_ethtool_ioctl.h"
#include "../../../platform/fd_file_util.h"
#include "../../../../ballet/json/fd_jtok.h"
#include "../../../../disco/net/iavf/fd_iavf.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>

#define NAME "iavf"

#define IAVF_SYSFS_ROOT "/sys"
#define IAVF_RUN_ROOT   "/run"
#define IAVF_DROP_MAX   (16U)

/* iavf_vf_policy holds the PF's VF settings reported by ip link. */
struct iavf_vf_policy {
  uchar mac[ 6 ];
  int   mac_valid;
  int   spoofchk;
  int   spoofchk_valid;
  int   trust;
  int   trust_valid;
  int   link_state_auto;
  int   link_state_valid;
};
typedef struct iavf_vf_policy iavf_vf_policy_t;

static int
enabled( fd_config_t const * config ) {
  return !strcmp( config->net.provider, "iavf" );
}

static int
iavf_vfio_avail( void ) {
  struct stat st;
  return !stat( IAVF_SYSFS_ROOT "/bus/pci/drivers/vfio-pci", &st ) && S_ISDIR( st.st_mode );
}

static int
iavf_vfio_modprobe( void ) {
  pid_t pid = fork();
  if( pid<0 ) return -1;
  if( !pid ) {
    int null_fd = open( "/dev/null", O_RDWR );
    if( null_fd<0 || dup2( null_fd, STDIN_FILENO )<0 ) _exit( 1 );
    if( null_fd!=STDIN_FILENO ) close( null_fd );
    char * const argv[] = { "modprobe", "--quiet", "vfio-pci", NULL };
    char * const envp[] = { NULL };
    execve( "/sbin/modprobe", argv, envp );
    _exit( 1 );
  }
  int status;
  while( waitpid( pid, &status, 0 )<0 ) {
    if( errno!=EINTR ) return -1;
  }
  if( WIFEXITED( status ) && !WEXITSTATUS( status ) ) return 0;
  errno = EIO;
  return -1;
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
iavf_path( char         path[ PATH_MAX ],
           char const * fmt,
           char const * pf_if,
           uint         vf_idx ) {
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, fmt, pf_if, vf_idx ) );
}

static int
iavf_interface_mac( char const * interface,
                    uchar        mac[ 6 ] ) {
  char path[ PATH_MAX ];
  iavf_path( path, IAVF_SYSFS_ROOT "/class/net/%s/address", interface, 0U );

  char  text[ 32 ];
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
  long  written  = write( fd, value, value_sz );
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
iavf_pf_pci( char const * pf_if,
             char         pf_pci[ FD_IAVF_PCI_ADDR_SZ ] ) {
  char path[ PATH_MAX ];
  iavf_path( path, IAVF_SYSFS_ROOT "/class/net/%s/device", pf_if, 0U );
  char resolved[ PATH_MAX ];
  if( FD_UNLIKELY( !realpath( path, resolved ) ) ) return -1;
  char const * pci = iavf_basename( resolved );
  if( FD_UNLIKELY( strlen( pci )!=FD_IAVF_PCI_ADDR_SZ-1UL ) ) {
    errno = ENODEV;
    return -1;
  }
  fd_cstr_ncpy( pf_pci, pci, FD_IAVF_PCI_ADDR_SZ );
  return 0;
}

static int
iavf_vf_pci( char const * pf_if,
             char         vf_pci[ FD_IAVF_PCI_ADDR_SZ ] ) {
  char path[ PATH_MAX ];
  iavf_path( path, IAVF_SYSFS_ROOT "/class/net/%s/device/virtfn%u", pf_if, 0U );
  char resolved[ PATH_MAX ];
  if( FD_UNLIKELY( !realpath( path, resolved ) ) ) return -1;
  char const * pci = iavf_basename( resolved );
  if( FD_UNLIKELY( strlen( pci )!=FD_IAVF_PCI_ADDR_SZ-1UL ) ) {
    errno = ENODEV;
    return -1;
  }
  fd_cstr_ncpy( vf_pci, pci, FD_IAVF_PCI_ADDR_SZ );
  return 0;
}

static int
iavf_pci_driver( char const * pci,
                 char         driver[ FD_IAVF_DRIVER_NAME_MAX ] ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, IAVF_SYSFS_ROOT "/bus/pci/devices/%s/driver", pci ) );
  char resolved[ PATH_MAX ];
  if( FD_UNLIKELY( !realpath( path, resolved ) ) ) return -1;
  char const * name = iavf_basename( resolved );
  if( FD_UNLIKELY( strlen( name )>=FD_IAVF_DRIVER_NAME_MAX ) ) {
    errno = ENAMETOOLONG;
    return -1;
  }
  fd_cstr_ncpy( driver, name, FD_IAVF_DRIVER_NAME_MAX );
  return 0;
}

static int
iavf_numvfs_get( char const * pf_if,
                 uint *       numvfs ) {
  char path[ PATH_MAX ];
  iavf_path( path, IAVF_SYSFS_ROOT "/class/net/%s/device/sriov_numvfs", pf_if, 0U );
  return fd_file_util_read_uint( path, numvfs );
}

static int
iavf_numvfs_set( char const * pf_if,
                 uint         numvfs ) {
  char path[ PATH_MAX ];
  iavf_path( path, IAVF_SYSFS_ROOT "/class/net/%s/device/sriov_numvfs", pf_if, 0U );
  return fd_file_util_write_uint( path, numvfs );
}

static int
iavf_validate_vf( char const * pf_if,
                  char const * vf_pci ) {
  char pf_pci[ FD_IAVF_PCI_ADDR_SZ ];
  if( FD_UNLIKELY( iavf_pf_pci( pf_if, pf_pci ) ) ) return -1;

  char path    [ PATH_MAX ];
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
  int   matched    = 0;
  for(;;) {
    errno                 = 0;
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
  char const * name    = iavf_basename( resolved );
  ulong        name_sz = strlen( name );
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
iavf_vfio_user_pid( char const * vf_pci,
                    uint *       user_pid ) {
  char group[ 32 ];
  if( FD_UNLIKELY( iavf_iommu_group( vf_pci, group ) ) ) return -1;
  char vfio_path[ 64 ];
  FD_TEST( fd_cstr_printf_check( vfio_path, sizeof(vfio_path), NULL, "/dev/vfio/%s", group ) );

  DIR * proc = opendir( "/proc" );
  if( FD_UNLIKELY( !proc ) ) return -1;
  int err = 0;
  for(;;) {
    errno                   = 0;
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
      errno                    = 0;
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

  ulong len      = 0UL;
  int   read_err = 0;
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
iavf_policy_set( char const * pf_if,
                 uchar const  mac[ 6 ] ) {
  char vf_idx  [ 11 ];
  char mac_text[ 18 ];
  FD_TEST( fd_cstr_printf_check( vf_idx, sizeof(vf_idx), NULL, "%u", 0U ) );
  FD_TEST( fd_cstr_printf_check( mac_text, sizeof(mac_text), NULL, "%02x:%02x:%02x:%02x:%02x:%02x",
                                 (uint)mac[0], (uint)mac[1], (uint)mac[2],
                                 (uint)mac[3], (uint)mac[4], (uint)mac[5] ) );
  char * argv[] = { "ip", "link", "set", "dev", (char *)pf_if,
                   "vf", vf_idx, "mac", mac_text, "spoofchk", "off",
                   "trust", "off", "state", "auto", NULL };
  FD_LOG_NOTICE(( "%sRUN: `/sbin/ip link set dev %s vf %s mac %s spoofchk off trust off state auto`%s",
                  fd_log_style_dim(), pf_if, vf_idx, mac_text, fd_log_style_normal() ));
  return iavf_ip_run( argv, NULL, 0UL, NULL );
}

static void
iavf_policy_parse_vf( fd_jtok_t *        j,
                      uint               vf_idx,
                      iavf_vf_policy_t * policy,
                      int *              found ) {
  iavf_vf_policy_t entry     = {0};
  ulong            entry_idx = ULONG_MAX;
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
      entry.link_state_auto  = !strcmp( state, "auto" );
      entry.link_state_valid = 1;
    }
  }
  if( entry_idx==(ulong)vf_idx ) {
    *policy = entry;
    *found  = 1;
  }
}

static int
iavf_policy_get( char const *       pf_if,
                 iavf_vf_policy_t * policy ) {
  char  output[ 16384 ];
  ulong output_sz;
  char * argv[] = { "ip", "-j", "link", "show", "dev", (char *)pf_if, NULL };
  if( FD_UNLIKELY( iavf_ip_run( argv, output, sizeof(output), &output_sz ) ) ) return -1;

  fd_jtok_t j[1];
  fd_jtok_init( j, output, output_sz );
  fd_jtok_arr_enter( j );
  ulong link_cnt          = 0UL;
  int found               = 0;
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
        while( fd_jtok_arr_next( j ) ) iavf_policy_parse_vf( j, 0U, &result, &found );
      }
    }
  }
  if( FD_UNLIKELY( fd_jtok_fini( j ) || link_cnt!=1UL || strcmp( ifname, pf_if ) ) ) {
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

  char driver[ FD_IAVF_DRIVER_NAME_MAX ];
  int has_driver = !iavf_pci_driver( vf_pci, driver );
  if( has_driver && !strcmp( driver, "vfio-pci" ) ) return 0;
  if( FD_UNLIKELY( iavf_driver_override( vf_pci, "vfio-pci" ) ) ) return -1;
  if( has_driver && FD_UNLIKELY( iavf_unbind( vf_pci ) ) ) return -1;
  if( FD_UNLIKELY( iavf_write( IAVF_SYSFS_ROOT "/bus/pci/drivers_probe", vf_pci ) ) ) return -1;
  if( FD_UNLIKELY( iavf_pci_driver( vf_pci, driver ) ) ) return -1;
  if( FD_UNLIKELY( strcmp( driver, "vfio-pci" ) ) ) {
    FD_LOG_WARNING(( "VF %s bound to %s, expected vfio-pci (%i-%s)", vf_pci, driver, ENODEV, fd_io_strerror( ENODEV ) ));
    errno = ENODEV;
    return -1;
  }
  return 0;
}

/* iavf_owned_v1 preserves records written before bond support. */
struct iavf_owned_v1 {
  uint                        version;
  char                        pf_pci[ FD_IAVF_PCI_ADDR_SZ ];
  char                        vf_pci[ FD_IAVF_PCI_ADDR_SZ ];
  uint                        vf_created;
  int                         ntuple_was_enabled;
  uint                        drop_cnt;
  struct ethtool_rx_flow_spec drops[ IAVF_DROP_MAX ];
  ulong                       checksum;
};
typedef struct iavf_owned_v1 iavf_owned_v1_t;

/* iavf_owned records only resources acquired by this configure stage. */
struct iavf_owned {
  uint                        version;
  char                        pf_pci[ FD_IAVF_PCI_ADDR_SZ ];
  char                        vf_pci[ FD_IAVF_PCI_ADDR_SZ ];
  char                        owner_if[ IFNAMSIZ ];
  uint                        vf_created;
  int                         ntuple_was_enabled;
  uint                        drop_cnt;
  struct ethtool_rx_flow_spec drops[ IAVF_DROP_MAX ];
  ulong                       checksum;
};
typedef struct iavf_owned iavf_owned_t;

static int
iavf_owned_decode( char const *   pf_if,
                   void const *   data,
                   ulong          data_sz,
                   iavf_owned_t * owned ) {
  if( data_sz==sizeof(iavf_owned_v1_t) ) {
    iavf_owned_v1_t old;
    fd_memcpy( &old, data, sizeof(old) );
    if( old.version!=1U || old.checksum!=fd_hash( 0UL, &old, offsetof(iavf_owned_v1_t,checksum) ) ) return EBADMSG;
    *owned = (iavf_owned_t) {
      .version            = 2U, .vf_created=old.vf_created,
      .ntuple_was_enabled = old.ntuple_was_enabled, .drop_cnt=old.drop_cnt
    };
    fd_memcpy( owned->pf_pci, old.pf_pci, sizeof(old.pf_pci) );
    fd_memcpy( owned->vf_pci, old.vf_pci, sizeof(old.vf_pci) );
    fd_memcpy( owned->drops, old.drops, sizeof(old.drops) );
    fd_cstr_ncpy( owned->owner_if, pf_if, sizeof(owned->owner_if) );
  } else if( data_sz==sizeof(*owned) ) {
    fd_memcpy( owned, data, sizeof(*owned) );
    if( owned->version!=2U || owned->checksum!=fd_hash( 0UL, owned, offsetof(iavf_owned_t,checksum) ) ) return EBADMSG;
  } else return EBADMSG;
  if( !owned->pf_pci[0] || owned->pf_pci[12] || owned->vf_pci[12] ||
      !owned->owner_if[0] || !memchr( owned->owner_if, '\0', sizeof(owned->owner_if) ) ||
      owned->drop_cnt>IAVF_DROP_MAX || owned->vf_created>1U ||
      (owned->ntuple_was_enabled!=0 && owned->ntuple_was_enabled!=1) ) return EBADMSG;
  return 0;
}

static void
iavf_owned_path( char const * pf_if,
                 char         path[ PATH_MAX ] ) {
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL,
                                IAVF_RUN_ROOT "/firedancer-iavf-%s.owned", pf_if ) );
}

static int
iavf_owned_read( char const *   pf_if,
                 iavf_owned_t * owned,
                 int *          locked_fd ) {
  char path[ PATH_MAX ];
  iavf_owned_path( pf_if, path );
  int fd = open( path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW );
  if( fd<0 ) return -1;
  struct stat st;
  int err = 0;
  if( flock( fd, (locked_fd ? LOCK_EX : LOCK_SH) | LOCK_NB ) || fstat( fd, &st ) ) err = errno;
  else if( !S_ISREG( st.st_mode ) || st.st_uid || st.st_nlink!=1UL ||
           (st.st_mode & 0777)!=0600 ||
           (st.st_size!=(off_t)sizeof(*owned) && st.st_size!=(off_t)sizeof(iavf_owned_v1_t)) ) err = EBADMSG;
  else {
    uchar data[ sizeof(iavf_owned_t) ];
    long sz = pread( fd, data, (ulong)st.st_size, 0L );
    if( sz<0L ) err = errno;
    else if( sz!=st.st_size ) err = EBADMSG;
    else err = iavf_owned_decode( pf_if, data, (ulong)sz, owned );
  }
  if( !err && locked_fd ) *locked_fd = fd;
  else if( close( fd ) && !err ) err = errno;
  if( err ) { errno = err; return -1; }
  return 0;
}

static int
iavf_owned_save( int            fd,
                 iavf_owned_t * owned ) {
  owned->checksum = fd_hash( 0UL, owned, offsetof(iavf_owned_t,checksum) );
  long written    = pwrite( fd, owned, sizeof(*owned), 0L );
  if( written!=(long)sizeof(*owned) ) {
    if( written>=0L ) errno = EIO;
    return -1;
  }
  return fdatasync( fd );
}

static int
iavf_ethtool( fd_ethtool_ioctl_t *   ioc,
              struct ethtool_rxnfc * request ) {
  ioc->ifr.ifr_data = (void *)request;
  return ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr );
}

static int
iavf_drop_get( fd_ethtool_ioctl_t *          ioc,
               uint                          location,
               struct ethtool_rx_flow_spec * rule ) {
  struct ethtool_rxnfc request = { .cmd=ETHTOOL_GRXCLSRULE, .fs={ .location=location } };
  if( iavf_ethtool( ioc, &request ) ) return -1;
  *rule = request.fs;
  return 0;
}

static int
iavf_drop_equal( struct ethtool_rx_flow_spec const * a,
                 struct ethtool_rx_flow_spec const * b ) {
  return a->flow_type==b->flow_type && a->ring_cookie==b->ring_cookie &&
         a->location==b->location &&
         !memcmp( &a->h_u,   &b->h_u,   sizeof(a->h_u)   ) &&
         !memcmp( &a->m_u,   &b->m_u,   sizeof(a->m_u)   ) &&
         !memcmp( &a->h_ext, &b->h_ext, sizeof(a->h_ext) ) &&
         !memcmp( &a->m_ext, &b->m_ext, sizeof(a->m_ext) );
}

static uint
iavf_udp_ports( fd_config_t const * config,
                ushort              ports[ IAVF_DROP_MAX ] ) {
  ushort candidates[] = {
    config->tiles.shred.shred_listen_port,
    config->tiles.quic.quic_transaction_listen_port,
    config->tiles.quic.regular_transaction_listen_port,
    config->is_firedancer ? config->gossip.port : 0U,
    config->is_firedancer ? config->tiles.repair.repair_client_listen_port : 0U,
    config->is_firedancer ? config->tiles.rserve.repair_serve_listen_port : 0U,
    config->is_firedancer ? config->tiles.txsend.txsend_src_port : 0U,
    config->is_firedancer && config->firedancer.development.alpenglow
      ? config->firedancer.development.votor.quic_client_listen_port : 0U,
    config->is_firedancer && config->firedancer.development.alpenglow
      ? config->firedancer.development.votor.quic_server_listen_port : 0U
  };
  uint port_cnt = 0U;
  for( ulong i=0UL; i<sizeof(candidates)/sizeof(candidates[0]); i++ ) {
    if( !candidates[i] ) continue;
    uint j = 0U;
    while( j<port_cnt && ports[j]!=candidates[i] ) j++;
    if( j==port_cnt ) ports[port_cnt++] = candidates[i];
  }
  return port_cnt;
}

static int
iavf_drops_install( char const *        pf_if,
                    fd_config_t const * config,
                    iavf_owned_t *      owned,
                    int                 owned_fd ) {
  fd_ethtool_ioctl_t ioc;
  if( !fd_ethtool_ioctl_init( &ioc, pf_if ) ) return -1;
  int err = fd_ethtool_ioctl_feature_test( &ioc, FD_ETHTOOL_FEATURE_NTUPLE, &owned->ntuple_was_enabled );
  if( err ) goto done;
  if( iavf_owned_save( owned_fd, owned ) ) { err = errno; goto done; }
  if( !owned->ntuple_was_enabled ) {
    err = fd_ethtool_ioctl_feature_set( &ioc, FD_ETHTOOL_FEATURE_NTUPLE, 1 );
    if( err ) goto done;
  }

  struct ethtool_rxnfc count = { .cmd=ETHTOOL_GRXCLSRLCNT };
  if( iavf_ethtool( &ioc, &count ) ) { err = errno; goto done; }
  uint capacity = (uint)(count.data & ~((ulong)RX_CLS_LOC_SPECIAL));
  if( !capacity || capacity>65536U ) { err = EOPNOTSUPP; goto done; }

  ushort ports[ IAVF_DROP_MAX ];
  uint port_cnt = iavf_udp_ports( config, ports );
  uint location = capacity;
  for( uint i=0U; i<port_cnt; i++ ) {
    struct ethtool_rx_flow_spec existing;
    for(;;) {
      if( !location ) { err = ENOSPC; goto done; }
      location--;
      if( !iavf_drop_get( &ioc, location, &existing ) ) continue;
      if( errno!=ENOENT && errno!=EINVAL ) { err = errno; goto done; }
      break;
    }
    struct ethtool_rx_flow_spec rule = {
      .flow_type   = UDP_V4_FLOW,
      .h_u         = { .udp_ip4_spec={ .ip4dst=config->net.bind_address_parsed, .pdst=fd_ushort_bswap( ports[i] ) } },
      .m_u         = { .udp_ip4_spec={ .ip4dst=config->net.bind_address_parsed ? UINT_MAX : 0U, .pdst=USHRT_MAX } },
      .ring_cookie = RX_CLS_FLOW_DISC,
      .location    = location
    };
    owned->drops[ owned->drop_cnt++ ] = rule;
    if( iavf_owned_save( owned_fd, owned ) ) { err = errno; goto done; }
    struct ethtool_rxnfc insert = { .cmd=ETHTOOL_SRXCLSRLINS, .fs=rule };
    if( iavf_ethtool( &ioc, &insert ) ) { err = errno; goto done; }
    if( iavf_drop_get( &ioc, rule.location, &existing ) ) { err = errno; goto done; }
    if( !iavf_drop_equal( &rule, &existing ) ) { err = EPROTO; goto done; }
  }

done:
  fd_ethtool_ioctl_fini( &ioc );
  if( err ) { errno = err; return -1; }
  return 0;
}

static int
iavf_owned_validate( char const *         pf_if,
                     iavf_owned_t const * owned ) {
  char pf_pci[ FD_IAVF_PCI_ADDR_SZ ];
  if( iavf_pf_pci( pf_if, pf_pci ) ) return -1;
  if( strcmp( pf_pci, owned->pf_pci ) ) { errno = ESTALE; return -1; }

  uint numvfs;
  if( iavf_numvfs_get( pf_if, &numvfs ) ) return -1;
  if( numvfs && !owned->vf_created ) { errno = EBUSY; return -1; }
  if( numvfs && owned->vf_created ) {
    char vf_pci[ FD_IAVF_PCI_ADDR_SZ ];
    if( numvfs!=1U || !owned->vf_pci[0] ) { errno = EBUSY; return -1; }
    if( iavf_vf_pci( pf_if, vf_pci ) || iavf_validate_vf( pf_if, vf_pci ) ) return -1;
    if( owned->vf_pci[0] && strcmp( vf_pci, owned->vf_pci ) ) { errno = ESTALE; return -1; }
    uint user_pid;
    int in_use = iavf_vfio_user_pid( vf_pci, &user_pid );
    if( in_use<0 ) return -1;
    if( in_use ) {
      FD_LOG_WARNING(( "VF %s is in use by PID %u", vf_pci, user_pid ));
      errno = EBUSY;
      return -1;
    }
  }

  fd_ethtool_ioctl_t ioc;
  if( !fd_ethtool_ioctl_init( &ioc, pf_if ) ) return -1;
  int err = 0;
  for( uint i=0U; i<owned->drop_cnt; i++ ) {
    struct ethtool_rx_flow_spec current;
    if( iavf_drop_get( &ioc, owned->drops[i].location, &current ) ) {
      if( errno==ENOENT || errno==EINVAL ) continue;
      err = errno;
      break;
    }
    if( !iavf_drop_equal( &current, &owned->drops[i] ) ) { err = ESTALE; break; }
  }
  fd_ethtool_ioctl_fini( &ioc );
  if( err ) { errno = err; return -1; }
  return 0;
}

static int
iavf_owned_remove( char const *         pf_if,
                   iavf_owned_t const * owned ) {
  if( iavf_owned_validate( pf_if, owned ) ) return -1;
  fd_ethtool_ioctl_t ioc;
  if( !fd_ethtool_ioctl_init( &ioc, pf_if ) ) return -1;
  int err = 0;
  for( uint i=0U; i<owned->drop_cnt; i++ ) {
    struct ethtool_rx_flow_spec current;
    if( iavf_drop_get( &ioc, owned->drops[i].location, &current ) ) {
      if( errno==ENOENT || errno==EINVAL ) continue;
      err = errno;
      goto done;
    }
    if( !iavf_drop_equal( &current, &owned->drops[i] ) ) { err = ESTALE; goto done; }
    struct ethtool_rxnfc del = { .cmd=ETHTOOL_SRXCLSRLDEL, .fs={ .location=current.location } };
    if( iavf_ethtool( &ioc, &del ) ) { err = errno; goto done; }
  }
  if( !owned->ntuple_was_enabled ) {
    struct ethtool_rxnfc count = { .cmd=ETHTOOL_GRXCLSRLCNT };
    if( iavf_ethtool( &ioc, &count ) ) { err = errno; goto done; }
    if( !count.rule_cnt ) err = fd_ethtool_ioctl_feature_set( &ioc, FD_ETHTOOL_FEATURE_NTUPLE, 0 );
  }
done:
  fd_ethtool_ioctl_fini( &ioc );
  if( err ) { errno = err; return -1; }
  uint numvfs;
  if( iavf_numvfs_get( pf_if, &numvfs ) ) return -1;
  if( numvfs && owned->vf_created && iavf_numvfs_set( pf_if, 0U ) ) return -1;
  char owned_path[ PATH_MAX ];
  iavf_owned_path( pf_if, owned_path );
  return unlink( owned_path );
}

static int
iavf_init_preflight( char const *        pf_if,
                     fd_config_t const * config,
                     iavf_owned_t *      owned ) {
  *owned = (iavf_owned_t) { .version=2U, .ntuple_was_enabled=1 };
  fd_cstr_ncpy( owned->owner_if, config->net.interface, sizeof(owned->owner_if) );
  if( iavf_pf_pci( pf_if, owned->pf_pci ) ) return -1;
  char driver[ FD_IAVF_DRIVER_NAME_MAX ];
  if( iavf_pci_driver( owned->pf_pci, driver ) ) return -1;
  if( strcmp( driver, "ice" ) && strcmp( driver, "i40e" ) ) { errno = EPROTONOSUPPORT; return -1; }
  uint numvfs;
  if( iavf_numvfs_get( pf_if, &numvfs ) ) return -1;
  if( numvfs ) { errno = EBUSY; return -1; }
  char owned_path[ PATH_MAX ];
  iavf_owned_path( pf_if, owned_path );
  struct stat st;
  if( !lstat( owned_path, &st ) ) { errno = EEXIST; return -1; }
  return errno==ENOENT ? 0 : -1;
}

static int
iavf_init_device( char const *        pf_if,
                  uchar const         mac[ 6 ],
                  fd_config_t const * config,
                  iavf_owned_t *      owned,
                  int                 owned_fd ) {
  char pf_pci[ FD_IAVF_PCI_ADDR_SZ ];
  uint numvfs;
  if( iavf_pf_pci( pf_if, pf_pci ) || iavf_numvfs_get( pf_if, &numvfs ) ) return -1;
  if( numvfs || strcmp( pf_pci, owned->pf_pci ) ) { errno = ESTALE; return -1; }
  int err = 0;
  if( iavf_numvfs_set( pf_if, 1U ) ) err = errno;
  if( !err ) {
    owned->vf_created = 1U;
    if( iavf_owned_save( owned_fd, owned ) ) err = errno;
  }
  if( !err && (iavf_vf_pci( pf_if, owned->vf_pci ) || iavf_validate_vf( pf_if, owned->vf_pci ) ||
      iavf_owned_save( owned_fd, owned ) || iavf_policy_set( pf_if, mac ) ||
      iavf_bind_vfio( owned->vf_pci )) ) err = errno;
  fd_iavf_pci_info_t pci_info;
  if( !err && fd_iavf_pci_probe( &pci_info, owned->vf_pci ) ) err = errno;
  if( !err && iavf_drops_install( pf_if, config, owned, owned_fd ) ) err = errno;
  if( err ) { errno = err; return -1; }
  return 0;
}

static int
iavf_owned_interfaces( char const * owner_if,
                       char         members[ FD_IAVF_MEMBER_MAX ][ IFNAMSIZ ],
                       ulong *      member_cnt ) {
  *member_cnt = 0UL;
  DIR * dir   = opendir( IAVF_RUN_ROOT );
  if( !dir ) return -1;
  int err             = 0;
  char const prefix[] = "firedancer-iavf-";
  char const suffix[] = ".owned";
  for(;;) {
    errno                 = 0;
    struct dirent * entry = readdir( dir );
    if( !entry ) { err = errno; break; }
    ulong len       = strlen( entry->d_name );
    ulong prefix_sz = sizeof(prefix)-1UL;
    ulong suffix_sz = sizeof(suffix)-1UL;
    if( len<=prefix_sz+suffix_sz || len>=prefix_sz+suffix_sz+IFNAMSIZ ||
        memcmp( entry->d_name, prefix, prefix_sz ) ||
        memcmp( entry->d_name+len-suffix_sz, suffix, suffix_sz ) ) continue;
    char pf_if[ IFNAMSIZ ] = {0};
    fd_memcpy( pf_if, entry->d_name+prefix_sz, len-prefix_sz-suffix_sz );
    iavf_owned_t owned;
    if( iavf_owned_read( pf_if, &owned, NULL ) ) {
      err = errno;
      FD_LOG_WARNING(( "IAVF ownership for %s unreadable (%i-%s)", pf_if, err, fd_io_strerror( err ) ));
      break;
    }
    if( strcmp( owned.owner_if, owner_if ) ) continue;
    if( *member_cnt>=FD_IAVF_MEMBER_MAX ) { err = E2BIG; break; }
    fd_cstr_ncpy( members[ (*member_cnt)++ ], pf_if, IFNAMSIZ );
  }
  if( closedir( dir ) && !err ) err = errno;
  if( err ) { errno = err; return -1; }
  return 0;
}

static void
init( fd_config_t const * config ) {
  char  members[ FD_IAVF_MEMBER_MAX ][ IFNAMSIZ ];
  ulong member_cnt;
  if( fd_iavf_member_interfaces( config->net.interface, members, &member_cnt ) ) {
    FD_LOG_ERR(( "IAVF member discovery failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  uchar mac[ 6 ];
  if( iavf_interface_mac( config->net.interface, mac ) ) {
    FD_LOG_ERR(( "interface MAC read failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  iavf_owned_t owned    [ FD_IAVF_MEMBER_MAX ];
  int          owned_fds[ FD_IAVF_MEMBER_MAX ];
  for( ulong i=0UL; i<member_cnt; i++ ) {
    if( iavf_init_preflight( members[i], config, &owned[i] ) ) {
      FD_LOG_ERR(( "IAVF preflight for %s failed (%i-%s)", members[i], errno, fd_io_strerror( errno ) ));
    }
  }
  ulong reserved_cnt = 0UL;
  int   err          = 0;
  for( ulong i=0UL; i<member_cnt; i++ ) {
    char owned_path[ PATH_MAX ];
    iavf_owned_path( members[i], owned_path );
    int fd = open( owned_path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600 );
    if( fd<0 ) { err = errno; break; }
    owned_fds[ reserved_cnt++ ] = fd;
    if( flock( fd, LOCK_EX | LOCK_NB ) || iavf_owned_save( fd, &owned[i] ) ) { err = errno; break; }
  }
  if( err ) {
    for( ulong i=0UL; i<reserved_cnt; i++ ) {
      char owned_path[ PATH_MAX ];
      iavf_owned_path( members[i], owned_path );
      if( unlink( owned_path ) ) FD_LOG_WARNING(( "IAVF reservation cleanup for %s failed (%i-%s)", members[i], errno, fd_io_strerror( errno ) ));
      close( owned_fds[i] );
    }
    FD_LOG_ERR(( "IAVF ownership reservation failed (%i-%s)", err, fd_io_strerror( err ) ));
  }
  if( !iavf_vfio_avail() && iavf_vfio_modprobe() ) {
    err = errno;
  }
  for( ulong i=0UL; i<member_cnt; i++ ) {
    if( err ) break;
    if( iavf_init_device( members[i], mac, config, &owned[i], owned_fds[i] ) ) {
      err = errno;
      FD_LOG_WARNING(( "IAVF configure for %s failed (%i-%s)", members[i], err, fd_io_strerror( err ) ));
    }
  }
  if( err ) {
    for( ulong i=member_cnt; i>0UL; i-- ) {
      if( iavf_owned_remove( members[i-1UL], &owned[i-1UL] ) ) {
        FD_LOG_WARNING(( "IAVF rollback for %s failed (%i-%s), ownership retained", members[i-1UL], errno, fd_io_strerror( errno ) ));
      }
    }
  }
  for( ulong i=0UL; i<member_cnt; i++ ) {
    if( close( owned_fds[i] ) && !err ) err = errno;
  }
  if( err ) FD_LOG_ERR(( "IAVF configure failed (%i-%s)", err, fd_io_strerror( err ) ));
}

static int
fini( fd_config_t const * config,
      int                 pre_init FD_PARAM_UNUSED ) {
  char  members[ FD_IAVF_MEMBER_MAX ][ IFNAMSIZ ];
  ulong member_cnt;
  if( iavf_owned_interfaces( config->net.interface, members, &member_cnt ) ) {
    FD_LOG_ERR(( "IAVF ownership read failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  iavf_owned_t owned    [ FD_IAVF_MEMBER_MAX ];
  int          owned_fds[ FD_IAVF_MEMBER_MAX ];
  ulong locked_cnt = 0UL;
  int   err        = 0;
  for( ulong i=0UL; i<member_cnt; i++ ) {
    if( iavf_owned_read( members[i], &owned[i], &owned_fds[i] ) ) { err = errno; break; }
    locked_cnt++;
    if( strcmp( owned[i].owner_if, config->net.interface ) ) { err = ESTALE; break; }
    if( iavf_owned_validate( members[i], &owned[i] ) ) { err = errno; break; }
  }
  if( !err ) {
    for( ulong i=0UL; i<member_cnt; i++ ) {
      if( iavf_owned_remove( members[i], &owned[i] ) ) {
        err = errno;
        FD_LOG_WARNING(( "IAVF cleanup for %s failed (%i-%s), ownership retained", members[i], err, fd_io_strerror( err ) ));
        break;
      }
    }
  }
  for( ulong i=0UL; i<locked_cnt; i++ ) {
    if( close( owned_fds[i] ) && !err ) err = errno;
  }
  if( err ) FD_LOG_ERR(( "IAVF cleanup failed (%i-%s)", err, fd_io_strerror( err ) ));
  return !!member_cnt;
}

static configure_result_t
iavf_check_device( fd_config_t const * config,
                   char const *        pf_if ) {
  iavf_owned_t owned;
  if( iavf_owned_read( pf_if, &owned, NULL ) ) {
    if( errno==ENOENT ) NOT_CONFIGURED( "IAVF ownership record missing" );
    PARTIALLY_CONFIGURED( "IAVF ownership unreadable (%i-%s)", errno, fd_io_strerror( errno ) );
  }
  char pf_pci[ FD_IAVF_PCI_ADDR_SZ ];
  char vf_pci[ FD_IAVF_PCI_ADDR_SZ ];
  char driver[ FD_IAVF_DRIVER_NAME_MAX ];
  uint numvfs;
  if( strcmp( owned.owner_if, config->net.interface ) ||
      iavf_pf_pci( pf_if, pf_pci ) || strcmp( owned.pf_pci, pf_pci ) ||
      iavf_numvfs_get( pf_if, &numvfs ) || numvfs!=1U || !owned.vf_created ||
      iavf_vf_pci( pf_if, vf_pci ) || strcmp( owned.vf_pci, vf_pci ) ||
      iavf_validate_vf( pf_if, vf_pci ) ||
      iavf_pci_driver( vf_pci, driver ) || strcmp( driver, "vfio-pci" ) ) {
    PARTIALLY_CONFIGURED( "IAVF device or driver differs from the owned configuration" );
  }
  uchar            mac[ 6 ];
  iavf_vf_policy_t policy;
  if( iavf_interface_mac( config->net.interface, mac ) || iavf_policy_get( pf_if, &policy ) ||
      !policy.mac_valid || memcmp( policy.mac, mac, 6UL ) ||
      !policy.spoofchk_valid || policy.spoofchk ||
      !policy.trust_valid || policy.trust ||
      !policy.link_state_valid || !policy.link_state_auto ) {
    PARTIALLY_CONFIGURED( "IAVF MAC or VF policy differs" );
  }

  fd_ethtool_ioctl_t ioc;
  if( !fd_ethtool_ioctl_init( &ioc, pf_if ) ) PARTIALLY_CONFIGURED( "PF filter lookup failed" );
  int valid          = 1;
  int ntuple_enabled = 0;
  if( fd_ethtool_ioctl_feature_test( &ioc, FD_ETHTOOL_FEATURE_NTUPLE, &ntuple_enabled ) || !ntuple_enabled ) valid = 0;
  ushort ports[ IAVF_DROP_MAX ];
  uint port_cnt = iavf_udp_ports( config, ports );
  if( port_cnt!=owned.drop_cnt ) valid = 0;
  for( uint i=0U; i<owned.drop_cnt; i++ ) {
    struct ethtool_rx_flow_spec current;
    if( iavf_drop_get( &ioc, owned.drops[i].location, &current ) ||
        !iavf_drop_equal( &current, &owned.drops[i] ) ) { valid = 0; break; }
    if( i>=port_cnt || current.h_u.udp_ip4_spec.pdst!=fd_ushort_bswap( ports[i] ) ||
        current.h_u.udp_ip4_spec.ip4dst!=config->net.bind_address_parsed ) valid = 0;
  }
  fd_ethtool_ioctl_fini( &ioc );
  if( !valid ) PARTIALLY_CONFIGURED( "PF UDP drop rules differ" );
  CONFIGURE_OK();
}

static configure_result_t
check( fd_config_t const * config,
       int                 check_type FD_PARAM_UNUSED ) {
  char  members[ FD_IAVF_MEMBER_MAX ][ IFNAMSIZ ];
  char  owned[ FD_IAVF_MEMBER_MAX ][ IFNAMSIZ ];
  ulong member_cnt;
  ulong owned_cnt;
  if( fd_iavf_member_interfaces( config->net.interface, members, &member_cnt ) ) {
    PARTIALLY_CONFIGURED( "IAVF member discovery failed (%i-%s)", errno, fd_io_strerror( errno ) );
  }
  if( iavf_owned_interfaces( config->net.interface, owned, &owned_cnt ) ) {
    PARTIALLY_CONFIGURED( "IAVF ownership unreadable (%i-%s)", errno, fd_io_strerror( errno ) );
  }
  if( !owned_cnt ) NOT_CONFIGURED( "IAVF ownership records missing" );
  if( member_cnt!=owned_cnt ) PARTIALLY_CONFIGURED( "IAVF members differ from the owned configuration" );
  for( ulong i=0UL; i<member_cnt; i++ ) {
    int found = 0;
    for( ulong j=0UL; j<owned_cnt; j++ ) found |= !strcmp( members[i], owned[j] );
    if( !found ) PARTIALLY_CONFIGURED( "IAVF member %s has no ownership record", members[i] );
    configure_result_t result = iavf_check_device( config, members[i] );
    if( result.result!=CONFIGURE_OK ) return result;
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

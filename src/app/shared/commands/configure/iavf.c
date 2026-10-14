#define _GNU_SOURCE

#include "configure.h"
#include "fd_ethtool_ioctl.h"
#include "../../../platform/fd_file_util.h"
#include "../../../../ballet/json/fd_jtok.h"
#include "../../../../disco/net/iavf/fd_iavf.h"
#include "../../../../waltz/ip/fd_netlink1.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define NAME "iavf"

#define IAVF_SYSFS_ROOT "/sys"
#define IAVF_DROP_MAX   (16U)

/* iavf_retry bounds recovery from PF reset and concurrent driver binding */
static int
iavf_retry( long * deadline,
            int    err ) {
  errno = err;
  if( err!=EBUSY && err!=EAGAIN ) return 0;
  struct timespec now;
  if( clock_gettime( CLOCK_MONOTONIC, &now ) ) { errno = err; return 0; }
  long now_ns = now.tv_sec*1000000000L + now.tv_nsec;
  if( !*deadline ) *deadline = now_ns+5000000000L;
  if( now_ns>=*deadline ) return 0;
  struct timespec delay = { .tv_nsec=fd_long_min( 100000000L, *deadline-now_ns ) };
  while( nanosleep( &delay, &delay ) && errno==EINTR ) {}
  errno = err;
  return 1;
}

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

static void
perm( fd_cap_chk_t *      chk,
      fd_config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "configure Intel SR-IOV VFs and PF filters" );
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
           char const * pf_if ) {
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, fmt, pf_if ) );
}

static int
iavf_interface_mac( char const * interface,
                    uchar        mac[ 6 ] ) {
  char path[ PATH_MAX ];
  iavf_path( path, IAVF_SYSFS_ROOT "/class/net/%s/address", interface );

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
  iavf_path( path, IAVF_SYSFS_ROOT "/class/net/%s/device", pf_if );
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
  iavf_path( path, IAVF_SYSFS_ROOT "/class/net/%s/device/sriov_numvfs", pf_if );
  if( FD_UNLIKELY( fd_file_util_read_uint( path, numvfs ) ) ) {
    int err = errno;
    FD_LOG_WARNING(( "reading %s failed (%i-%s)", path, err, fd_io_strerror( err ) ));
    if( err==ENOENT ) {
      FD_LOG_WARNING(( "PF %s does not expose SR-IOV configuration, check NIC firmware and BIOS SR-IOV settings", pf_if ));
    }
    errno = err;
    return -1;
  }
  return 0;
}

static int
iavf_numvfs_set( char const * pf_if,
                 uint         numvfs ) {
  char path[ PATH_MAX ];
  iavf_path( path, IAVF_SYSFS_ROOT "/class/net/%s/device/sriov_numvfs", pf_if );
  return fd_file_util_write_uint( path, numvfs );
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
  if( FD_UNLIKELY( pipe2( pipefd, O_CLOEXEC ) ) ) return -1;

  pid_t pid = fork();
  if( FD_UNLIKELY( pid<0 ) ) {
    int err = errno;
    close( pipefd[0] );
    close( pipefd[1] );
    errno = err;
    return -1;
  }
  if( !pid ) {
    close( pipefd[0] );
    if( FD_UNLIKELY( dup2( pipefd[1], STDOUT_FILENO )<0 ) ) {
      FD_LOG_WARNING(( "dup2 for ip output failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      _exit( 1 );
    }
    if( pipefd[1]!=STDOUT_FILENO ) close( pipefd[1] );
    char * const envp[] = { NULL };
    execve( "/sbin/ip", argv, envp );
    FD_LOG_WARNING(( "execve(/sbin/ip) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    _exit( 1 );
  }

  ulong len      = 0UL;
  int   read_err = 0;
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
  *output_sz = len;
  return 0;
}

static int
iavf_policy_attr_set( uint         if_idx,
                      ushort       attr,
                      void const * value,
                      uint         value_sz ) {
  struct {
    struct nlmsghdr  nlh;
    struct ifinfomsg ifi;
    struct rtattr    list;
    struct rtattr    vf;
    struct rtattr    setting;
    uchar            value[ sizeof(struct ifla_vf_mac) ];
  } request = {
    .nlh     = { .nlmsg_type=RTM_SETLINK, .nlmsg_flags=NLM_F_REQUEST | NLM_F_ACK },
    .ifi     = { .ifi_family=AF_UNSPEC, .ifi_index=(int)if_idx },
    .list    = { .rta_type=IFLA_VFINFO_LIST },
    .vf      = { .rta_type=IFLA_VF_INFO },
    .setting = { .rta_type=attr }
  };
  FD_TEST( value_sz<=sizeof(request.value) && !(value_sz & 3U) );
  request.setting.rta_len = (ushort)RTA_LENGTH( value_sz );
  request.vf.rta_len      = (ushort)RTA_LENGTH( request.setting.rta_len );
  request.list.rta_len    = (ushort)RTA_LENGTH( request.vf.rta_len );
  request.nlh.nlmsg_len   = NLMSG_LENGTH( sizeof(request.ifi)+request.list.rta_len );
  fd_memcpy( request.value, value, value_sz );

  fd_netlink_t nl;
  if( !fd_netlink_init( &nl, 0U ) ) return -1;
  struct timeval timeout = { .tv_sec=5L };
  int err = 0;
  if( setsockopt( nl.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout) ) ) { err = errno; goto done; }
  long deadline = 0L;
  do {
    request.nlh.nlmsg_seq = ++nl.seq;
    long sent = sendto( nl.fd, &request, request.nlh.nlmsg_len, 0, NULL, 0 );
    if( sent!=(long)request.nlh.nlmsg_len ) { err = sent<0L ? errno : EIO; break; }
    uchar buf[ 4096 ] __attribute__((aligned(NLMSG_ALIGNTO)));
    fd_netlink_iter_t iter;
    fd_netlink_iter_init( &iter, &nl, buf, sizeof(buf) );
    /* A lost acknowledgement must not cause another MAC reset */
    if( iter.err ) { err = iter.err==EAGAIN ? ETIMEDOUT : iter.err; break; }
    if( fd_netlink_iter_done( &iter ) ) { err = EPROTO; break; }
    struct nlmsghdr const * reply = fd_netlink_iter_msg( &iter );
    if( reply->nlmsg_seq!=nl.seq || reply->nlmsg_type!=NLMSG_ERROR ||
        reply->nlmsg_len<NLMSG_LENGTH( sizeof(struct nlmsgerr) ) ) { err = EPROTO; break; }
    struct nlmsgerr const * ack = NLMSG_DATA( reply );
    if( ack->error>0 || ack->error < -4095 ) { err = EPROTO; break; }
    err = -ack->error;
  } while( err && iavf_retry( &deadline, err ) );
done:
  fd_netlink_fini( &nl );
  if( err ) { errno = err; return -1; }
  return 0;
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
iavf_policy_read( char const *       pf_if,
                  uint               vf_idx,
                  iavf_vf_policy_t * policy ) {
  char  output[ 131072 ];
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
        while( fd_jtok_arr_next( j ) ) iavf_policy_parse_vf( j, vf_idx, &result, &found );
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
iavf_policy_get( char const *       pf_if,
                 uint               vf_idx,
                 iavf_vf_policy_t * policy ) {
  long deadline = 0L;
  while( iavf_policy_read( pf_if, vf_idx, policy ) ) {
    if( errno!=ENODATA ) return -1;
    uint numvfs;
    if( iavf_numvfs_get( pf_if, &numvfs ) ) return -1;
    if( numvfs<=vf_idx || !iavf_retry( &deadline, EAGAIN ) ) { errno = ENODATA; return -1; }
  }
  return 0;
}

static int
iavf_policy_set( char const * pf_if,
                 uint         vf_idx,
                 uchar const  mac[ 6 ] ) {
  iavf_vf_policy_t policy;
  if( iavf_policy_get( pf_if, vf_idx, &policy ) ) return -1;
  uint if_idx = if_nametoindex( pf_if );
  if( !if_idx ) return -1;
  struct ifla_vf_mac        vf_mac   = { .vf=vf_idx };
  struct ifla_vf_spoofchk   spoofchk = { .vf=vf_idx, .setting=0U };
  struct ifla_vf_trust      trust    = { .vf=vf_idx, .setting=0U };
  struct ifla_vf_link_state link     = { .vf=vf_idx, .link_state=IFLA_VF_LINK_STATE_AUTO };
  fd_memcpy( vf_mac.mac, mac, 6UL );
  /* Retry each setting separately, i40e resets the VF on every MAC write */
  if( (!policy.mac_valid || memcmp( policy.mac, mac, 6UL )) &&
      iavf_policy_attr_set( if_idx, IFLA_VF_MAC, &vf_mac, sizeof(vf_mac) ) ) return -1;
  if( (!policy.spoofchk_valid || policy.spoofchk) &&
      iavf_policy_attr_set( if_idx, IFLA_VF_SPOOFCHK, &spoofchk, sizeof(spoofchk) ) ) return -1;
  if( (!policy.trust_valid || policy.trust) &&
      iavf_policy_attr_set( if_idx, IFLA_VF_TRUST, &trust, sizeof(trust) ) ) return -1;
  if( (!policy.link_state_valid || !policy.link_state_auto) &&
      iavf_policy_attr_set( if_idx, IFLA_VF_LINK_STATE, &link, sizeof(link) ) ) return -1;
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

  if( FD_UNLIKELY( iavf_driver_override( vf_pci, "vfio-pci" ) ) ) return -1;
  long deadline = 0L;
  do {
    char driver[ FD_IAVF_DRIVER_NAME_MAX ];
    int has_driver = !iavf_pci_driver( vf_pci, driver );
    if( !has_driver && errno!=ENOENT ) return -1;
    if( has_driver && !strcmp( driver, "vfio-pci" ) ) return 0;
    if( has_driver && iavf_unbind( vf_pci ) && errno!=ENOENT && errno!=ENODEV ) return -1;
    int err = iavf_write( IAVF_SYSFS_ROOT "/bus/pci/drivers_probe", vf_pci ) ? errno : 0;
    has_driver = !iavf_pci_driver( vf_pci, driver );
    if( !has_driver && errno!=ENOENT ) return -1;
    if( has_driver && !strcmp( driver, "vfio-pci" ) ) return 0;
    if( err && err!=EBUSY && err!=EAGAIN ) { errno = err; return -1; }
    /* A driver may have matched before driver_override was written */
  } while( iavf_retry( &deadline, EAGAIN ) );
  errno = ENODEV;
  return -1;
}

static int
iavf_ethtool( fd_ethtool_ioctl_t *   ioc,
              struct ethtool_rxnfc * request ) {
  ioc->ifr.ifr_data = (void *)request;
  long deadline = 0L;
  int ret;
  do ret = ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr );
  while( ret<0 && iavf_retry( &deadline, errno ) );
  return ret;
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
    config->is_firedancer && config->firedancer.consensus.alpenglow
      ? config->firedancer.development.votor.quic_client_listen_port : 0U,
    config->is_firedancer && config->firedancer.consensus.alpenglow
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

static struct ethtool_rx_flow_spec
iavf_drop_rule( fd_config_t const * config,
                ushort              port,
                uint                location ) {
  return (struct ethtool_rx_flow_spec) {
    .flow_type   = UDP_V4_FLOW,
    .h_u         = { .udp_ip4_spec={ .ip4dst=config->net.bind_address_parsed, .pdst=fd_ushort_bswap( port ) } },
    .m_u         = { .udp_ip4_spec={ .ip4dst=config->net.bind_address_parsed ? UINT_MAX : 0U, .pdst=USHRT_MAX } },
    .ring_cookie = RX_CLS_FLOW_DISC,
    .location    = location
  };
}

static int
iavf_drops_clear( fd_ethtool_ioctl_t * ioc ) {
  long deadline = 0L;
  int err;
  do err = fd_ethtool_ioctl_ntuple_clear( ioc );
  while( err && iavf_retry( &deadline, err ) );
  return err;
}

static int
iavf_drops_install( char const *        pf_if,
                    fd_config_t const * config ) {
  fd_ethtool_ioctl_t ioc;
  if( !fd_ethtool_ioctl_init( &ioc, pf_if ) ) return -1;
  long deadline = 0L;
  int err;
  do err = fd_ethtool_ioctl_feature_set( &ioc, FD_ETHTOOL_FEATURE_NTUPLE, 1 );
  while( err && iavf_retry( &deadline, err ) );
  if( err ) goto done;
  err = iavf_drops_clear( &ioc );
  if( err ) goto done;

  struct ethtool_rxnfc count = { .cmd=ETHTOOL_GRXCLSRLCNT };
  if( iavf_ethtool( &ioc, &count ) ) { err = errno; goto done; }
  uint capacity = (uint)(count.data & ~((ulong)RX_CLS_LOC_SPECIAL));
  if( !capacity || capacity>65536U ) { err = EOPNOTSUPP; goto done; }
  ushort ports[ IAVF_DROP_MAX ];
  uint port_cnt = iavf_udp_ports( config, ports );
  if( port_cnt>capacity ) { err = ENOSPC; goto done; }

  for( uint i=0U; i<port_cnt; i++ ) {
    struct ethtool_rx_flow_spec rule = iavf_drop_rule( config, ports[i], capacity-1U-i );
    struct ethtool_rxnfc insert = { .cmd=ETHTOOL_SRXCLSRLINS, .fs=rule };
    if( iavf_ethtool( &ioc, &insert ) ) { err = errno; goto done; }
    struct ethtool_rx_flow_spec current;
    if( iavf_drop_get( &ioc, rule.location, &current ) ) { err = errno; goto done; }
    if( !iavf_drop_equal( &rule, &current ) ) { err = EPROTO; goto done; }
  }
done:
  fd_ethtool_ioctl_fini( &ioc );
  if( err ) { errno = err; return -1; }
  return 0;
}

static configure_result_t
iavf_check_device( fd_config_t const * config,
                   char const *        pf_if,
                   int                 check_type ) {
  uint numvfs;
  if( iavf_numvfs_get( pf_if, &numvfs ) ) PARTIALLY_CONFIGURED( "PF %s VF count unreadable", pf_if );
  if( !numvfs ) NOT_CONFIGURED( "PF %s has no VFs", pf_if );
  if( numvfs==1U && (check_type==FD_CONFIGURE_CHECK_TYPE_FINI_PERM ||
                    check_type==FD_CONFIGURE_CHECK_TYPE_PRE_FINI) ) {
    PARTIALLY_CONFIGURED( "PF %s has one VF to remove", pf_if );
  }

  fd_ethtool_ioctl_t ioc;
  if( !fd_ethtool_ioctl_init( &ioc, pf_if ) ) PARTIALLY_CONFIGURED( "PF %s filter lookup failed", pf_if );
  int ntuple_enabled = 0;
  if( fd_ethtool_ioctl_feature_test( &ioc, FD_ETHTOOL_FEATURE_NTUPLE, &ntuple_enabled ) ) {
    fd_ethtool_ioctl_fini( &ioc );
    PARTIALLY_CONFIGURED( "PF %s filter feature unreadable", pf_if );
  }
  if( !ntuple_enabled ) {
    fd_ethtool_ioctl_fini( &ioc );
    NOT_CONFIGURED( "PF %s ntuple filtering disabled", pf_if );
  }
  ushort ports[ IAVF_DROP_MAX ];
  uint port_cnt = iavf_udp_ports( config, ports );
  struct ethtool_rxnfc count = { .cmd=ETHTOOL_GRXCLSRLCNT };
  if( iavf_ethtool( &ioc, &count ) ) {
    fd_ethtool_ioctl_fini( &ioc );
    PARTIALLY_CONFIGURED( "PF %s filter count unreadable", pf_if );
  }
  if( !count.rule_cnt && port_cnt ) {
    fd_ethtool_ioctl_fini( &ioc );
    NOT_CONFIGURED( "PF %s UDP drop rules missing", pf_if );
  }
  uint capacity = (uint)(count.data & ~((ulong)RX_CLS_LOC_SPECIAL));
  int valid = capacity && capacity<=65536U && port_cnt<=capacity && count.rule_cnt==port_cnt;
  for( uint i=0U; valid && i<port_cnt; i++ ) {
    struct ethtool_rx_flow_spec rule = iavf_drop_rule( config, ports[i], capacity-1U-i );
    struct ethtool_rx_flow_spec current;
    valid = !iavf_drop_get( &ioc, rule.location, &current ) && iavf_drop_equal( &rule, &current );
  }
  fd_ethtool_ioctl_fini( &ioc );
  if( !valid ) PARTIALLY_CONFIGURED( "PF %s UDP drop rules differ", pf_if );

  char pf_pci[ FD_IAVF_PCI_ADDR_SZ ];
  char vf_pci[ FD_IAVF_PCI_ADDR_SZ ];
  uint vf_idx;
  fd_iavf_pci_info_t pci;
  if( iavf_pf_pci( pf_if, pf_pci ) || fd_iavf_get_last_vf( pf_if, &vf_idx, vf_pci ) ||
      fd_iavf_pci_probe( &pci, vf_pci ) || strcmp( pci.pf_pci_addr, pf_pci ) || strcmp( pci.driver, "vfio-pci" ) ) {
    PARTIALLY_CONFIGURED( "PF %s highest-index VF or driver differs", pf_if );
  }
  uchar mac[ 6 ];
  iavf_vf_policy_t policy;
  if( iavf_interface_mac( config->net.interface, mac ) || iavf_policy_get( pf_if, vf_idx, &policy ) ||
      !policy.mac_valid || memcmp( policy.mac, mac, 6UL ) ||
      !policy.spoofchk_valid || policy.spoofchk ||
      !policy.trust_valid || policy.trust ||
      !policy.link_state_valid || !policy.link_state_auto ) {
    PARTIALLY_CONFIGURED( "PF %s MAC or VF policy differs", pf_if );
  }
  CONFIGURE_OK();
}

static int
iavf_vf_idle( char const * vf_pci ) {
  uint user_pid;
  int in_use = iavf_vfio_user_pid( vf_pci, &user_pid );
  if( in_use<0 ) return -1;
  if( in_use ) {
    FD_LOG_WARNING(( "VF %s is in use by PID %u", vf_pci, user_pid ));
    errno = EBUSY;
    return -1;
  }
  return 0;
}

static int
iavf_init_device( char const *        pf_if,
                  uchar const         mac[ 6 ],
                  fd_config_t const * config ) {
  long deadline = 0L;
  for(;;) {
    uint numvfs;
    if( iavf_numvfs_get( pf_if, &numvfs ) ) return -1;
    if( numvfs || !iavf_numvfs_set( pf_if, 1U ) ) break;
    if( !iavf_retry( &deadline, errno ) ) return -1;
  }
  char pf_pci[ FD_IAVF_PCI_ADDR_SZ ];
  char vf_pci[ FD_IAVF_PCI_ADDR_SZ ];
  uint vf_idx;
  fd_iavf_pci_info_t pci;
  if( iavf_pf_pci( pf_if, pf_pci ) || fd_iavf_get_last_vf( pf_if, &vf_idx, vf_pci ) ||
      fd_iavf_pci_probe( &pci, vf_pci ) ) return -1;
  if( strcmp( pci.pf_pci_addr, pf_pci ) ) { errno = ENODEV; return -1; }
  if( iavf_vf_idle( vf_pci ) || iavf_bind_vfio( vf_pci ) || iavf_policy_set( pf_if, vf_idx, mac ) ) return -1;
  return iavf_drops_install( pf_if, config );
}

static void
init( fd_config_t const * config ) {
  configure_result_t vfio = fd_cfg_stage_vfio.check( config, FD_CONFIGURE_CHECK_TYPE_PRE_INIT );
  if( FD_UNLIKELY( vfio.result!=CONFIGURE_OK ) ) {
    FD_LOG_ERR(( "%s. Run `%s configure init vfio`.", vfio.message, FD_BINARY_NAME ));
  }
  char members[ FD_IAVF_MEMBER_MAX ][ IFNAMSIZ ];
  ulong member_cnt;
  if( fd_iavf_member_interfaces( config->net.interface, members, &member_cnt ) ) {
    FD_LOG_ERR(( "IAVF member discovery failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  uchar mac[ 6 ];
  if( iavf_interface_mac( config->net.interface, mac ) ) {
    FD_LOG_ERR(( "interface MAC read failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  for( ulong i=0UL; i<member_cnt; i++ ) {
    if( iavf_check_device( config, members[i], FD_CONFIGURE_CHECK_TYPE_PRE_INIT ).result==CONFIGURE_OK ) continue;
    if( iavf_init_device( members[i], mac, config ) ) {
      FD_LOG_ERR(( "IAVF configure for %s failed (%i-%s)", members[i], errno, fd_io_strerror( errno ) ));
    }
  }
}

static int
fini( fd_config_t const * config,
      int                 pre_init ) {
  if( pre_init ) return 0;
  char members[ FD_IAVF_MEMBER_MAX ][ IFNAMSIZ ];
  ulong member_cnt;
  if( fd_iavf_member_interfaces( config->net.interface, members, &member_cnt ) ) {
    FD_LOG_ERR(( "IAVF member discovery failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  int changed = 0;
  for( ulong i=0UL; i<member_cnt; i++ ) {
    uint numvfs;
    if( iavf_numvfs_get( members[i], &numvfs ) ) {
      FD_LOG_ERR(( "PF %s VF count unreadable (%i-%s)", members[i], errno, fd_io_strerror( errno ) ));
    }
    if( numvfs==1U ) {
      char vf_pci[ FD_IAVF_PCI_ADDR_SZ ];
      if( fd_iavf_get_last_vf( members[i], NULL, vf_pci ) || iavf_vf_idle( vf_pci ) ) {
        FD_LOG_ERR(( "PF %s VF removal blocked (%i-%s)", members[i], errno, fd_io_strerror( errno ) ));
      }
    }
    fd_ethtool_ioctl_t ioc;
    if( !fd_ethtool_ioctl_init( &ioc, members[i] ) ) {
      FD_LOG_ERR(( "PF %s filter cleanup failed (%i-%s)", members[i], errno, fd_io_strerror( errno ) ));
    }
    struct ethtool_rxnfc count = { .cmd=ETHTOOL_GRXCLSRLCNT };
    int err = 0;
    if( iavf_ethtool( &ioc, &count ) && errno!=EOPNOTSUPP ) err = errno;
    if( !err ) err = iavf_drops_clear( &ioc );
    fd_ethtool_ioctl_fini( &ioc );
    if( err ) FD_LOG_ERR(( "PF %s filter cleanup failed (%i-%s)", members[i], err, fd_io_strerror( err ) ));
    changed |= !!count.rule_cnt;
    long deadline = 0L;
    for(;;) {
      if( iavf_numvfs_get( members[i], &numvfs ) ) {
        FD_LOG_ERR(( "PF %s VF count unreadable (%i-%s)", members[i], errno, fd_io_strerror( errno ) ));
      }
      if( numvfs!=1U ) break;
      char vf_pci[ FD_IAVF_PCI_ADDR_SZ ];
      if( fd_iavf_get_last_vf( members[i], NULL, vf_pci ) || iavf_vf_idle( vf_pci ) ) {
        FD_LOG_ERR(( "PF %s VF removal blocked (%i-%s)", members[i], errno, fd_io_strerror( errno ) ));
      }
      if( !iavf_numvfs_set( members[i], 0U ) ) { changed = 1; break; }
      if( !iavf_retry( &deadline, errno ) ) {
        FD_LOG_ERR(( "PF %s VF removal failed (%i-%s)", members[i], errno, fd_io_strerror( errno ) ));
      }
    }
  }
  return changed;
}

static configure_result_t
check( fd_config_t const * config,
       int                 check_type ) {
  char members[ FD_IAVF_MEMBER_MAX ][ IFNAMSIZ ];
  ulong member_cnt;
  if( fd_iavf_member_interfaces( config->net.interface, members, &member_cnt ) ) {
    PARTIALLY_CONFIGURED( "IAVF member discovery failed (%i-%s)", errno, fd_io_strerror( errno ) );
  }
  ulong missing_cnt = 0UL;
  configure_result_t first = { .result=CONFIGURE_OK };
  for( ulong i=0UL; i<member_cnt; i++ ) {
    configure_result_t result = iavf_check_device( config, members[i], check_type );
    missing_cnt += (ulong)(result.result==CONFIGURE_NOT_CONFIGURED);
    if( first.result==CONFIGURE_OK && result.result!=CONFIGURE_OK ) first = result;
  }
  if( first.result==CONFIGURE_OK ) CONFIGURE_OK();
  /* Init repairs existing VFs without removing them first */
  if( check_type==FD_CONFIGURE_CHECK_TYPE_PRE_INIT ) NOT_CONFIGURED( "%s", first.message );
  if( missing_cnt==member_cnt || first.result==CONFIGURE_PARTIALLY_CONFIGURED ) return first;
  PARTIALLY_CONFIGURED( "IAVF PFs are not all configured" );
}

configure_stage_t fd_cfg_stage_iavf = {
  .name      = NAME,
  .enabled   = enabled,
  .init_perm = perm,
  .fini_perm = perm,
  .init      = init,
  .fini      = fini,
  .check     = check,
};

#undef NAME

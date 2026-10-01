#define _GNU_SOURCE

#include "configure.h"
#include "fd_ethtool_ioctl.h"
#include "../../../platform/fd_file_util.h"
#include "../../../platform/fd_sys_util.h"
#include "../../../../disco/net/iavf/fd_iavf.h"
#include "../../../../waltz/ip/fd_netlink1.h"
#include "../../../../util/net/fd_eth.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define NAME "iavf"

#define IAVF_SYSFS_ROOT "/sys"

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

/* iavf_vf_policy holds the PF's VF settings reported by rtnetlink */
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
init_perm( fd_cap_chk_t *      chk,
           fd_config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "configure Intel SR-IOV VFs and PF filters" );
  if( !fd_iavf_vfio_avail() ) {
    fd_cap_chk_cap( chk, NAME, CAP_SYS_MODULE, "run modprobe to load the vfio-pci kernel module" );
  }
}

static void
fini_perm( fd_cap_chk_t *      chk,
           fd_config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "configure Intel SR-IOV VFs and PF filters" );
}

static int
iavf_parse_mac( char const * text,
                uchar        mac[ 6 ] ) {
  if( FD_UNLIKELY( strlen( text )!=17UL || !fd_cstr_to_mac_addr( text, mac ) ) ) return -1;
  if( FD_UNLIKELY( !(mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]) || fd_eth_mac_is_mcast( mac ) ) ) return -1;
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
  if( FD_UNLIKELY( fd_iavf_numvfs_get( pf_if, numvfs ) ) ) {
    int err = errno;
    char path[ PATH_MAX ];
    iavf_path( path, IAVF_SYSFS_ROOT "/class/net/%s/device/sriov_numvfs", pf_if );
    FD_LOG_WARNING(( "reading %s failed (%i-%s)", path, err, fd_io_strerror( err ) ));
    if( err==ENOENT ) {
      FD_LOG_WARNING(( "Cannot create VFs on PF %s because sriov_numvfs is missing. "
                       "The NIC's Virtualization Mode is likely not set to SR-IOV, so select SR-IOV in the NIC firmware settings "
                       "and reboot the machine", pf_if ));
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
  if( FD_UNLIKELY( fd_file_util_write_uint( path, numvfs ) ) ) {
    int err = errno;
    if( numvfs && err==ENOMEM ) {
      FD_LOG_WARNING(( "Enabling VFs on PF %s failed (%i-%s).\n"
                       "  Linux can return this error for insufficient PCIe resources or a kernel\n"
                       "  memory allocation failure. Review the kernel log to identify the cause",
                       pf_if, err, fd_io_strerror( err ) ));
    }
    errno = err;
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

/* iavf_netlink_request returns a positive errno on failure */
static int
iavf_netlink_request( struct nlmsghdr * request,
                      ushort            reply_type,
                      uchar *           buf,
                      ulong             buf_sz ) {
  fd_netlink_t nl __attribute__((cleanup(fd_netlink_fini)));
  if( FD_UNLIKELY( !fd_netlink_init( &nl, 0U ) ) ) return errno;

  struct timeval timeout = { .tv_sec=5L };
  if( FD_UNLIKELY( setsockopt( nl.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout) ) ) ) return errno;

  request->nlmsg_seq = ++nl.seq;
  long sent = sendto( nl.fd, request, request->nlmsg_len, 0, NULL, 0 );
  if( FD_UNLIKELY( sent<0L ) ) return errno;
  if( FD_UNLIKELY( sent!=(long)request->nlmsg_len ) ) return EIO;

  fd_netlink_iter_t iter;
  fd_netlink_iter_init( &iter, &nl, buf, buf_sz );

  /* A lost ACK must not retry a MAC write and reset the VF again */
  if( FD_UNLIKELY( iter.err==EAGAIN ) ) return ETIMEDOUT;
  if( FD_UNLIKELY( iter.err ) ) return iter.err;
  if( FD_UNLIKELY( fd_netlink_iter_done( &iter ) ) ) return EPROTO;

  struct nlmsghdr const * reply = fd_netlink_iter_msg( &iter );
  if( FD_UNLIKELY( reply->nlmsg_seq!=nl.seq ) ) return EPROTO;

  if( reply->nlmsg_type==NLMSG_ERROR ) {
    if( FD_UNLIKELY( reply->nlmsg_len<NLMSG_LENGTH( sizeof(struct nlmsgerr) ) ) ) return EPROTO;
    /* NLMSG_ERROR carries zero for an ACK or a negative Linux errno */
    struct nlmsgerr const * ack = NLMSG_DATA( reply );
    if( FD_UNLIKELY( ack->error>0 || ack->error<-4095 ) ) return EPROTO;
    if( ack->error ) return -ack->error;
  }

  if( FD_UNLIKELY( reply->nlmsg_type!=reply_type ) ) return EPROTO;
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

  uchar buf[ 4096 ] __attribute__((aligned(NLMSG_ALIGNTO)));
  long deadline = 0L;
  int err;
  do err = iavf_netlink_request( &request.nlh, NLMSG_ERROR, buf, sizeof(buf) );
  while( err && iavf_retry( &deadline, err ) );
  if( err ) { errno = err; return -1; }
  return 0;
}

/* iavf_policy_parse_vf returns ENODATA for a different VF */
static int
iavf_policy_parse_vf( struct rtattr const * vf_info,
                      uint                  vf_idx,
                      iavf_vf_policy_t *     policy ) {
  iavf_vf_policy_t entry     = {0};
  uint             entry_idx = UINT_MAX;

  struct rtattr const * attr      = RTA_DATA( vf_info );
  long                  remaining = (long)RTA_PAYLOAD( vf_info );
  for( ; RTA_OK( attr, remaining ); attr=RTA_NEXT( attr, remaining ) ) {
    uint type = attr->rta_type & NLA_TYPE_MASK;

    if( type==IFLA_VF_MAC ) {
      if( FD_UNLIKELY( RTA_PAYLOAD( attr )!=sizeof(struct ifla_vf_mac) ) ) return EPROTO;
      struct ifla_vf_mac const * vf_mac = RTA_DATA( attr );
      entry_idx = vf_mac->vf;
      fd_memcpy( entry.mac, vf_mac->mac, sizeof(entry.mac) );
      int mac_nonzero = entry.mac[0] | entry.mac[1] | entry.mac[2] | entry.mac[3] | entry.mac[4] | entry.mac[5];
      entry.mac_valid = !!mac_nonzero && !fd_eth_mac_is_mcast( entry.mac );

    } else if( type==IFLA_VF_SPOOFCHK ) {
      if( FD_UNLIKELY( RTA_PAYLOAD( attr )!=sizeof(struct ifla_vf_spoofchk) ) ) return EPROTO;
      struct ifla_vf_spoofchk const * vf_spoofchk = RTA_DATA( attr );
      if( vf_spoofchk->vf!=vf_idx ) continue;

      entry.spoofchk       = !!vf_spoofchk->setting;
      /* Linux uses UINT_MAX when a driver does not report this setting */
      entry.spoofchk_valid = vf_spoofchk->setting!=UINT_MAX;

    } else if( type==IFLA_VF_TRUST ) {
      if( FD_UNLIKELY( RTA_PAYLOAD( attr )!=sizeof(struct ifla_vf_trust) ) ) return EPROTO;
      struct ifla_vf_trust const * vf_trust = RTA_DATA( attr );
      if( vf_trust->vf!=vf_idx ) continue;

      entry.trust       = !!vf_trust->setting;
      entry.trust_valid = vf_trust->setting!=UINT_MAX;

    } else if( type==IFLA_VF_LINK_STATE ) {
      if( FD_UNLIKELY( RTA_PAYLOAD( attr )!=sizeof(struct ifla_vf_link_state) ) ) return EPROTO;
      struct ifla_vf_link_state const * vf_link_state = RTA_DATA( attr );
      if( vf_link_state->vf!=vf_idx ) continue;

      entry.link_state_auto  = vf_link_state->link_state==IFLA_VF_LINK_STATE_AUTO;
      entry.link_state_valid = 1;
    }
  }

  if( FD_UNLIKELY( remaining ) ) return EPROTO;
  if( entry_idx!=vf_idx ) return ENODATA;
  *policy = entry;
  return 0;
}

static int
iavf_policy_read( char const *       pf_if,
                  uint               vf_idx,
                  iavf_vf_policy_t * policy ) {
  uint if_idx = if_nametoindex( pf_if );
  if( FD_UNLIKELY( !if_idx ) ) return -1;

  struct {
    struct nlmsghdr  nlh;
    struct ifinfomsg ifi;
    struct rtattr    ext_mask;
    uint             ext_mask_value;
  } request = {
    .nlh = {
      .nlmsg_len   = sizeof(request),
      .nlmsg_type  = RTM_GETLINK,
      .nlmsg_flags = NLM_F_REQUEST
    },
    .ifi            = { .ifi_family=AF_UNSPEC, .ifi_index=(int)if_idx },
    .ext_mask       = { .rta_type=IFLA_EXT_MASK, .rta_len=RTA_LENGTH( sizeof(uint) ) },
    .ext_mask_value = RTEXT_FILTER_VF
  };

  /* RTM_GETLINK returns every VF on the PF in one reply */
  uchar buf[ 131072 ] __attribute__((aligned(NLMSG_ALIGNTO)));
  int err = iavf_netlink_request( &request.nlh, RTM_NEWLINK, buf, sizeof(buf) );
  if( FD_UNLIKELY( err ) ) goto done;

  struct nlmsghdr const * reply = fd_type_pun_const( buf );
  struct ifinfomsg const * ifi = NLMSG_DATA( reply );
  if( FD_UNLIKELY( reply->nlmsg_len<NLMSG_LENGTH( sizeof(*ifi) ) || ifi->ifi_index!=(int)if_idx ) ) {
    err = EPROTO;
    goto done;
  }

  int vf_found = 0;
  struct rtattr const * attr           = IFLA_RTA( ifi );
  long                  attr_remaining = (long)IFLA_PAYLOAD( reply );
  for( ; RTA_OK( attr, attr_remaining ); attr=RTA_NEXT( attr, attr_remaining ) ) {
    if( (attr->rta_type & NLA_TYPE_MASK)!=IFLA_VFINFO_LIST ) continue;

    struct rtattr const * vf_info      = RTA_DATA( attr );
    long                  vf_remaining = (long)RTA_PAYLOAD( attr );
    for( ; RTA_OK( vf_info, vf_remaining ); vf_info=RTA_NEXT( vf_info, vf_remaining ) ) {
      if( (vf_info->rta_type & NLA_TYPE_MASK)!=IFLA_VF_INFO ) continue;

      err = iavf_policy_parse_vf( vf_info, vf_idx, policy );
      if( err==ENODATA ) continue;
      if( FD_UNLIKELY( err ) ) goto done;
      vf_found = 1;
    }
    if( FD_UNLIKELY( vf_remaining ) ) {
      err = EPROTO;
      goto done;
    }
  }

  if( FD_UNLIKELY( attr_remaining ) ) err = EPROTO;
  else if( !vf_found ) err = ENODATA;
  else err = 0;
done:
  if( FD_UNLIKELY( err ) ) {
    errno = err;
    return -1;
  }
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
  ushort ports[ 32 ];
  uint port_cnt = configure_udp_ports( config, ports );
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
  if( FD_UNLIKELY( iavf_numvfs_get( pf_if, &numvfs ) ) ) {
    FD_LOG_ERR(( "Cannot read the enabled VF count for PF %s (%i-%s)", pf_if, errno, fd_io_strerror( errno ) ));
  }
  int fini_check = check_type==FD_CONFIGURE_CHECK_TYPE_FINI_PERM ||
                   check_type==FD_CONFIGURE_CHECK_TYPE_PRE_FINI  ||
                   check_type==FD_CONFIGURE_CHECK_TYPE_POST_FINI;
  if( fini_check && numvfs==1U ) PARTIALLY_CONFIGURED( "PF %s has one VF to remove", pf_if );
  if( !fini_check && !numvfs ) {
    if( FD_UNLIKELY( fd_iavf_sriov_resources_check( pf_if ) ) ) {
      int err = errno;
      if( err==ENOMEM ) {
        FD_LOG_ERR(( "The system has not reserved PCIe memory for VFs on PF %s.\n\n"
                     "  %s", pf_if, fd_iavf_sriov_bios_guide() ));
      }
      FD_LOG_ERR(( "Checking VF PCIe memory resources for PF %s failed (%i-%s). "
                   "Check that /sys/class/net/%s/device/resource is accessible.",
                   pf_if, err, fd_io_strerror( err ), pf_if ));
    }
    NOT_CONFIGURED( "PF %s has no VFs", pf_if );
  }
  fd_ethtool_ioctl_t ioc;
  if( !fd_ethtool_ioctl_init( &ioc, pf_if ) ) {
    PARTIALLY_CONFIGURED( "Opening PF %s for ntuple rule lookup failed (%i-%s)", pf_if, errno, fd_io_strerror( errno ) );
  }
  if( !fini_check ) {
    int ntuple_enabled = 0;
    int err = fd_ethtool_ioctl_feature_test( &ioc, FD_ETHTOOL_FEATURE_NTUPLE, &ntuple_enabled );
    if( err || !ntuple_enabled ) {
      fd_ethtool_ioctl_fini( &ioc );
      if( err ) PARTIALLY_CONFIGURED( "Reading ntuple filtering support on PF %s failed (%i-%s)", pf_if, err, fd_io_strerror( err ) );
      NOT_CONFIGURED( "PF %s ntuple filtering disabled", pf_if );
    }
  }

  /* PF drop rules can remain after the VFs have been removed */
  struct ethtool_rxnfc count = { .cmd=ETHTOOL_GRXCLSRLCNT };
  int err = iavf_ethtool( &ioc, &count ) ? errno : 0;
  if( err || fini_check ) {
    fd_ethtool_ioctl_fini( &ioc );
    if( err && !(fini_check && err==EOPNOTSUPP) ) {
      PARTIALLY_CONFIGURED( "Reading the ntuple rule count on PF %s failed (%i-%s)", pf_if, err, fd_io_strerror( err ) );
    }
    if( !err && count.rule_cnt ) PARTIALLY_CONFIGURED( "PF %s has %u ntuple rules to remove", pf_if, count.rule_cnt );
    NOT_CONFIGURED( "PF %s has %u VFs and no ntuple rules to remove", pf_if, numvfs );
  }
  ushort ports[ 32 ];
  uint port_cnt = configure_udp_ports( config, ports );
  if( !count.rule_cnt && port_cnt ) {
    fd_ethtool_ioctl_fini( &ioc );
    NOT_CONFIGURED( "PF %s UDP drop rules missing", pf_if );
  }
  uint capacity = (uint)(count.data & ~((ulong)RX_CLS_LOC_SPECIAL));
  int valid = capacity && capacity<=65536U && port_cnt<=capacity && count.rule_cnt==port_cnt;
  for( uint i=0U; valid && i<port_cnt; i++ ) {
    struct ethtool_rx_flow_spec rule = iavf_drop_rule( config, ports[i], capacity-1U-i );
    struct ethtool_rx_flow_spec current;
    if( iavf_drop_get( &ioc, rule.location, &current ) ) { err = errno; break; }
    valid = iavf_drop_equal( &rule, &current );
  }
  fd_ethtool_ioctl_fini( &ioc );
  if( err ) PARTIALLY_CONFIGURED( "Reading a UDP drop rule on PF %s failed (%i-%s)", pf_if, err, fd_io_strerror( err ) );
  if( !valid ) PARTIALLY_CONFIGURED( "PF %s does not have the %u matching UDP drop rules required by IAVF", pf_if, port_cnt );

  char pf_pci[ FD_IAVF_PCI_ADDR_SZ ];
  char vf_pci[ FD_IAVF_PCI_ADDR_SZ ];
  uint vf_idx;
  fd_iavf_pci_info_t pci;
  if( iavf_pf_pci( pf_if, pf_pci ) || fd_iavf_get_last_vf( pf_if, &vf_idx, vf_pci ) || fd_iavf_pci_probe( &pci, vf_pci ) ) {
    PARTIALLY_CONFIGURED( "Reading PCI information for PF %s and its highest-index VF failed (%i-%s)", pf_if, errno, fd_io_strerror( errno ) );
  }
  if( strcmp( pci.pf_pci_addr, pf_pci ) ) {
    PARTIALLY_CONFIGURED( "VF %s belongs to PF %s but IAVF requires PF %s (%s)", vf_pci, pci.pf_pci_addr, pf_if, pf_pci );
  }
  if( strcmp( pci.driver, "vfio-pci" ) ) {
    PARTIALLY_CONFIGURED( "VF %u on PF %s uses driver '%s' but IAVF requires vfio-pci", vf_idx, pf_if, pci.driver );
  }
  uchar mac[ 6 ];
  iavf_vf_policy_t policy;
  if( iavf_interface_mac( config->net.interface, mac ) || iavf_policy_get( pf_if, vf_idx, &policy ) ) {
    PARTIALLY_CONFIGURED( "Reading interface %s MAC or PF %s VF %u policy failed (%i-%s)",
                          config->net.interface, pf_if, vf_idx, errno, fd_io_strerror( errno ) );
  }
  if( !policy.mac_valid || !policy.spoofchk_valid || !policy.trust_valid || !policy.link_state_valid ) {
    PARTIALLY_CONFIGURED( "PF %s did not report a complete policy with a valid unicast MAC address for VF %u", pf_if, vf_idx );
  }
  if( memcmp( policy.mac, mac, 6UL ) || policy.spoofchk || policy.trust || !policy.link_state_auto ) {
    PARTIALLY_CONFIGURED( "VF %u on PF %s requires MAC " FD_ETH_MAC_FMT ", spoof checking disabled, trust disabled and automatic link state",
                          vf_idx, pf_if, FD_ETH_MAC_FMT_ARGS( mac ) );
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

static void
iavf_init_device( char const *        pf_if,
                  uchar const         mac[ 6 ],
                  fd_config_t const * config ) {
  long deadline = 0L;
  for(;;) {
    uint numvfs;
    if( iavf_numvfs_get( pf_if, &numvfs ) ) {
      FD_LOG_ERR(( "Reading the enabled VF count for PF %s failed (%i-%s)", pf_if, errno, fd_io_strerror( errno ) ));
    }
    if( numvfs || !iavf_numvfs_set( pf_if, 1U ) ) break;
    if( !iavf_retry( &deadline, errno ) ) {
      FD_LOG_ERR(( "Creating VF 0 on PF %s through /sys/class/net/%s/device/sriov_numvfs failed (%i-%s)",
                   pf_if, pf_if, errno, fd_io_strerror( errno ) ));
    }
  }
  char pf_pci[ FD_IAVF_PCI_ADDR_SZ ];
  char vf_pci[ FD_IAVF_PCI_ADDR_SZ ];
  uint vf_idx;
  fd_iavf_pci_info_t pci;
  if( iavf_pf_pci( pf_if, pf_pci ) || fd_iavf_get_last_vf( pf_if, &vf_idx, vf_pci ) || fd_iavf_pci_probe( &pci, vf_pci ) ) {
    FD_LOG_ERR(( "Reading PCI information for PF %s and its highest-index VF failed (%i-%s)", pf_if, errno, fd_io_strerror( errno ) ));
  }
  if( strcmp( pci.pf_pci_addr, pf_pci ) ) {
    FD_LOG_ERR(( "VF %s belongs to PF %s but IAVF requires PF %s (%s)", vf_pci, pci.pf_pci_addr, pf_if, pf_pci ));
  }
  if( iavf_vf_idle( vf_pci ) ) {
    FD_LOG_ERR(( "VF %s on PF %s is unavailable for configuration (%i-%s)", vf_pci, pf_if, errno, fd_io_strerror( errno ) ));
  }
  if( iavf_bind_vfio( vf_pci ) ) {
    FD_LOG_ERR(( "Binding VF %s on PF %s to vfio-pci failed (%i-%s)", vf_pci, pf_if, errno, fd_io_strerror( errno ) ));
  }
  if( iavf_policy_set( pf_if, vf_idx, mac ) ) {
    FD_LOG_ERR(( "Setting the MAC, spoof checking, trust and link state of VF %u on PF %s failed (%i-%s)",
                 vf_idx, pf_if, errno, fd_io_strerror( errno ) ));
  }
  if( iavf_drops_install( pf_if, config ) ) {
    FD_LOG_ERR(( "Installing UDP drop rules on PF %s failed (%i-%s)", pf_if, errno, fd_io_strerror( errno ) ));
  }
}

static void
init( fd_config_t const * config ) {
  if( !fd_iavf_vfio_avail() ) {
    FD_LOG_NOTICE(( "%sRUN: `modprobe vfio-pci`%s", fd_log_style_dim(), fd_log_style_normal() ));
    if( FD_UNLIKELY( fd_sys_util_modprobe( "vfio-pci", 0 ) ) ) {
      FD_LOG_ERR(( "failed to load vfio-pci kernel module. Run `sudo modprobe vfio-pci` and retry" ));
    }
    if( FD_UNLIKELY( !fd_iavf_vfio_avail() ) ) {
      FD_LOG_ERR(( "vfio-pci driver still unavailable after trying to load its kernel module" ));
    }
  }
  char members[ FD_IAVF_MEMBER_MAX ][ IFNAMSIZ ];
  ulong member_cnt;
  if( fd_iavf_member_interfaces( config->net.interface, members, &member_cnt ) ) {
    FD_LOG_ERR(( "IAVF member discovery failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  /* Check every bond member before creating a VF on any PF. */
  int member_configured[ FD_IAVF_MEMBER_MAX ];
  for( ulong i=0UL; i<member_cnt; i++ ) {
    char const * diagnostic;
    if( FD_UNLIKELY( fd_iavf_iommu_check( members[i], &diagnostic ) ) ) {
      int err = errno;
      FD_LOG_ERR(( "%s for PF %s.\n"
                   "  Resolving /sys/class/net/%s/device/iommu_group failed (%i-%s).\n\n"
                   "  %s",
                   err==ENOENT ? "IOMMU is not enabled" : "IOMMU check failed",
                   members[i], members[i], err, fd_io_strerror( err ), diagnostic ));
    }
    member_configured[i] = iavf_check_device( config, members[i], FD_CONFIGURE_CHECK_TYPE_PRE_INIT ).result==CONFIGURE_OK;
  }
  uchar mac[ 6 ];
  if( iavf_interface_mac( config->net.interface, mac ) ) {
    FD_LOG_ERR(( "interface MAC read failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  for( ulong i=0UL; i<member_cnt; i++ ) {
    if( member_configured[i] ) continue;
    iavf_init_device( members[i], mac, config );
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
  if( check_type!=FD_CONFIGURE_CHECK_TYPE_FINI_PERM &&
      check_type!=FD_CONFIGURE_CHECK_TYPE_PRE_FINI  &&
      check_type!=FD_CONFIGURE_CHECK_TYPE_POST_FINI &&
      !fd_iavf_vfio_avail() ) {
    NOT_CONFIGURED( "vfio-pci driver unavailable" );
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
  .init_perm = init_perm,
  .fini_perm = fini_perm,
  .init      = init,
  .fini      = fini,
  .check     = check,
};

#undef NAME

#define _GNU_SOURCE

#include "configure.h"
#include "fd_ethtool_ioctl.h"
#include "../../../platform/fd_file_util.h"
#include "../../../../disco/net/iavf/fd_iavf.h"
#include "../../../../waltz/ip/fd_netlink1.h"
#include "../../../../util/net/fd_eth.h"

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
#include <unistd.h>

#define NAME "iavf"

#define IAVF_SYSFS_ROOT "/sys"

/* iavf_vf_policy holds the PF's rtnetlink settings for one VF. Missing
   attributes leave the corresponding *_valid fields clear */
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
  return 0==strcmp( config->net.provider, "iavf" );
}

static void
perm( fd_cap_chk_t *      chk,
      fd_config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "configure Intel SR-IOV VFs and PF filters" );
}

static int
iavf_netdev_mac_get( char const * interface,
                     uchar        mac[ 6 ] ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, IAVF_SYSFS_ROOT "/class/net/%s/address", interface ) );

  char  text[ 32 ];
  ulong text_sz;
  if( FD_UNLIKELY( NULL==fd_file_util_read_cstr( path, text, sizeof(text), &text_sz ) ) ) return -1;
  if( 0!=text_sz && text[ text_sz-1UL ]=='\n' ) text[ --text_sz ] = '\0';
  if( FD_UNLIKELY( strlen( text )!=17UL || !fd_cstr_to_mac_addr( text, mac ) ) ) {
    errno = EBADMSG;
    return -1;
  }
  if( FD_UNLIKELY( !(mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]) || fd_eth_mac_is_mcast( mac ) ) ) {
    errno = EBADMSG;
    return -1;
  }
  return 0;
}

static int
iavf_sysfs_write_cstr( char const * path,
                       char const * value ) {
  int fd = open( path, O_WRONLY | O_CLOEXEC );
  if( FD_UNLIKELY( -1==fd ) ) return -1;

  ulong value_sz = strlen( value );
  long  written  = write( fd, value, value_sz );
  if( FD_UNLIKELY( -1==written || (ulong)written!=value_sz ) ) {
    int err = -1==written ? errno : EIO;
    close( fd );
    errno = err;
    return -1;
  }
  return close( fd );
}

static int
iavf_pf_pci_addr_get( char const * pf_if,
                      char         pf_pci[ FD_IAVF_PCI_ADDR_SZ ] ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, IAVF_SYSFS_ROOT "/class/net/%s/device", pf_if ) );
  char resolved[ PATH_MAX ];
  if( FD_UNLIKELY( NULL==realpath( path, resolved ) ) ) return -1;
  char const * pci = strrchr( resolved, '/' )+1;
  if( FD_UNLIKELY( strlen( pci )!=FD_IAVF_PCI_ADDR_SZ-1UL ) ) {
    errno = ENODEV;
    return -1;
  }
  fd_cstr_ncpy( pf_pci, pci, FD_IAVF_PCI_ADDR_SZ );
  return 0;
}

static int
iavf_pci_driver_name_get( char const * pci,
                          char         driver[ FD_IAVF_DRIVER_NAME_MAX ] ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, IAVF_SYSFS_ROOT "/bus/pci/devices/%s/driver", pci ) );
  char resolved[ PATH_MAX ];
  if( FD_UNLIKELY( NULL==realpath( path, resolved ) ) ) return -1;
  char const * name = strrchr( resolved, '/' )+1;
  if( FD_UNLIKELY( strlen( name )>=FD_IAVF_DRIVER_NAME_MAX ) ) {
    errno = ENAMETOOLONG;
    return -1;
  }
  fd_cstr_ncpy( driver, name, FD_IAVF_DRIVER_NAME_MAX );
  return 0;
}

static int
iavf_pf_sriov_numvfs_get( char const * pf_if,
                          uint *       numvfs ) {
  if( FD_UNLIKELY( -1==fd_iavf_numvfs_get( pf_if, numvfs ) ) ) {
    int err = errno;
    char path[ PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, IAVF_SYSFS_ROOT "/class/net/%s/device/sriov_numvfs", pf_if ) );
    FD_LOG_WARNING(( "reading %s failed (%i-%s)", path, err, fd_io_strerror( err ) ));
    if( err==ENOENT ) {
      FD_LOG_WARNING(( "Cannot create VFs on PF %s because sriov_numvfs is missing. "
                       "The NIC's Virtualization Mode is likely not set to SR-IOV, so select SR-IOV in the NIC firmware settings "
                       "and reboot the machine", pf_if ));
      char const * guide = fd_iavf_sriov_bios_guide( 1 );
      if( NULL!=guide ) FD_LOG_WARNING(( "%s", guide ));
    }
    errno = err;
    return -1;
  }
  return 0;
}

static int
iavf_pf_sriov_numvfs_set( char const * pf_if,
                          uint         numvfs ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, IAVF_SYSFS_ROOT "/class/net/%s/device/sriov_numvfs", pf_if ) );
  if( FD_UNLIKELY( -1==fd_file_util_write_uint( path, numvfs ) ) ) {
    int err = errno;
    if( 0!=numvfs && err==ENOMEM ) {
      FD_LOG_WARNING(( "Enabling VFs on PF %s failed (%i-%s).\n"
                       "  Linux can return this error for insufficient PCIe resources or a kernel\n"
                       "  memory allocation failure",
                       pf_if, err, fd_io_strerror( err ) ));
    }
    errno = err;
    return -1;
  }
  return 0;
}

static int
iavf_vf_iommu_group_get( char const * vf_pci,
                         char         group[ 32 ] ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, IAVF_SYSFS_ROOT "/bus/pci/devices/%s/iommu_group", vf_pci ) );
  char resolved[ PATH_MAX ];
  if( FD_UNLIKELY( NULL==realpath( path, resolved ) ) ) return -1;
  char const * name    = strrchr( resolved, '/' )+1;
  ulong        name_sz = strlen( name );
  if( FD_UNLIKELY( 0==name_sz || name_sz>=32UL ) ) {
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

/* iavf_vf_vfio_group_user_pid_find scans /proc/<pid>/fd for the VF's
   /dev/vfio/<group> descriptor. Returns 1 with *user_pid set when found,
   0 if no descriptor is found, or -1 with errno set on failure */
static int
iavf_vf_vfio_group_user_pid_find( char const * vf_pci,
                                  uint *       user_pid ) {
  char group[ 32 ];
  if( FD_UNLIKELY( -1==iavf_vf_iommu_group_get( vf_pci, group ) ) ) return -1;
  char vfio_path[ 64 ];
  FD_TEST( fd_cstr_printf_check( vfio_path, sizeof(vfio_path), NULL, "/dev/vfio/%s", group ) );

  DIR * proc = opendir( "/proc" );
  if( FD_UNLIKELY( NULL==proc ) ) return -1;
  int err = 0;
  for(;;) {
    errno                   = 0;
    struct dirent * process = readdir( proc );
    if( NULL==process ) {
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
    if( NULL==fd_dir ) {
      if( errno==ENOENT ) continue;
      err = errno;
      break;
    }
    for(;;) {
      errno                    = 0;
      struct dirent * fd_entry = readdir( fd_dir );
      if( NULL==fd_entry ) {
        if( 0!=errno ) err = errno;
        break;
      }
      if( fd_entry->d_name[0]=='.' ) continue;
      char fd_path[ PATH_MAX ];
      FD_TEST( fd_cstr_printf_check( fd_path, sizeof(fd_path), NULL, "%s/%s", fd_dir_path, fd_entry->d_name ) );
      char target[ PATH_MAX ];
      long target_sz = readlink( fd_path, target, sizeof(target)-1UL );
      if( -1==target_sz ) {
        if( errno==ENOENT ) continue;
        err = errno;
        break;
      }
      target[ target_sz ] = '\0';
      if( 0!=strcmp( target, vfio_path ) ) continue;
      ulong pid = strtoul( process->d_name, NULL, 10 );
      if( FD_UNLIKELY( pid>UINT_MAX ) ) {
        err = ERANGE;
        break;
      }
      *user_pid = (uint)pid;
      if( FD_UNLIKELY( -1==closedir( fd_dir ) && 0==err ) ) err = errno;
      if( FD_UNLIKELY( -1==closedir( proc ) && 0==err ) ) err = errno;
      if( 0!=err ) {
        errno = err;
        return -1;
      }
      return 1;
    }
    if( FD_UNLIKELY( -1==closedir( fd_dir ) && 0==err ) ) err = errno;
    if( 0!=err ) break;
  }
  if( FD_UNLIKELY( -1==closedir( proc ) && 0==err ) ) err = errno;
  if( 0!=err ) {
    errno = err;
    return -1;
  }
  return 0;
}

/* iavf_rtnetlink_request returns 0 on success or a positive errno on failure */
static int
iavf_rtnetlink_request( struct nlmsghdr * request,
                        ushort            reply_type,
                        uchar *           buf,
                        ulong             buf_sz ) {
  fd_netlink_t nl __attribute__((cleanup(fd_netlink_fini)));
  if( FD_UNLIKELY( NULL==fd_netlink_init( &nl, 0U ) ) ) return errno;

  struct timeval timeout = { .tv_sec=5L };
  if( FD_UNLIKELY( -1==setsockopt( nl.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout) ) ) ) return errno;

  request->nlmsg_seq = ++nl.seq;
  long sent = sendto( nl.fd, request, request->nlmsg_len, 0, NULL, 0 );
  if( FD_UNLIKELY( -1==sent ) ) return errno;
  if( FD_UNLIKELY( sent!=(long)request->nlmsg_len ) ) return EIO;

  fd_netlink_iter_t iter;
  fd_netlink_iter_init( &iter, &nl, buf, buf_sz );

  /* Distinguish a receive timeout from a driver returning EAGAIN */
  if( FD_UNLIKELY( iter.err==EAGAIN ) ) return ETIMEDOUT;
  if( FD_UNLIKELY( 0!=iter.err ) ) return iter.err;
  if( FD_UNLIKELY( fd_netlink_iter_done( &iter ) ) ) return EPROTO;

  struct nlmsghdr const * reply = fd_netlink_iter_msg( &iter );
  if( FD_UNLIKELY( reply->nlmsg_seq!=nl.seq ) ) return EPROTO;

  if( reply->nlmsg_type==NLMSG_ERROR ) {
    if( FD_UNLIKELY( reply->nlmsg_len<NLMSG_LENGTH( sizeof(struct nlmsgerr) ) ) ) return EPROTO;
    /* NLMSG_ERROR carries zero for an ACK or a negative Linux errno */
    struct nlmsgerr const * ack = NLMSG_DATA( reply );
    if( FD_UNLIKELY( ack->error>0 || ack->error<-4095 ) ) return EPROTO;
    if( 0!=ack->error ) return -ack->error;
  }

  if( FD_UNLIKELY( reply->nlmsg_type!=reply_type ) ) return EPROTO;
  return 0;
}

static int
iavf_vf_policy_attr_set( uint         if_idx,
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
  FD_TEST( value_sz<=sizeof(request.value) && 0==(value_sz & 3U) );
  request.setting.rta_len = (ushort)RTA_LENGTH( value_sz );
  request.vf.rta_len      = (ushort)RTA_LENGTH( request.setting.rta_len );
  request.list.rta_len    = (ushort)RTA_LENGTH( request.vf.rta_len );
  request.nlh.nlmsg_len   = NLMSG_LENGTH( sizeof(request.ifi)+request.list.rta_len );
  fd_memcpy( request.value, value, value_sz );

  uchar buf[ 4096 ] __attribute__((aligned(NLMSG_ALIGNTO)));
  int err = iavf_rtnetlink_request( &request.nlh, NLMSG_ERROR, buf, sizeof(buf) );
  if( 0!=err ) { errno = err; return -1; }
  return 0;
}

/* iavf_vf_policy_parse extracts the MAC address, spoof checking, trust and
   link state from one IFLA_VF_INFO entry matching vf_idx */
static int
iavf_vf_policy_parse( struct rtattr const * vf_info,
                      uint                  vf_idx,
                      iavf_vf_policy_t *    policy ) {
  iavf_vf_policy_t entry     = {0};
  uint             entry_idx = UINT_MAX;

  struct rtattr const * attr      = RTA_DATA( vf_info );
  long                  remaining = (long)RTA_PAYLOAD( vf_info );
  for( ; RTA_OK( attr, remaining ); attr=RTA_NEXT( attr, remaining ) ) {
    int type = attr->rta_type & NLA_TYPE_MASK;

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

  if( FD_UNLIKELY( 0!=remaining ) ) return EPROTO;
  if( entry_idx!=vf_idx ) return ENODATA;
  *policy = entry;
  return 0;
}

/* iavf_vf_policy_get reads vf_idx's settings through RTM_GETLINK on pf_if.
   The PF can report these settings when the VF is bound to vfio-pci and
   has no Linux network interface */
static int
iavf_vf_policy_get( char const *       pf_if,
                    uint               vf_idx,
                    iavf_vf_policy_t * policy ) {
  uint if_idx = if_nametoindex( pf_if );
  if( FD_UNLIKELY( 0==if_idx ) ) return -1;

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
  int err = iavf_rtnetlink_request( &request.nlh, RTM_NEWLINK, buf, sizeof(buf) );
  if( FD_UNLIKELY( 0!=err ) ) goto done;

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

      err = iavf_vf_policy_parse( vf_info, vf_idx, policy );
      if( err==ENODATA ) continue;
      if( FD_UNLIKELY( 0!=err ) ) goto done;
      vf_found = 1;
    }
    if( FD_UNLIKELY( 0!=vf_remaining ) ) {
      err = EPROTO;
      goto done;
    }
  }

  if( FD_UNLIKELY( 0!=attr_remaining ) ) err = EPROTO;
  else if( !vf_found ) err = ENODATA;
  else err = 0;
done:
  if( FD_UNLIKELY( 0!=err ) ) {
    errno = err;
    return -1;
  }
  return 0;
}

static void
iavf_vf_policy_configure( char const * pf_if,
                          uint         vf_idx,
                          uchar const  mac[ 6 ] ) {
  iavf_vf_policy_t policy;
  if( -1==iavf_vf_policy_get( pf_if, vf_idx, &policy ) ) {
    FD_LOG_ERR(( "Reading settings for VF %u on PF %s failed (%i-%s)", vf_idx, pf_if, errno, fd_io_strerror( errno ) ));
  }
  uint if_idx = if_nametoindex( pf_if );
  if( 0==if_idx ) {
    FD_LOG_ERR(( "Looking up the interface index for PF %s failed (%i-%s)", pf_if, errno, fd_io_strerror( errno ) ));
  }
  struct ifla_vf_mac        vf_mac   = { .vf=vf_idx };
  struct ifla_vf_spoofchk   spoofchk = { .vf=vf_idx, .setting=0U };
  struct ifla_vf_trust      trust    = { .vf=vf_idx, .setting=0U };
  struct ifla_vf_link_state link     = { .vf=vf_idx, .link_state=IFLA_VF_LINK_STATE_AUTO };
  fd_memcpy( vf_mac.mac, mac, 6UL );
  /* i40e_ndo_set_vf_mac resets the VF even when the MAC address is unchanged */
  if( (!policy.mac_valid || 0!=memcmp( policy.mac, mac, 6UL )) &&
      -1==iavf_vf_policy_attr_set( if_idx, IFLA_VF_MAC, &vf_mac, sizeof(vf_mac) ) ) {
    FD_LOG_ERR(( "Setting the MAC address of VF %u on PF %s failed (%i-%s)", vf_idx, pf_if, errno, fd_io_strerror( errno ) ));
  }
  if( (!policy.spoofchk_valid || policy.spoofchk) &&
      -1==iavf_vf_policy_attr_set( if_idx, IFLA_VF_SPOOFCHK, &spoofchk, sizeof(spoofchk) ) ) {
    FD_LOG_ERR(( "Disabling spoof checking for VF %u on PF %s failed (%i-%s)", vf_idx, pf_if, errno, fd_io_strerror( errno ) ));
  }
  if( (!policy.trust_valid || policy.trust) &&
      -1==iavf_vf_policy_attr_set( if_idx, IFLA_VF_TRUST, &trust, sizeof(trust) ) ) {
    FD_LOG_ERR(( "Disabling trust for VF %u on PF %s failed (%i-%s)", vf_idx, pf_if, errno, fd_io_strerror( errno ) ));
  }
  /* IFLA_VF_LINK_STATE_AUTO reports the physical link's up/down state */
  if( (!policy.link_state_valid || !policy.link_state_auto) &&
      -1==iavf_vf_policy_attr_set( if_idx, IFLA_VF_LINK_STATE, &link, sizeof(link) ) ) {
    FD_LOG_ERR(( "Setting automatic link state for VF %u on PF %s failed (%i-%s)", vf_idx, pf_if, errno, fd_io_strerror( errno ) ));
  }
}

static int
iavf_vf_driver_unbind( char const * vf_pci ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, IAVF_SYSFS_ROOT "/bus/pci/devices/%s/driver/unbind", vf_pci ) );
  return iavf_sysfs_write_cstr( path, vf_pci );
}

static int
iavf_vf_driver_override_set( char const * vf_pci,
                             char const * driver ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, IAVF_SYSFS_ROOT "/bus/pci/devices/%s/driver_override", vf_pci ) );
  return iavf_sysfs_write_cstr( path, driver );
}

static void
iavf_vf_vfio_pci_bind( char const * vf_pci ) {
  struct stat st;
  if( FD_UNLIKELY( -1==stat( IAVF_SYSFS_ROOT "/bus/pci/drivers/vfio-pci", &st ) ) ) {
    FD_LOG_ERR(( "Checking /sys/bus/pci/drivers/vfio-pci failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  /* Set driver_override before unbinding so subsequent PCI driver matching
     accepts only vfio-pci for this VF. The override itself does not bind it */
  if( FD_UNLIKELY( -1==iavf_vf_driver_override_set( vf_pci, "vfio-pci" ) ) ) {
    FD_LOG_ERR(( "Setting driver_override to vfio-pci for VF %s failed (%i-%s)", vf_pci, errno, fd_io_strerror( errno ) ));
  }
  char driver[ FD_IAVF_DRIVER_NAME_MAX ];
  int has_driver = 0==iavf_pci_driver_name_get( vf_pci, driver );
  if( !has_driver && errno!=ENOENT ) {
    FD_LOG_ERR(( "Reading the driver for VF %s failed (%i-%s)", vf_pci, errno, fd_io_strerror( errno ) ));
  }
  if( has_driver && 0==strcmp( driver, "vfio-pci" ) ) return;
  if( has_driver && -1==iavf_vf_driver_unbind( vf_pci ) && errno!=ENOENT && errno!=ENODEV ) {
    FD_LOG_ERR(( "Unbinding VF %s from %s failed (%i-%s)", vf_pci, driver, errno, fd_io_strerror( errno ) ));
  }
  /* Probe explicitly, including when sriov_drivers_autoprobe is 0 on the PF */
  int err = -1==iavf_sysfs_write_cstr( IAVF_SYSFS_ROOT "/bus/pci/drivers_probe", vf_pci ) ? errno : 0;
  has_driver = 0==iavf_pci_driver_name_get( vf_pci, driver );
  if( !has_driver && errno!=ENOENT ) {
    FD_LOG_ERR(( "Reading the driver for VF %s after probing failed (%i-%s)", vf_pci, errno, fd_io_strerror( errno ) ));
  }
  if( has_driver && 0==strcmp( driver, "vfio-pci" ) ) return;
  if( 0!=err ) {
    FD_LOG_ERR(( "Probing VF %s through /sys/bus/pci/drivers_probe failed (%i-%s)", vf_pci, err, fd_io_strerror( err ) ));
  }
  FD_LOG_ERR(( "VF %s did not bind to vfio-pci after probing (driver '%s')", vf_pci, has_driver ? driver : "none" ));
}

static int
iavf_pf_ntuple_ioctl( fd_ethtool_ioctl_t *   ioc,
                      struct ethtool_rxnfc * request ) {
  ioc->ifr.ifr_data = (void *)request;
  return ioctl( ioc->fd, SIOCETHTOOL, &ioc->ifr );
}

static int
iavf_pf_ntuple_rule_get( fd_ethtool_ioctl_t *          ioc,
                         uint                          location,
                         struct ethtool_rx_flow_spec * rule ) {
  struct ethtool_rxnfc request = { .cmd=ETHTOOL_GRXCLSRULE, .fs={ .location=location } };
  if( -1==iavf_pf_ntuple_ioctl( ioc, &request ) ) return -1;
  *rule = request.fs;
  return 0;
}

static int
iavf_pf_ntuple_rule_equal( struct ethtool_rx_flow_spec const * a,
                           struct ethtool_rx_flow_spec const * b ) {
  return a->flow_type==b->flow_type && a->ring_cookie==b->ring_cookie &&
         a->location==b->location &&
         0==memcmp( &a->h_u,   &b->h_u,   sizeof(a->h_u)   ) &&
         0==memcmp( &a->m_u,   &b->m_u,   sizeof(a->m_u)   ) &&
         0==memcmp( &a->h_ext, &b->h_ext, sizeof(a->h_ext) ) &&
         0==memcmp( &a->m_ext, &b->m_ext, sizeof(a->m_ext) );
}

/* iavf_pf_ntuple_drop_rule_build returns a drop rule for the given UDP/IPv4
   destination port. The PF drops suppress kernel delivery, while fd_iavf_init
   installs the VF receive MAC filter separately. */
static struct ethtool_rx_flow_spec
iavf_pf_ntuple_drop_rule_build( fd_config_t const * config,
                                ushort              port,
                                uint                location ) {
  return (struct ethtool_rx_flow_spec) {
    .flow_type   = UDP_V4_FLOW,
    .h_u         = { .udp_ip4_spec={ .ip4dst=config->net.bind_address_parsed, .pdst=fd_ushort_bswap( port ) } },
    .m_u         = { .udp_ip4_spec={ .ip4dst=0!=config->net.bind_address_parsed ? UINT_MAX : 0U, .pdst=USHRT_MAX } },
    .ring_cookie = RX_CLS_FLOW_DISC,
    .location    = location
  };
}

static void
iavf_pf_ntuple_drops_install( char const *        pf_if,
                              fd_config_t const * config ) {
  fd_ethtool_ioctl_t ioc;
  if( NULL==fd_ethtool_ioctl_init( &ioc, pf_if ) ) {
    FD_LOG_ERR(( "Opening PF %s for ntuple rule installation failed (%i-%s)", pf_if, errno, fd_io_strerror( errno ) ));
  }
  int err = fd_ethtool_ioctl_feature_set( &ioc, FD_ETHTOOL_FEATURE_NTUPLE, 1 );
  if( 0!=err ) {
    FD_LOG_ERR(( "Enabling ntuple filtering on PF %s failed (%i-%s)", pf_if, err, fd_io_strerror( err ) ));
  }
  /* Delete every PF ntuple rule */
  err = fd_ethtool_ioctl_ntuple_clear( &ioc );
  if( 0!=err ) {
    FD_LOG_ERR(( "Clearing ntuple rules on PF %s failed (%i-%s)", pf_if, err, fd_io_strerror( err ) ));
  }

  struct ethtool_rxnfc count = { .cmd=ETHTOOL_GRXCLSRLCNT };
  if( -1==iavf_pf_ntuple_ioctl( &ioc, &count ) ) {
    FD_LOG_ERR(( "Reading the ntuple rule capacity on PF %s failed (%i-%s)", pf_if, errno, fd_io_strerror( errno ) ));
  }
  uint capacity = (uint)(count.data & ~((ulong)RX_CLS_LOC_SPECIAL));
  if( 0==capacity || capacity>65536U ) {
    FD_LOG_ERR(( "PF %s reports an unsupported ntuple rule capacity of %u", pf_if, capacity ));
  }
  ushort ports[ 32 ];
  uint port_cnt = configure_udp_ports( config, ports );
  if( port_cnt>capacity ) {
    FD_LOG_ERR(( "PF %s has space for %u ntuple rules but IAVF requires %u UDP drop rules", pf_if, capacity, port_cnt ));
  }

  /* Install PF UDP drop rules at ntuple locations capacity-1U-i.
     iavf_pf_config_check uses the same locations to verify each port's rule */
  for( uint i=0U; i<port_cnt; i++ ) {
    struct ethtool_rx_flow_spec rule = iavf_pf_ntuple_drop_rule_build( config, ports[i], capacity-1U-i );
    struct ethtool_rxnfc insert = { .cmd=ETHTOOL_SRXCLSRLINS, .fs=rule };
    if( -1==iavf_pf_ntuple_ioctl( &ioc, &insert ) ) {
      FD_LOG_ERR(( "Installing UDP drop rule %u for port %hu on PF %s failed (%i-%s)", rule.location, ports[i], pf_if, errno, fd_io_strerror( errno ) ));
    }
    struct ethtool_rx_flow_spec current;
    if( -1==iavf_pf_ntuple_rule_get( &ioc, rule.location, &current ) ) {
      FD_LOG_ERR(( "Reading UDP drop rule %u for port %hu on PF %s after installation failed (%i-%s)", rule.location, ports[i], pf_if, errno, fd_io_strerror( errno ) ));
    }
    if( !iavf_pf_ntuple_rule_equal( &rule, &current ) ) {
      FD_LOG_ERR(( "UDP drop rule %u for port %hu on PF %s does not match the required rule after installation", rule.location, ports[i], pf_if ));
    }
  }
  fd_ethtool_ioctl_fini( &ioc );
}

static configure_result_t
iavf_pf_config_check( fd_config_t const * config,
                      char const *        pf_if,
                      int                 check_type ) {
  uint numvfs;
  if( FD_UNLIKELY( -1==iavf_pf_sriov_numvfs_get( pf_if, &numvfs ) ) ) {
    FD_LOG_ERR(( "Cannot read the enabled VF count for PF %s (%i-%s)", pf_if, errno, fd_io_strerror( errno ) ));
  }
  int fini_check = check_type==FD_CONFIGURE_CHECK_TYPE_FINI_PERM ||
                   check_type==FD_CONFIGURE_CHECK_TYPE_PRE_FINI  ||
                   check_type==FD_CONFIGURE_CHECK_TYPE_POST_FINI;
  /* A PF's only VF is removed by configure fini. Report it before checking
     ntuple rules so missing rules cannot cause fini to skip VF removal */
  if( fini_check && numvfs==1U ) {
    PARTIALLY_CONFIGURED( "PF %s has one VF to remove", pf_if );
  }
  if( !fini_check && 0==numvfs ) {
    if( FD_UNLIKELY( -1==fd_iavf_sriov_resources_check( pf_if ) ) ) {
      int err = errno;
      if( err==ENOMEM ) {
        FD_LOG_ERR(( "The system has not reserved PCIe memory for VFs on PF %s.\n\n"
                     "  %s", pf_if, fd_iavf_sriov_bios_guide( 0 ) ));
      }
      FD_LOG_ERR(( "Checking VF PCIe memory resources for PF %s failed (%i-%s). "
                   "Check that /sys/class/net/%s/device/resource is accessible.",
                   pf_if, err, fd_io_strerror( err ), pf_if ));
    }
    NOT_CONFIGURED( "PF %s has no VFs", pf_if );
  }
  fd_ethtool_ioctl_t ioc;
  if( NULL==fd_ethtool_ioctl_init( &ioc, pf_if ) ) {
    PARTIALLY_CONFIGURED( "Opening PF %s for ntuple rule lookup failed (%i-%s)", pf_if, errno, fd_io_strerror( errno ) );
  }
  if( !fini_check ) {
    int ntuple_enabled = 0;
    int err = fd_ethtool_ioctl_feature_test( &ioc, FD_ETHTOOL_FEATURE_NTUPLE, &ntuple_enabled );
    if( 0!=err || !ntuple_enabled ) {
      fd_ethtool_ioctl_fini( &ioc );
      if( 0!=err ) {
        PARTIALLY_CONFIGURED( "Reading ntuple filtering support on PF %s failed (%i-%s)", pf_if, err, fd_io_strerror( err ) );
      }
      NOT_CONFIGURED( "PF %s ntuple filtering disabled", pf_if );
    }
  }

  /* With sriov_numvfs==0, fini still runs if the PF has any ntuple rules */
  struct ethtool_rxnfc count = { .cmd=ETHTOOL_GRXCLSRLCNT };
  int err = -1==iavf_pf_ntuple_ioctl( &ioc, &count ) ? errno : 0;
  if( 0!=err || fini_check ) {
    fd_ethtool_ioctl_fini( &ioc );
    if( 0!=err && !(fini_check && err==EOPNOTSUPP) ) {
      PARTIALLY_CONFIGURED( "Reading the ntuple rule count on PF %s failed (%i-%s)", pf_if, err, fd_io_strerror( err ) );
    }
    if( 0==err && 0!=count.rule_cnt ) {
      PARTIALLY_CONFIGURED( "PF %s has %u ntuple rules to remove", pf_if, count.rule_cnt );
    }
    NOT_CONFIGURED( "PF %s has %u VFs and no ntuple rules to remove", pf_if, numvfs );
  }
  ushort ports[ 32 ];
  uint port_cnt = configure_udp_ports( config, ports );
  if( 0==count.rule_cnt && 0!=port_cnt ) {
    fd_ethtool_ioctl_fini( &ioc );
    NOT_CONFIGURED( "PF %s UDP drop rules missing", pf_if );
  }
  uint capacity = (uint)(count.data & ~((ulong)RX_CLS_LOC_SPECIAL));
  int valid = 0!=capacity && capacity<=65536U && port_cnt<=capacity && count.rule_cnt==port_cnt;
  for( uint i=0U; valid && i<port_cnt; i++ ) {
    struct ethtool_rx_flow_spec rule = iavf_pf_ntuple_drop_rule_build( config, ports[i], capacity-1U-i );
    struct ethtool_rx_flow_spec current;
    if( -1==iavf_pf_ntuple_rule_get( &ioc, rule.location, &current ) ) { err = errno; break; }
    valid = iavf_pf_ntuple_rule_equal( &rule, &current );
  }
  fd_ethtool_ioctl_fini( &ioc );
  if( 0!=err ) {
    PARTIALLY_CONFIGURED( "Reading a UDP drop rule on PF %s failed (%i-%s)", pf_if, err, fd_io_strerror( err ) );
  }
  if( !valid ) {
    PARTIALLY_CONFIGURED( "PF %s does not have the %u matching UDP drop rules required by IAVF", pf_if, port_cnt );
  }

  char pf_pci[ FD_IAVF_PCI_ADDR_SZ ];
  char vf_pci[ FD_IAVF_PCI_ADDR_SZ ];
  uint vf_idx;
  fd_iavf_pci_info_t pci;
  if( -1==iavf_pf_pci_addr_get( pf_if, pf_pci ) ) {
    PARTIALLY_CONFIGURED( "Reading the PCI address of PF %s failed (%i-%s)", pf_if, errno, fd_io_strerror( errno ) );
  }
  if( -1==fd_iavf_get_last_vf( pf_if, &vf_idx, vf_pci ) ) {
    PARTIALLY_CONFIGURED( "Finding the highest-index VF on PF %s failed (%i-%s)", pf_if, errno, fd_io_strerror( errno ) );
  }
  if( -1==fd_iavf_pci_probe( &pci, vf_pci ) ) {
    PARTIALLY_CONFIGURED( "Reading PCI information for VF %s on PF %s failed (%i-%s)", vf_pci, pf_if, errno, fd_io_strerror( errno ) );
  }
  if( 0!=strcmp( pci.pf_pci_addr, pf_pci ) ) {
    PARTIALLY_CONFIGURED( "VF %s belongs to PF %s but IAVF requires PF %s (%s)", vf_pci, pci.pf_pci_addr, pf_if, pf_pci );
  }
  if( 0!=strcmp( pci.driver, "vfio-pci" ) ) {
    PARTIALLY_CONFIGURED( "VF %u on PF %s uses driver '%s' but IAVF requires vfio-pci", vf_idx, pf_if, pci.driver );
  }
  uchar mac[ 6 ];
  iavf_vf_policy_t policy;
  if( -1==iavf_netdev_mac_get( config->net.interface, mac ) ) {
    PARTIALLY_CONFIGURED( "Reading the MAC address of interface %s failed (%i-%s)", config->net.interface, errno, fd_io_strerror( errno ) );
  }
  if( -1==iavf_vf_policy_get( pf_if, vf_idx, &policy ) ) {
    PARTIALLY_CONFIGURED( "Reading settings for VF %u on PF %s failed (%i-%s)", vf_idx, pf_if, errno, fd_io_strerror( errno ) );
  }
  if( !policy.mac_valid ) {
    PARTIALLY_CONFIGURED( "PF %s did not report a valid unicast MAC address for VF %u", pf_if, vf_idx );
  }
  if( !policy.spoofchk_valid ) {
    PARTIALLY_CONFIGURED( "PF %s did not report spoof checking for VF %u", pf_if, vf_idx );
  }
  if( !policy.trust_valid ) {
    PARTIALLY_CONFIGURED( "PF %s did not report trust for VF %u", pf_if, vf_idx );
  }
  if( !policy.link_state_valid ) {
    PARTIALLY_CONFIGURED( "PF %s did not report link state for VF %u", pf_if, vf_idx );
  }
  if( 0!=memcmp( policy.mac, mac, 6UL ) ) {
    PARTIALLY_CONFIGURED( "VF %u on PF %s requires MAC " FD_ETH_MAC_FMT, vf_idx, pf_if, FD_ETH_MAC_FMT_ARGS( mac ) );
  }
  if( policy.spoofchk ) {
    PARTIALLY_CONFIGURED( "VF %u on PF %s requires spoof checking disabled", vf_idx, pf_if );
  }
  if( policy.trust ) {
    PARTIALLY_CONFIGURED( "VF %u on PF %s requires trust disabled", vf_idx, pf_if );
  }
  if( !policy.link_state_auto ) {
    PARTIALLY_CONFIGURED( "VF %u on PF %s requires automatic link state", vf_idx, pf_if );
  }
  CONFIGURE_OK();
}

static int
iavf_vf_vfio_group_idle_check( char const * vf_pci ) {
  uint user_pid;
  int in_use = iavf_vf_vfio_group_user_pid_find( vf_pci, &user_pid );
  if( -1==in_use ) return -1;
  if( in_use ) {
    FD_LOG_WARNING(( "VF %s is in use by PID %u", vf_pci, user_pid ));
    errno = EBUSY;
    return -1;
  }
  return 0;
}

static void
iavf_pf_configure( char const *        pf_if,
                   uchar const         mac[ 6 ],
                   fd_config_t const * config ) {
  /* Linux requires disabling all VFs before changing an existing nonzero
     sriov_numvfs to a different nonzero count. Reuse VF numvfs-1 when VFs
     exist, otherwise create VF 0 */
  uint numvfs;
  if( -1==iavf_pf_sriov_numvfs_get( pf_if, &numvfs ) ) {
    FD_LOG_ERR(( "Reading the enabled VF count for PF %s failed (%i-%s)", pf_if, errno, fd_io_strerror( errno ) ));
  }
  if( 0==numvfs && -1==iavf_pf_sriov_numvfs_set( pf_if, 1U ) ) {
    int err = errno;
    FD_LOG_ERR(( "Creating VF 0 on PF %s through /sys/class/net/%s/device/sriov_numvfs failed (%i-%s)%s",
                 pf_if, pf_if, err, fd_io_strerror( err ),
                 err==ENOMEM ? "" : ".\n  The PF driver may have logged why VF creation failed, so check dmesg for details" ));
  }
  char pf_pci[ FD_IAVF_PCI_ADDR_SZ ];
  char vf_pci[ FD_IAVF_PCI_ADDR_SZ ];
  uint vf_idx;
  fd_iavf_pci_info_t pci;
  if( -1==iavf_pf_pci_addr_get( pf_if, pf_pci ) ) {
    FD_LOG_ERR(( "Reading the PCI address of PF %s failed (%i-%s)", pf_if, errno, fd_io_strerror( errno ) ));
  }
  if( -1==fd_iavf_get_last_vf( pf_if, &vf_idx, vf_pci ) ) {
    FD_LOG_ERR(( "Finding the highest-index VF on PF %s failed (%i-%s)", pf_if, errno, fd_io_strerror( errno ) ));
  }
  if( -1==fd_iavf_pci_probe( &pci, vf_pci ) ) {
    FD_LOG_ERR(( "Reading PCI information for VF %s on PF %s failed (%i-%s)", vf_pci, pf_if, errno, fd_io_strerror( errno ) ));
  }
  if( 0!=strcmp( pci.pf_pci_addr, pf_pci ) ) {
    FD_LOG_ERR(( "VF %s belongs to PF %s but IAVF requires PF %s (%s)", vf_pci, pci.pf_pci_addr, pf_if, pf_pci ));
  }
  if( -1==iavf_vf_vfio_group_idle_check( vf_pci ) ) {
    FD_LOG_ERR(( "VF %s on PF %s is unavailable for configuration (%i-%s)", vf_pci, pf_if, errno, fd_io_strerror( errno ) ));
  }
  iavf_vf_vfio_pci_bind( vf_pci );
  iavf_vf_policy_configure( pf_if, vf_idx, mac );
  iavf_pf_ntuple_drops_install( pf_if, config );
}

static void
init( fd_config_t const * config ) {
  char const * members[] = { config->net.interface };
  ulong const member_cnt = 1UL;
  /* Resolve the PF's iommu_group and check VF BAR allocations when
     sriov_numvfs==0 before creating a VF or replacing PF ntuple rules */
  int member_configured[ FD_IAVF_MEMBER_MAX ];
  for( ulong i=0UL; i<member_cnt; i++ ) {
    char const * diagnostic;
    if( FD_UNLIKELY( -1==fd_iavf_iommu_check( members[i], &diagnostic ) ) ) {
      int err = errno;
      FD_LOG_ERR(( "%s for PF %s.\n"
                   "  Resolving /sys/class/net/%s/device/iommu_group failed (%i-%s).\n\n"
                   "  %s",
                   err==ENOENT ? "IOMMU is not enabled" : "IOMMU check failed",
                   members[i], members[i], err, fd_io_strerror( err ), diagnostic ));
    }
    member_configured[i] = iavf_pf_config_check( config, members[i], FD_CONFIGURE_CHECK_TYPE_PRE_INIT ).result==CONFIGURE_OK;
  }
  uchar mac[ 6 ];
  if( -1==iavf_netdev_mac_get( config->net.interface, mac ) ) {
    FD_LOG_ERR(( "Reading the MAC address of interface %s failed (%i-%s)", config->net.interface, errno, fd_io_strerror( errno ) ));
  }
  for( ulong i=0UL; i<member_cnt; i++ ) {
    if( member_configured[i] ) continue;
    iavf_pf_configure( members[i], mac, config );
  }
}

static int
fini( fd_config_t const * config,
      int                 pre_init ) {
  /* configure init passes pre_init=1 when undoing a partially configured
     stage. Leave existing VFs for init to reuse. The configure fini command
     passes pre_init=0 and runs the PF ntuple and VF removal below */
  if( pre_init ) return 0;
  char const * members[] = { config->net.interface };
  ulong const member_cnt = 1UL;
  int changed = 0;
  for( ulong i=0UL; i<member_cnt; i++ ) {
    uint numvfs;
    if( -1==iavf_pf_sriov_numvfs_get( members[i], &numvfs ) ) {
      FD_LOG_ERR(( "Reading the enabled VF count for PF %s failed (%i-%s)", members[i], errno, fd_io_strerror( errno ) ));
    }
    /* If the sole VF has an open VFIO group descriptor, abort before deleting
       this PF's ntuple rules */
    if( numvfs==1U ) {
      char vf_pci[ FD_IAVF_PCI_ADDR_SZ ];
      if( -1==fd_iavf_get_last_vf( members[i], NULL, vf_pci ) ) {
        FD_LOG_ERR(( "Finding the highest-index VF on PF %s failed (%i-%s)", members[i], errno, fd_io_strerror( errno ) ));
      }
      if( -1==iavf_vf_vfio_group_idle_check( vf_pci ) ) {
        FD_LOG_ERR(( "VF %s on PF %s is unavailable for removal (%i-%s)", vf_pci, members[i], errno, fd_io_strerror( errno ) ));
      }
    }
    fd_ethtool_ioctl_t ioc;
    if( NULL==fd_ethtool_ioctl_init( &ioc, members[i] ) ) {
      FD_LOG_ERR(( "Opening PF %s for ntuple rule cleanup failed (%i-%s)", members[i], errno, fd_io_strerror( errno ) ));
    }
    struct ethtool_rxnfc count = { .cmd=ETHTOOL_GRXCLSRLCNT };
    if( -1==iavf_pf_ntuple_ioctl( &ioc, &count ) && errno!=EOPNOTSUPP ) {
      FD_LOG_ERR(( "Reading the ntuple rule count on PF %s before cleanup failed (%i-%s)", members[i], errno, fd_io_strerror( errno ) ));
    }
    int err = fd_ethtool_ioctl_ntuple_clear( &ioc );
    fd_ethtool_ioctl_fini( &ioc );
    if( 0!=err ) {
      FD_LOG_ERR(( "Clearing ntuple rules on PF %s failed (%i-%s)", members[i], err, fd_io_strerror( err ) ));
    }
    changed |= 0!=count.rule_cnt;

    /* sriov_numvfs=0 removes every VF on the PF. Reread the num and check
       VFIO group descriptors again, and only write zero for a single-VF PF */
    if( -1==iavf_pf_sriov_numvfs_get( members[i], &numvfs ) ) {
      FD_LOG_ERR(( "Reading the enabled VF count for PF %s failed (%i-%s)", members[i], errno, fd_io_strerror( errno ) ));
    }
    if( numvfs==1U ) {
      char vf_pci[ FD_IAVF_PCI_ADDR_SZ ];
      if( -1==fd_iavf_get_last_vf( members[i], NULL, vf_pci ) ) {
        FD_LOG_ERR(( "Finding the highest-index VF on PF %s failed (%i-%s)", members[i], errno, fd_io_strerror( errno ) ));
      }
      if( -1==iavf_vf_vfio_group_idle_check( vf_pci ) ) {
        FD_LOG_ERR(( "VF %s on PF %s is unavailable for removal (%i-%s)", vf_pci, members[i], errno, fd_io_strerror( errno ) ));
      }
      if( -1==iavf_pf_sriov_numvfs_set( members[i], 0U ) ) {
        FD_LOG_ERR(( "Removing VF 0 from PF %s failed (%i-%s)", members[i], errno, fd_io_strerror( errno ) ));
      }
      changed = 1;
    }
  }
  return changed;
}

static configure_result_t
check( fd_config_t const * config,
       int                 check_type ) {
  char const * members[] = { config->net.interface };
  ulong const member_cnt = 1UL;
  ulong missing_cnt = 0UL;
  configure_result_t first = { .result=CONFIGURE_OK };
  for( ulong i=0UL; i<member_cnt; i++ ) {
    configure_result_t result = iavf_pf_config_check( config, members[i], check_type );
    missing_cnt += (ulong)(result.result==CONFIGURE_NOT_CONFIGURED);
    if( first.result==CONFIGURE_OK && result.result!=CONFIGURE_OK ) first = result;
  }
  if( first.result==CONFIGURE_OK ) CONFIGURE_OK();
  /* configure_stage runs fini before init for PARTIALLY_CONFIGURED results.
     Return NOT_CONFIGURED so init can fix VFIO binding, VF settings and
     PF ntuple rules without deleting and recreating VFs */
  if( check_type==FD_CONFIGURE_CHECK_TYPE_PRE_INIT ) {
    NOT_CONFIGURED( "%s", first.message );
  }
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

#define _GNU_SOURCE

#include "configure.h"
#include "../../../platform/fd_file_util.h"
#include "../../../../disco/net/iavf/fd_iavf.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
  uint  link_state;
  int   link_state_valid;
} iavf_vf_policy_t;

typedef struct {
  struct nlmsghdr nlh;
  struct ifinfomsg ifm;
  uchar buf[ 512 ];
} iavf_netlink_req_t;

static int
enabled( fd_config_t const * config ) {
  return !strcmp( config->net.provider, "iavf" );
}

static void
perm( fd_cap_chk_t *      chk,
      fd_config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "create an Intel SR-IOV Virtual Function and bind it to vfio-pci" );
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

static int
iavf_path( char       path[ PATH_MAX ],
           char const * fmt,
           char const * pf_if,
           uint         vf_idx ) {
  return fd_cstr_printf_check( path, PATH_MAX, NULL, fmt, pf_if, vf_idx ) ? 0 : -1;
}

static int
iavf_pf_mac( fd_config_t const * config,
             uchar               mac[ 6 ] ) {
  char path[ PATH_MAX ];
  if( FD_UNLIKELY( iavf_path( path, IAVF_SYSFS_ROOT "/class/net/%s/address",
                              config->net.interface, 0U ) ) ) {
    errno = ENAMETOOLONG;
    return -1;
  }

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
  if( FD_UNLIKELY( close( fd ) ) ) return -1;
  return 0;
}

static int
iavf_realpath( char const * path,
               char         resolved[ PATH_MAX ] ) {
  return realpath( path, resolved ) ? 0 : -1;
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
  if( FD_UNLIKELY( iavf_path( path, IAVF_SYSFS_ROOT "/class/net/%s/device", config->net.interface, 0U ) ) ) {
    errno = ENAMETOOLONG;
    return -1;
  }
  char resolved[ PATH_MAX ];
  if( FD_UNLIKELY( iavf_realpath( path, resolved ) ) ) return -1;
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
  if( FD_UNLIKELY( iavf_path( path, IAVF_SYSFS_ROOT "/class/net/%s/device/virtfn%u",
                              config->net.interface, config->net.iavf.vf_index ) ) ) {
    errno = ENAMETOOLONG;
    return -1;
  }
  char resolved[ PATH_MAX ];
  if( FD_UNLIKELY( iavf_realpath( path, resolved ) ) ) return -1;
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
  if( FD_UNLIKELY( !fd_cstr_printf_check( path, sizeof(path), NULL,
                                          IAVF_SYSFS_ROOT "/bus/pci/devices/%s/driver", pci ) ) ) {
    errno = ENAMETOOLONG;
    return -1;
  }
  char resolved[ PATH_MAX ];
  if( FD_UNLIKELY( iavf_realpath( path, resolved ) ) ) return -1;
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
  if( FD_UNLIKELY( iavf_path( path, IAVF_SYSFS_ROOT "/class/net/%s/device/sriov_numvfs",
                              config->net.interface, 0U ) ) ) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return fd_file_util_read_uint( path, numvfs );
}

static int
iavf_set_numvfs( fd_config_t const * config,
                 uint                numvfs ) {
  char path[ PATH_MAX ];
  if( FD_UNLIKELY( iavf_path( path, IAVF_SYSFS_ROOT "/class/net/%s/device/sriov_numvfs",
                              config->net.interface, 0U ) ) ) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return fd_file_util_write_uint( path, numvfs );
}

static int
iavf_validate_vf( fd_config_t const * config,
                  char const *        vf_pci ) {
  char pf_pci[ 13 ];
  if( FD_UNLIKELY( iavf_pf_pci( config, pf_pci ) ) ) return -1;

  char path[ PATH_MAX ];
  char resolved[ PATH_MAX ];
  if( FD_UNLIKELY( !fd_cstr_printf_check( path, sizeof(path), NULL,
                                          IAVF_SYSFS_ROOT "/bus/pci/devices/%s/physfn", vf_pci ) ) ) {
    errno = ENAMETOOLONG;
    return -1;
  }
  if( FD_UNLIKELY( iavf_realpath( path, resolved ) || strcmp( iavf_basename( resolved ), pf_pci ) ) ) {
    errno = ENODEV;
    return -1;
  }

  if( FD_UNLIKELY( !fd_cstr_printf_check( path, sizeof(path), NULL,
                                          IAVF_SYSFS_ROOT "/bus/pci/devices/%s/iommu_group", vf_pci ) ) ) {
    errno = ENAMETOOLONG;
    return -1;
  }
  if( FD_UNLIKELY( iavf_realpath( path, resolved ) ) ) return -1;
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
    errno = EXDEV;
    return -1;
  }
  return 0;
}

static int
iavf_iommu_group( char const * vf_pci,
                  char         group[ 32 ] ) {
  char path[ PATH_MAX ];
  if( FD_UNLIKELY( !fd_cstr_printf_check( path, sizeof(path), NULL,
                                          IAVF_SYSFS_ROOT "/bus/pci/devices/%s/iommu_group", vf_pci ) ) ) {
    errno = ENAMETOOLONG;
    return -1;
  }
  char resolved[ PATH_MAX ];
  if( FD_UNLIKELY( iavf_realpath( path, resolved ) ) ) return -1;
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
    if( FD_UNLIKELY( !fd_cstr_printf_check( fd_dir_path, sizeof(fd_dir_path), NULL, "/proc/%s/fd", process->d_name ) ) ) {
      err = ENAMETOOLONG;
      break;
    }
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
      if( FD_UNLIKELY( !fd_cstr_printf_check( fd_path, sizeof(fd_path), NULL, "%s/%s", fd_dir_path, fd_entry->d_name ) ) ) {
        err = ENAMETOOLONG;
        break;
      }
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
iavf_rta_add( struct nlmsghdr * nlh,
              ulong             max_sz,
              ushort            type,
              void const *      data,
              ulong             data_sz ) {
  ulong off = NLMSG_ALIGN( nlh->nlmsg_len );
  ulong attr_sz = RTA_LENGTH( data_sz );
  if( FD_UNLIKELY( off+RTA_ALIGN( attr_sz )>max_sz ) ) {
    errno = ENOBUFS;
    return -1;
  }
  struct rtattr * rta = (struct rtattr *)((uchar *)nlh+off);
  rta->rta_type = type;
  rta->rta_len  = (ushort)attr_sz;
  if( data_sz ) fd_memcpy( RTA_DATA( rta ), data, data_sz );
  nlh->nlmsg_len = (uint)(off+RTA_ALIGN( attr_sz ));
  return 0;
}

static struct rtattr *
iavf_rta_nest_start( struct nlmsghdr * nlh,
                     ulong             max_sz,
                     ushort            type ) {
  ulong off = NLMSG_ALIGN( nlh->nlmsg_len );
  if( FD_UNLIKELY( iavf_rta_add( nlh, max_sz, type, NULL, 0UL ) ) ) return NULL;
  return (struct rtattr *)((uchar *)nlh+off);
}

static void
iavf_rta_nest_end( struct nlmsghdr * nlh,
                   struct rtattr *  nest ) {
  nest->rta_len = (ushort)((uchar *)nlh+nlh->nlmsg_len-(uchar *)nest);
}

static struct rtattr const *
iavf_rta_next( struct rtattr const * rta,
               int *                 remaining ) {
  int const aligned_sz = (int)RTA_ALIGN( rta->rta_len );
  *remaining -= aligned_sz;
  return (struct rtattr const *)((uchar const *)rta+aligned_sz);
}

static int
iavf_netlink_open( void ) {
  int fd = socket( AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE );
  if( FD_UNLIKELY( fd<0 ) ) return -1;
  union {
    struct sockaddr    base;
    struct sockaddr_nl netlink;
  } addr = { .netlink = { .nl_family = AF_NETLINK } };
  if( FD_UNLIKELY( bind( fd, &addr.base, sizeof(addr.netlink) ) ) ) {
    int err = errno;
    close( fd );
    errno = err;
    return -1;
  }
  return fd;
}

static int
iavf_netlink_send( int                fd,
                   struct nlmsghdr * nlh ) {
  struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
  struct iovec iov = { .iov_base = nlh, .iov_len = nlh->nlmsg_len };
  struct msghdr msg = {
    .msg_name    = &addr,
    .msg_namelen = sizeof(addr),
    .msg_iov     = &iov,
    .msg_iovlen  = 1UL,
  };
  long sent = sendmsg( fd, &msg, 0 );
  if( FD_UNLIKELY( sent<0 ) ) return -1;
  if( FD_UNLIKELY( (ulong)sent!=nlh->nlmsg_len ) ) {
    errno = EIO;
    return -1;
  }
  return 0;
}

static int
iavf_netlink_ack( int  fd,
                  uint seq ) {
  uchar buf[ 4096 ];
  for(;;) {
    long recv_sz = recv( fd, buf, sizeof(buf), 0 );
    if( FD_UNLIKELY( recv_sz<0 ) ) return -1;
    if( FD_UNLIKELY( !recv_sz ) ) {
      errno = EIO;
      return -1;
    }
    for( struct nlmsghdr * nlh=(struct nlmsghdr *)buf; NLMSG_OK( nlh, recv_sz ); nlh=NLMSG_NEXT( nlh, recv_sz ) ) {
      if( nlh->nlmsg_seq!=seq ) continue;
      if( nlh->nlmsg_type!=NLMSG_ERROR ) continue;
      if( FD_UNLIKELY( nlh->nlmsg_len<NLMSG_LENGTH( sizeof(struct nlmsgerr) ) ) ) {
        errno = EBADMSG;
        return -1;
      }
      int err = ((struct nlmsgerr *)NLMSG_DATA( nlh ))->error;
      if( FD_UNLIKELY( err ) ) {
        errno = -err;
        return -1;
      }
      return 0;
    }
  }
}

static int
iavf_policy_set( fd_config_t const * config,
                 uchar const         mac[ 6 ] ) {
  uint if_idx = if_nametoindex( config->net.interface );
  if( FD_UNLIKELY( !if_idx ) ) {
    errno = ENODEV;
    return -1;
  }

  iavf_netlink_req_t req = {
    .nlh = {
      .nlmsg_len   = NLMSG_LENGTH( sizeof(struct ifinfomsg) ),
      .nlmsg_type  = RTM_SETLINK,
      .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
      .nlmsg_seq   = 1U,
    },
    .ifm = {
      .ifi_family = AF_UNSPEC,
      .ifi_index  = (int)if_idx,
    },
  };

  struct rtattr * list = iavf_rta_nest_start( &req.nlh, sizeof(req), IFLA_VFINFO_LIST );
  struct rtattr * info = iavf_rta_nest_start( &req.nlh, sizeof(req), IFLA_VF_INFO );
  if( FD_UNLIKELY( !list || !info ) ) return -1;

  struct ifla_vf_mac vf_mac = { .vf = config->net.iavf.vf_index };
  fd_memcpy( vf_mac.mac, mac, 6UL );
  struct ifla_vf_spoofchk spoofchk = { .vf = config->net.iavf.vf_index, .setting = 0U };
  struct ifla_vf_trust trust = { .vf = config->net.iavf.vf_index, .setting = 0U };
  struct ifla_vf_link_state link_state = { .vf = config->net.iavf.vf_index, .link_state = IFLA_VF_LINK_STATE_AUTO };

  if( FD_UNLIKELY( iavf_rta_add( &req.nlh, sizeof(req), IFLA_VF_MAC,        &vf_mac,     sizeof(vf_mac)     ) ||
                   iavf_rta_add( &req.nlh, sizeof(req), IFLA_VF_SPOOFCHK,   &spoofchk,   sizeof(spoofchk)   ) ||
                   iavf_rta_add( &req.nlh, sizeof(req), IFLA_VF_TRUST,      &trust,      sizeof(trust)      ) ||
                   iavf_rta_add( &req.nlh, sizeof(req), IFLA_VF_LINK_STATE, &link_state, sizeof(link_state) ) ) ) return -1;
  iavf_rta_nest_end( &req.nlh, info );
  iavf_rta_nest_end( &req.nlh, list );

  int fd = iavf_netlink_open();
  if( FD_UNLIKELY( fd<0 ) ) return -1;
  if( FD_UNLIKELY( iavf_netlink_send( fd, &req.nlh ) || iavf_netlink_ack( fd, req.nlh.nlmsg_seq ) ) ) {
    int err = errno;
    close( fd );
    errno = err;
    return -1;
  }
  if( FD_UNLIKELY( close( fd ) ) ) return -1;
  return 0;
}

static void
iavf_policy_parse_info( struct rtattr const * info,
                        uint                  vf_idx,
                        iavf_vf_policy_t *    policy ) {
  int len = (int)info->rta_len-(int)RTA_LENGTH( 0 );
  for( struct rtattr const * rta=(struct rtattr const *)RTA_DATA( info ); RTA_OK( rta, len ); rta=iavf_rta_next( rta, &len ) ) {
    ushort type = (ushort)(rta->rta_type & NLA_TYPE_MASK);
    if( type==IFLA_VF_MAC && RTA_PAYLOAD( rta )>=sizeof(struct ifla_vf_mac) ) {
      struct ifla_vf_mac const * value = (struct ifla_vf_mac const *)RTA_DATA( rta );
      if( value->vf==vf_idx ) {
        fd_memcpy( policy->mac, value->mac, 6UL );
        policy->mac_valid = 1;
      }
    } else if( type==IFLA_VF_SPOOFCHK && RTA_PAYLOAD( rta )>=sizeof(struct ifla_vf_spoofchk) ) {
      struct ifla_vf_spoofchk const * value = (struct ifla_vf_spoofchk const *)RTA_DATA( rta );
      if( value->vf==vf_idx ) {
        policy->spoofchk = (int)value->setting;
        policy->spoofchk_valid = 1;
      }
    } else if( type==IFLA_VF_TRUST && RTA_PAYLOAD( rta )>=sizeof(struct ifla_vf_trust) ) {
      struct ifla_vf_trust const * value = (struct ifla_vf_trust const *)RTA_DATA( rta );
      if( value->vf==vf_idx ) {
        policy->trust = (int)value->setting;
        policy->trust_valid = 1;
      }
    } else if( type==IFLA_VF_LINK_STATE && RTA_PAYLOAD( rta )>=sizeof(struct ifla_vf_link_state) ) {
      struct ifla_vf_link_state const * value = (struct ifla_vf_link_state const *)RTA_DATA( rta );
      if( value->vf==vf_idx ) {
        policy->link_state = value->link_state;
        policy->link_state_valid = 1;
      }
    }
  }
}

static int
iavf_policy_parse_link( struct nlmsghdr const * nlh,
                        uint                    vf_idx,
                        iavf_vf_policy_t *      policy ) {
  if( FD_UNLIKELY( nlh->nlmsg_len<NLMSG_LENGTH( sizeof(struct ifinfomsg) ) ) ) {
    errno = EBADMSG;
    return -1;
  }
  struct ifinfomsg const * ifm = (struct ifinfomsg const *)NLMSG_DATA( nlh );
  int len = (int)(nlh->nlmsg_len-NLMSG_LENGTH( sizeof(*ifm) ));
  for( struct rtattr const * rta=IFLA_RTA( ifm ); RTA_OK( rta, len ); rta=iavf_rta_next( rta, &len ) ) {
    if( (rta->rta_type & NLA_TYPE_MASK)!=IFLA_VFINFO_LIST ) continue;
    int list_len = (int)rta->rta_len-(int)RTA_LENGTH( 0 );
    for( struct rtattr const * entry=(struct rtattr const *)RTA_DATA( rta ); RTA_OK( entry, list_len ); entry=iavf_rta_next( entry, &list_len ) ) {
      if( (entry->rta_type & NLA_TYPE_MASK)==IFLA_VF_INFO ) iavf_policy_parse_info( entry, vf_idx, policy );
    }
  }
  return 0;
}

static int
iavf_policy_get( fd_config_t const * config,
                 iavf_vf_policy_t * policy ) {
  uint if_idx = if_nametoindex( config->net.interface );
  if( FD_UNLIKELY( !if_idx ) ) {
    errno = ENODEV;
    return -1;
  }

  iavf_netlink_req_t req = {
    .nlh = {
      .nlmsg_len   = NLMSG_LENGTH( sizeof(struct ifinfomsg) ),
      .nlmsg_type  = RTM_GETLINK,
      .nlmsg_flags = NLM_F_REQUEST,
      .nlmsg_seq   = 2U,
    },
    .ifm = {
      .ifi_family = AF_UNSPEC,
      .ifi_index  = (int)if_idx,
    },
  };
  uint ext_mask = RTEXT_FILTER_VF;
  if( FD_UNLIKELY( iavf_rta_add( &req.nlh, sizeof(req), IFLA_EXT_MASK, &ext_mask, sizeof(ext_mask) ) ) ) return -1;

  int fd = iavf_netlink_open();
  if( FD_UNLIKELY( fd<0 ) ) return -1;
  if( FD_UNLIKELY( iavf_netlink_send( fd, &req.nlh ) ) ) {
    int err = errno;
    close( fd );
    errno = err;
    return -1;
  }

  uchar buf[ 16384 ];
  long recv_sz = recv( fd, buf, sizeof(buf), 0 );
  int err = errno;
  if( FD_UNLIKELY( close( fd ) && recv_sz>=0L ) ) {
    recv_sz = -1L;
    err = errno;
  }
  if( FD_UNLIKELY( recv_sz<0L ) ) {
    errno = err;
    return -1;
  }

  fd_memset( policy, 0, sizeof(*policy) );
  for( struct nlmsghdr * nlh=(struct nlmsghdr *)buf; NLMSG_OK( nlh, recv_sz ); nlh=NLMSG_NEXT( nlh, recv_sz ) ) {
    if( nlh->nlmsg_seq!=req.nlh.nlmsg_seq ) continue;
    if( nlh->nlmsg_type==NLMSG_ERROR ) {
      if( FD_UNLIKELY( nlh->nlmsg_len<NLMSG_LENGTH( sizeof(struct nlmsgerr) ) ) ) {
        errno = EBADMSG;
        return -1;
      }
      int nl_err = ((struct nlmsgerr *)NLMSG_DATA( nlh ))->error;
      errno = nl_err ? -nl_err : ENODATA;
      return -1;
    }
    if( nlh->nlmsg_type==RTM_NEWLINK ) return iavf_policy_parse_link( nlh, config->net.iavf.vf_index, policy );
  }
  errno = ENODATA;
  return -1;
}

static int
iavf_marker_path( fd_config_t const * config,
                  char                path[ PATH_MAX ] ) {
  if( FD_UNLIKELY( !fd_cstr_printf_check( path, PATH_MAX, NULL, IAVF_RUN_ROOT "/firedancer-iavf-%s-%u.owned",
                                          config->net.interface, config->net.iavf.vf_index ) ) ) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return 0;
}

static int
iavf_marker_read( fd_config_t const * config,
                  char                vf_pci[ 13 ] ) {
  char path[ PATH_MAX ];
  if( FD_UNLIKELY( iavf_marker_path( config, path ) ) ) return -1;
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
  if( FD_UNLIKELY( iavf_marker_path( config, path ) ) ) return -1;
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
  if( FD_UNLIKELY( !fd_cstr_printf_check( path, sizeof(path), NULL,
                                          IAVF_SYSFS_ROOT "/bus/pci/devices/%s/driver/unbind", vf_pci ) ) ) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return iavf_write( path, vf_pci );
}

static int
iavf_driver_override( char const * vf_pci,
                      char const * driver ) {
  char path[ PATH_MAX ];
  if( FD_UNLIKELY( !fd_cstr_printf_check( path, sizeof(path), NULL,
                                          IAVF_SYSFS_ROOT "/bus/pci/devices/%s/driver_override", vf_pci ) ) ) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return iavf_write( path, driver );
}

static int
iavf_probe( char const * vf_pci ) {
  return iavf_write( IAVF_SYSFS_ROOT "/bus/pci/drivers_probe", vf_pci );
}

static void
iavf_bind_vfio( char const * vf_pci ) {
  struct stat st;
  if( FD_UNLIKELY( stat( IAVF_SYSFS_ROOT "/bus/pci/drivers/vfio-pci", &st ) ) ) {
    FD_LOG_ERR(( "vfio-pci is not loaded (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  char driver[ 32 ];
  int has_driver = !iavf_driver( vf_pci, driver );
  if( has_driver && !strcmp( driver, "vfio-pci" ) ) return;
  if( FD_UNLIKELY( iavf_driver_override( vf_pci, "vfio-pci" ) ) ) {
    FD_LOG_ERR(( "failed to set driver_override for IAVF VF %s (%i-%s)", vf_pci, errno, fd_io_strerror( errno ) ));
  }
  if( has_driver && FD_UNLIKELY( iavf_unbind( vf_pci ) ) ) {
    FD_LOG_ERR(( "failed to unbind IAVF VF %s from %s (%i-%s)", vf_pci, driver, errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( iavf_probe( vf_pci ) ) ) {
    FD_LOG_ERR(( "failed to probe IAVF VF %s for vfio-pci (%i-%s)", vf_pci, errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( iavf_driver( vf_pci, driver ) || strcmp( driver, "vfio-pci" ) ) ) {
    FD_LOG_ERR(( "IAVF VF %s did not bind to vfio-pci", vf_pci ));
  }
}

static void
init( fd_config_t const * config ) {
  if( FD_UNLIKELY( config->net.iavf.vf_index ) ) {
    FD_LOG_ERR(( "IAVF currently supports only VF index zero" ));
  }

  uchar mac[ 6 ];
  if( FD_UNLIKELY( iavf_pf_mac( config, mac ) ) ) {
    FD_LOG_ERR(( "failed to read MAC address for IAVF Physical Function `%s` (%i-%s)",
                 config->net.interface, errno, fd_io_strerror( errno ) ));
  }

  char pf_driver[ 32 ];
  if( FD_UNLIKELY( iavf_pf_driver( config, pf_driver ) ) ) {
    FD_LOG_ERR(( "failed to find PCI driver for IAVF Physical Function `%s` (%i-%s)",
                 config->net.interface, errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( strcmp( pf_driver, "ice" ) && strcmp( pf_driver, "i40e" ) ) ) {
    FD_LOG_ERR(( "IAVF Physical Function `%s` uses unsupported driver `%s`, expected ice or i40e",
                 config->net.interface, pf_driver ));
  }

  uint totalvfs;
  char path[ PATH_MAX ];
  if( FD_UNLIKELY( iavf_path( path, IAVF_SYSFS_ROOT "/class/net/%s/device/sriov_totalvfs",
                              config->net.interface, 0U ) ||
                   fd_file_util_read_uint( path, &totalvfs ) ) ) {
    FD_LOG_ERR(( "failed to read SR-IOV capacity for `%s` (%i-%s)",
                 config->net.interface, errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( !totalvfs ) ) FD_LOG_ERR(( "Physical Function `%s` does not support SR-IOV", config->net.interface ));

  uint numvfs;
  if( FD_UNLIKELY( iavf_numvfs( config, &numvfs ) ) ) {
    FD_LOG_ERR(( "failed to read SR-IOV VF count for `%s` (%i-%s)",
                 config->net.interface, errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( numvfs ) ) {
    FD_LOG_ERR(( "Physical Function `%s` already has %u SR-IOV VF%s. Firedancer did not modify them.\n"
                 "Remove all VFs from this PF with:\n"
                 "  echo 0 | sudo tee /sys/class/net/%s/device/sriov_numvfs\n"
                 "WARNING: this deletes every VF on `%s` and may disrupt other applications.",
                 config->net.interface, numvfs, numvfs==1U ? "" : "s",
                 config->net.interface, config->net.interface ));
  }

  if( FD_UNLIKELY( iavf_set_numvfs( config, 1U ) ) ) {
    FD_LOG_ERR(( "failed to create VF 0 on `%s` (%i-%s)",
                 config->net.interface, errno, fd_io_strerror( errno ) ));
  }

  char vf_pci[ 13 ];
  if( FD_UNLIKELY( iavf_vf_pci( config, vf_pci ) || iavf_validate_vf( config, vf_pci ) ) ) {
    FD_LOG_ERR(( "VF 0 on `%s` is not an isolated SR-IOV Virtual Function (%i-%s)",
                 config->net.interface, errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( iavf_marker_write( config, vf_pci ) ) ) {
    int err = errno;
    if( FD_UNLIKELY( iavf_set_numvfs( config, 0U ) ) ) {
      FD_LOG_ERR(( "failed to record ownership of newly created VF %s and rollback failed (%i-%s)",
                   vf_pci, errno, fd_io_strerror( errno ) ));
    }
    FD_LOG_ERR(( "failed to record ownership of newly created VF %s (%i-%s)", vf_pci, err, fd_io_strerror( err ) ));
  }

  if( FD_UNLIKELY( iavf_policy_set( config, mac ) ) ) {
    FD_LOG_ERR(( "failed to set MAC and anti-spoofing policy for VF %u on `%s` (%i-%s)",
                 config->net.iavf.vf_index, config->net.interface, errno, fd_io_strerror( errno ) ));
  }
  iavf_bind_vfio( vf_pci );

  fd_iavf_hw_pci_info_t pci_info[ 1 ];
  if( FD_UNLIKELY( fd_iavf_hw_pci_probe( pci_info, vf_pci ) ) ) {
    FD_LOG_ERR(( "VF %s is not supported by the IAVF provider (%i-%s)", vf_pci, errno, fd_io_strerror( errno ) ));
  }
}

static int
fini( fd_config_t const * config,
      int                 pre_init FD_PARAM_UNUSED ) {
  uint numvfs;
  if( FD_UNLIKELY( iavf_numvfs( config, &numvfs ) ) ) {
    if( errno==ENOENT ) return 0;
    FD_LOG_ERR(( "failed to read SR-IOV VF count for `%s` (%i-%s)",
                 config->net.interface, errno, fd_io_strerror( errno ) ));
  }
  if( !numvfs ) return 0;
  if( FD_UNLIKELY( numvfs>1U ) ) {
    FD_LOG_ERR(( "refusing to finish IAVF configuration because `%s` has %u VFs",
                 config->net.interface, numvfs ));
  }

  char vf_pci[ 13 ];
  if( FD_UNLIKELY( iavf_vf_pci( config, vf_pci ) || iavf_validate_vf( config, vf_pci ) ) ) {
    FD_LOG_ERR(( "cannot safely identify VF %u on `%s` (%i-%s)",
                 config->net.iavf.vf_index, config->net.interface, errno, fd_io_strerror( errno ) ));
  }

  char owned_pci[ 13 ];
  if( FD_UNLIKELY( iavf_marker_read( config, owned_pci ) ) ) {
    if( errno==ENOENT ) return 0;
    FD_LOG_ERR(( "failed to read IAVF ownership marker (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( strcmp( owned_pci, vf_pci ) ) ) {
    FD_LOG_ERR(( "IAVF ownership marker names VF %s but the configured VF is %s", owned_pci, vf_pci ));
  }

  uint user_pid;
  int in_use = iavf_vfio_user( vf_pci, &user_pid );
  if( FD_UNLIKELY( in_use<0 ) ) {
    FD_LOG_ERR(( "failed to check whether IAVF VF %s is in use (%i-%s)", vf_pci, errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( in_use ) ) {
    FD_LOG_ERR(( "refusing to rebind IAVF VF %s while process %u has its VFIO IOMMU group open", vf_pci, user_pid ));
  }

  char driver[ 32 ];
  if( !iavf_driver( vf_pci, driver ) && FD_UNLIKELY( iavf_unbind( vf_pci ) ) ) {
    FD_LOG_ERR(( "failed to unbind owned IAVF VF %s from %s (%i-%s)", vf_pci, driver, errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( iavf_set_numvfs( config, 0U ) ) ) {
    FD_LOG_ERR(( "failed to remove owned VF %s (%i-%s)", vf_pci, errno, fd_io_strerror( errno ) ));
  }
  char marker[ PATH_MAX ];
  FD_TEST( !iavf_marker_path( config, marker ) );
  if( FD_UNLIKELY( unlink( marker ) && errno!=ENOENT ) ) {
    FD_LOG_ERR(( "failed to remove IAVF ownership marker `%s` (%i-%s)", marker, errno, fd_io_strerror( errno ) ));
  }
  return 1;
}

static configure_result_t
check( fd_config_t const * config,
       int                 check_type FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( config->net.iavf.vf_index ) ) {
    PARTIALLY_CONFIGURED( "only VF index zero is supported" );
  }

  uchar expected_mac[ 6 ];
  if( FD_UNLIKELY( iavf_pf_mac( config, expected_mac ) ) ) {
    NOT_CONFIGURED( "cannot read the MAC address for Physical Function `%s`", config->net.interface );
  }

  char pf_driver[ 32 ];
  if( FD_UNLIKELY( iavf_pf_driver( config, pf_driver ) ) ) {
    NOT_CONFIGURED( "Physical Function interface `%s` is unavailable", config->net.interface );
  }
  if( FD_UNLIKELY( strcmp( pf_driver, "ice" ) && strcmp( pf_driver, "i40e" ) ) ) {
    PARTIALLY_CONFIGURED( "Physical Function `%s` uses unsupported driver `%s`",
                          config->net.interface, pf_driver );
  }

  uint numvfs;
  if( FD_UNLIKELY( iavf_numvfs( config, &numvfs ) ) ) {
    NOT_CONFIGURED( "cannot read the SR-IOV VF count for `%s`", config->net.interface );
  }
  if( !numvfs ) NOT_CONFIGURED( "VF 0 does not exist on `%s`", config->net.interface );

  char owned_pci[ 13 ];
  int marker_status = iavf_marker_read( config, owned_pci );
  if( FD_UNLIKELY( marker_status ) ) {
    if( errno!=ENOENT ) PARTIALLY_CONFIGURED( "cannot read the ownership marker for VF 0 on `%s`", config->net.interface );
    NOT_CONFIGURED( "Physical Function `%s` has %u existing VF%s not owned by Firedancer. Remove all VFs with `echo 0 | sudo tee /sys/class/net/%s/device/sriov_numvfs`",
                    config->net.interface, numvfs, numvfs==1U ? "" : "s", config->net.interface );
  }
  if( FD_UNLIKELY( numvfs>1U ) ) {
    PARTIALLY_CONFIGURED( "Physical Function `%s` has %u VFs, only a single VF is supported",
                          config->net.interface, numvfs );
  }

  char vf_pci[ 13 ];
  if( FD_UNLIKELY( iavf_vf_pci( config, vf_pci ) || iavf_validate_vf( config, vf_pci ) ) ) {
    PARTIALLY_CONFIGURED( "VF 0 on `%s` is not isolated in its IOMMU group", config->net.interface );
  }
  char driver[ 32 ];
  int has_driver = !iavf_driver( vf_pci, driver );
  if( FD_UNLIKELY( strcmp( owned_pci, vf_pci ) ) ) {
    PARTIALLY_CONFIGURED( "the ownership marker names VF %s instead of %s", owned_pci, vf_pci );
  }
  if( FD_UNLIKELY( !has_driver || strcmp( driver, "vfio-pci" ) ) ) {
    PARTIALLY_CONFIGURED( "owned VF %s is not bound to vfio-pci", vf_pci );
  }

  iavf_vf_policy_t policy[ 1 ];
  if( FD_UNLIKELY( iavf_policy_get( config, policy ) ) ) {
    PARTIALLY_CONFIGURED( "cannot read VF policy for `%s`", config->net.interface );
  }
  if( FD_UNLIKELY( !policy->mac_valid ) ) PARTIALLY_CONFIGURED( "the Physical Function did not report a MAC address for VF %s", vf_pci );
  if( FD_UNLIKELY( memcmp( policy->mac, expected_mac, 6UL ) ) ) {
    PARTIALLY_CONFIGURED( "VF %s has MAC address %02x:%02x:%02x:%02x:%02x:%02x, "
                          "expected Physical Function MAC %02x:%02x:%02x:%02x:%02x:%02x",
                          vf_pci, (uint)policy->mac[0], (uint)policy->mac[1], (uint)policy->mac[2],
                          (uint)policy->mac[3], (uint)policy->mac[4], (uint)policy->mac[5],
                          (uint)expected_mac[0], (uint)expected_mac[1], (uint)expected_mac[2],
                          (uint)expected_mac[3], (uint)expected_mac[4], (uint)expected_mac[5] );
  }
  if( FD_UNLIKELY( !policy->spoofchk_valid || policy->spoofchk ) ) {
    PARTIALLY_CONFIGURED( "VF %s has spoof checking enabled", vf_pci );
  }
  if( FD_UNLIKELY( !policy->trust_valid || policy->trust ) ) {
    PARTIALLY_CONFIGURED( "VF %s is trusted, expected trust disabled", vf_pci );
  }
  if( FD_UNLIKELY( !policy->link_state_valid || policy->link_state!=IFLA_VF_LINK_STATE_AUTO ) ) {
    PARTIALLY_CONFIGURED( "VF %s link state is not automatic", vf_pci );
  }

  fd_iavf_hw_pci_info_t pci_info[ 1 ];
  if( FD_UNLIKELY( fd_iavf_hw_pci_probe( pci_info, vf_pci ) ) ) {
    PARTIALLY_CONFIGURED( "VF %s is not supported by the IAVF provider", vf_pci );
  }
  CONFIGURE_OK();
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

#include "fd_netdev_netlink.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"
#include "fd_netdev_tbl.h"
#include <linux/if_link.h>

#if !defined(__linux__)
#error "fd_fib4_netlink.c requires a Linux system with kernel headers"
#endif

#include <errno.h>
#include <linux/if.h> /* IFNAMSIZ */
#include <linux/if_arp.h> /* ARPHRD_NETROM */
#include <linux/rtnetlink.h> /* RTM_{...}, NLM_{...} */
#include <linux/if_tunnel.h>

static fd_netdev_t *
fd_netdev_init( fd_netdev_t * netdev ) {
  *netdev = (fd_netdev_t) {
    .mtu           = 1500,
    .if_idx        = 0,
    .slave_tbl_idx = -1,
    .master_idx    = -1,
    .oper_status   = FD_OPER_STATUS_INVALID,
    .dev_type      = ARPHRD_NONE,
    .gre_dst_ip    = 0,
    .gre_src_ip    = 0
  };
  return netdev;
}

FD_FN_CONST static uchar
ifoper_to_oper_status( uint if_oper ) {
  /* Linux uses different enum values than RFC 2863 */
  switch( if_oper ) {
	case IF_OPER_UNKNOWN:
    return FD_OPER_STATUS_UNKNOWN;
	case IF_OPER_NOTPRESENT:
    return FD_OPER_STATUS_NOT_PRESENT;
	case IF_OPER_DOWN:
    return FD_OPER_STATUS_DOWN;
	case IF_OPER_LOWERLAYERDOWN:
    return FD_OPER_STATUS_LOWER_LAYER_DOWN;
	case IF_OPER_TESTING:
    return FD_OPER_STATUS_TESTING;
	case IF_OPER_DORMANT:
    return FD_OPER_STATUS_DORMANT;
	case IF_OPER_UP:
    return FD_OPER_STATUS_UP;
  default:
    return FD_OPER_STATUS_INVALID;
  }
}

int
fd_netdev_netlink_load_table( fd_netdev_tbl_join_t * tbl,
                              fd_netlink_t *         netlink ) {
  fd_netdev_tbl_reset( tbl );

  uint seq = netlink->seq++;

  struct {
    struct nlmsghdr  nlh;
    struct ifinfomsg ifi;
  } request;
  request.nlh = (struct nlmsghdr) {
    .nlmsg_type  = RTM_GETLINK,
    .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
    .nlmsg_len   = sizeof(request),
    .nlmsg_seq   = seq
  };
  request.ifi = (struct ifinfomsg) {
    .ifi_family = AF_PACKET,
    .ifi_type   = ARPHRD_NETROM,
  };

  long send_res = sendto( netlink->fd, &request, sizeof(request), 0, NULL, 0 );
  if( FD_UNLIKELY( send_res<0 ) ) {
    FD_LOG_WARNING(( "netlink send(%d,RTM_GETLINK,NLM_F_REQUEST|NLM_F_DUMP) failed (%i-%s)", netlink->fd, errno, fd_io_strerror( errno ) ));
    return errno;
  }
  if( FD_UNLIKELY( send_res!=sizeof(request) ) ) {
    FD_LOG_WARNING(( "netlink send(%d,RTM_GETLINK,NLM_F_REQUEST|NLM_F_DUMP) failed (short write)", netlink->fd ));
    return EPIPE;
  }

  int err = 0;

  uchar buf[ 4096 ];
  fd_netlink_iter_t iter[1];
  for( fd_netlink_iter_init( iter, netlink, buf, sizeof(buf) );
       !fd_netlink_iter_done( iter );
       fd_netlink_iter_next( iter, netlink ) ) {
    struct nlmsghdr const * nlh = fd_netlink_iter_msg( iter );
    if( FD_UNLIKELY( nlh->nlmsg_type==NLMSG_ERROR ) ) {
      struct nlmsgerr * err = NLMSG_DATA( nlh );
      int nl_err = -err->error;
      FD_LOG_WARNING(( "netlink RTM_GETLINK,NLM_F_REQUEST|NLM_F_DUMP failed (%d-%s)", nl_err, fd_io_strerror( nl_err ) ));
      return nl_err;
    }
    if( FD_UNLIKELY( nlh->nlmsg_type!=RTM_NEWLINK ) ) {
      FD_LOG_DEBUG(( "unexpected nlmsg_type %u", nlh->nlmsg_type ));
      continue;
    }
    struct ifinfomsg const * ifi = NLMSG_DATA( nlh );

    if( FD_UNLIKELY( ifi->ifi_index<0 ) ) {
      FD_LOG_WARNING(( "Error reading interface table: interface %d has invalid index", ifi->ifi_index ));
      err = EPROTO;
      break;
    }

    ushort ifi_type = ifi->ifi_type;
    if( ifi_type!=ARPHRD_ETHER && ifi_type!=ARPHRD_LOOPBACK && ifi_type!=ARPHRD_IPGRE ) continue;

    struct ifinfomsg * msg    = NLMSG_DATA( nlh );
    struct rtattr *    rat    = (void *)( (ulong)msg + NLMSG_ALIGN( sizeof(struct ifinfomsg) ) );
    long               rat_sz = (long)NLMSG_PAYLOAD( nlh, sizeof(struct ifinfomsg) );

    fd_netdev_t netdev[1];
    fd_netdev_init( netdev );

    for( ; RTA_OK( rat, rat_sz ); rat=RTA_NEXT( rat, rat_sz ) ) {
      void * rta    = RTA_DATA( rat );
      ulong  rta_sz = RTA_PAYLOAD( rat );

      switch( rat->rta_type ) {

      case IFLA_IFNAME:
        /* Includes trailing zero */
        if( FD_UNLIKELY( rta_sz==0 || rta_sz>IFNAMSIZ ) ) {
          FD_LOG_WARNING(( "Error reading interface table: IFLA_IFNAME has unsupported size %lu", rta_sz ));
          err = EPROTO;
          goto fail;
        }
        memcpy( netdev->name, rta, rta_sz );
        netdev->name[ rta_sz-1 ] = '\0';
        break;

      case IFLA_ADDRESS:
        if( FD_UNLIKELY( rta_sz==6UL ) ) {
          memcpy( netdev->mac_addr, rta, 6 );
        }
        break;

      case IFLA_OPERSTATE:
        if( FD_UNLIKELY( rta_sz!=1UL ) ) {
          FD_LOG_WARNING(( "Error reading interface table: IFLA_OPERSTATE has unexpected size %lu", rta_sz ));
          err = EPROTO;
          goto fail;
        }
        netdev->oper_status = (uchar)ifoper_to_oper_status( FD_LOAD( uchar, rta ) );
        break;

      case IFLA_MTU:
        if( FD_UNLIKELY( rta_sz!=4UL ) ) {
          FD_LOG_WARNING(( "Error reading interface table: IFLA_MTU has unexpected size %lu", rta_sz ));
          err = EPROTO;
          goto fail;
        }
        netdev->mtu = (ushort)fd_uint_min( FD_LOAD( uint, rta ), USHORT_MAX );
        break;

      case IFLA_MASTER: {
        if( FD_UNLIKELY( rta_sz!=4UL ) ) {
          FD_LOG_WARNING(( "Error reading interface table: IFLA_MASTER has unexpected size %lu", rta_sz ));
          err = EPROTO;
          goto fail;
        }
        int master_idx = FD_LOAD( int, rta );
        if( FD_UNLIKELY( master_idx<0 || master_idx>=tbl->hdr->dev_max ) ) {
          FD_LOG_WARNING(( "Error reading interface table: IFLA_MASTER has invalid index %d", master_idx ));
          err = EPROTO;
          goto fail;
        }
        netdev->master_idx = master_idx;
        break;
      } /* IFLA_MASTER */

      case IFLA_LINKINFO : {
        if( ifi->ifi_type!=ARPHRD_IPGRE ) continue;

        struct rtattr * info_rat    = rta;
        long            info_rat_sz = (long)rta_sz;

        for( ; RTA_OK( info_rat, info_rat_sz ); info_rat = RTA_NEXT( info_rat, info_rat_sz ) ) {
          void * info_rta    = RTA_DATA( info_rat );
          ulong  info_rta_sz = RTA_PAYLOAD( info_rat );

          switch( info_rat->rta_type ) {
          case IFLA_INFO_DATA: {
            struct rtattr * gre_rat    = (struct rtattr *)info_rta;
            long            gre_rat_sz = (long)info_rta_sz;

            for( ; RTA_OK( gre_rat, gre_rat_sz ); gre_rat = RTA_NEXT( gre_rat, gre_rat_sz ) ) {
              void * gre_rta    = RTA_DATA( gre_rat );
              uint gre_dst_ip;
              uint gre_src_ip;

              switch( gre_rat->rta_type ) {
              case IFLA_GRE_REMOTE: {
                gre_dst_ip = FD_LOAD( uint, gre_rta );
                if( gre_dst_ip != 0 ) netdev->gre_dst_ip = gre_dst_ip;
                break;
              } /* IFLA_GRE_REMOTE */
              case IFLA_GRE_LOCAL: {
                gre_src_ip = FD_LOAD( uint, gre_rta );
                if( gre_src_ip != 0 ) netdev->gre_src_ip = gre_src_ip;
                break;
              } /* IFLA_GRE_LOCAL */
              }
            }
            break;
          } /* IFLA_INFO_DATA */
          } /* info_rat->rta_type */
        } /* for each info_rta */
      } /* IFLA_LINKINFO */

      } /* switch( rat->rta_type ) */
    } /* for each RTA */

    if( ifi->ifi_type==ARPHRD_LOOPBACK ) {
      netdev->oper_status = FD_OPER_STATUS_UP;
    }

    netdev->dev_type = ifi_type;
    netdev->if_idx   = (uint)ifi->ifi_index;
    fd_netdev_t * dst = fd_netdev_tbl_query( tbl, (uint)ifi->ifi_index );
    if( FD_UNLIKELY( !dst ) ) {
      if( FD_UNLIKELY( tbl->hdr->dev_cnt >= tbl->hdr->dev_max ) ) {
        FD_LOG_WARNING(( "Error reading interface table: tracked interface limit %u reached (dropping ifindex %i)",
                         tbl->hdr->dev_max, ifi->ifi_index ));
        err = ENOSPC;
        break;
      }
      dst = &tbl->dev_tbl[ tbl->hdr->dev_cnt ]; // alloc new entry
      tbl->hdr->dev_cnt = (ushort)(tbl->hdr->dev_cnt + 1);
    }
    *dst = *netdev;
  }

  /* Walk the table again to index the bond master => slave mapping */

  for( ulong j=0UL; j<(tbl->hdr->dev_cnt); j++ ) {
    /* Only consider UP slaves */
    if( tbl->dev_tbl[ j ].oper_status!=FD_OPER_STATUS_UP ) continue;

    /* Find master */
    int master_idx = tbl->dev_tbl[ j ].master_idx;
    if( master_idx<0 ) continue;
    fd_netdev_t * master = fd_netdev_tbl_query( tbl, (uint)master_idx );
    if( FD_UNLIKELY( !master ) ) {
      FD_LOG_WARNING(( "Error reading interface table: Bond device references missing master %d", master_idx ));
      continue;
    }

    /* Allocate a new bond slave table if needed */
    if( master->slave_tbl_idx<0 ) {
      if( FD_UNLIKELY( tbl->hdr->bond_cnt>=tbl->hdr->bond_max ) ) {
        FD_LOG_WARNING(( "Error reading interface table: Found %u bond devices but max is %u", tbl->hdr->bond_cnt, tbl->hdr->bond_max ));
        continue;
      }

      master->slave_tbl_idx = (short)tbl->hdr->bond_cnt;
      tbl->hdr->bond_cnt = (ushort)( tbl->hdr->bond_cnt+1U );
      /* Assume that this table is empty */
    }

    fd_netdev_bond_t * bond = &tbl->bond_tbl[ master->slave_tbl_idx ];
    if( FD_UNLIKELY( bond->slave_cnt>=FD_NETDEV_BOND_SLAVE_MAX ) ) {
      FD_LOG_WARNING(( "Error reading interface table: Bond device %d has %u slaves but max is %d", master_idx, bond->slave_cnt, FD_NETDEV_BOND_SLAVE_MAX ));
      continue;
    }
    bond->slave_idx[ bond->slave_cnt ] = (ushort)j;
    bond->slave_cnt = (uchar)( bond->slave_cnt+1U );
  }

  return 0;

fail:
  fd_netlink_iter_drain( iter, netlink );
  return err;
}

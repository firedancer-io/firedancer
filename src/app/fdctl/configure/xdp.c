#define _GNU_SOURCE
#include "configure.h"

#include "../../../waltz/ebpf/fd_ebpf.h"
#include "../../../waltz/xdp/fd_xdp_redirect_user.h"

#include "../../../util/net/fd_ip4.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <linux/capability.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>

#define NAME "xdp"

static void
init_perm( fd_caps_ctx_t *  caps,
           config_t * const config ) {
  if( FD_UNLIKELY( config->development.netns.enabled ) )
    fd_caps_check_capability( caps, NAME, CAP_SYS_ADMIN, "enter a network namespace by calling `setns(2)`" );
  else {
    fd_caps_check_capability( caps, NAME, CAP_SYS_ADMIN, "create a BPF map with `bpf_map_create`" );
    fd_caps_check_capability( caps, NAME, CAP_NET_ADMIN, "create an XSK map with `bpf_map_create`" );
  }
}

/* fd_xdp_redirect_prog is eBPF ELF object containing the XDP program.
   It is embedded into this program. */
FD_IMPORT_BINARY( fd_xdp_redirect_prog, "src/waltz/xdp/fd_xdp_redirect_prog.o" );

static void
init( config_t * const config ) {
  if( FD_UNLIKELY( config->development.netns.enabled ) )
    enter_network_namespace( config->tiles.net.interface );

  uint mode = 0;
  if(      FD_LIKELY( !strcmp( config->tiles.net.xdp_mode, "skb" ) ) ) mode = XDP_FLAGS_SKB_MODE;
  else if( FD_LIKELY( !strcmp( config->tiles.net.xdp_mode, "drv" ) ) ) mode = XDP_FLAGS_DRV_MODE;
  else if( FD_LIKELY( !strcmp( config->tiles.net.xdp_mode, "hw"  ) ) ) mode = XDP_FLAGS_HW_MODE;
  else FD_LOG_ERR(( "unknown XDP mode `%s`", config->tiles.net.xdp_mode ));

  if( FD_UNLIKELY( fd_xdp_init( config->name,
                                0750,
                                (int)config->uid,
                                (int)config->uid ) ) )
    FD_LOG_ERR(( "fd_xdp_init failed" ));

  if( FD_UNLIKELY( fd_xdp_hook_iface( config->name,
                                      config->tiles.net.interface,
                                      mode,
                                      fd_xdp_redirect_prog,
                                      fd_xdp_redirect_prog_sz ) ) )
    FD_LOG_ERR(( "fd_xdp_hook_iface failed" ));

  /* The Linux kernel does some short circuiting optimizations
     when sending packets to an IP address that's owned by the
     same host. The optimization is basically to route them over
     to the loopback interface directly, bypassing the network
     hardware.

     This redirection to the loopback interface happens before
     XDP programs are executed, so local traffic destined for
     our listen addresses will not get ingested correctly.

     There are two reasons we send traffic locally,

      * For testing and development.
      * The Solana Labs code sends local traffic to itself to
        as part of routine operation (eg, when it's the leader
        it sends votes to its own TPU socket).

     So for now we need to also bind to loopback. This is a
     small performance hit for other traffic, but we only
     redirect packets destined for our target IP and port so
     it will not otherwise interfere. */
  if( FD_LIKELY( strcmp( config->tiles.net.interface, "lo" ) ) ) {
    if( FD_UNLIKELY( fd_xdp_hook_iface( config->name,
                                        "lo",
                                        mode,
                                        fd_xdp_redirect_prog,
                                        fd_xdp_redirect_prog_sz ) ) )
      FD_LOG_ERR(( "fd_xdp_hook_iface failed" ));
  }


  ushort udp_ports[] = { config->tiles.quic.regular_transaction_listen_port, config->tiles.quic.quic_transaction_listen_port,
                         config->tiles.shred.shred_listen_port                                                                };
  if( FD_UNLIKELY( fd_xdp_listen_udp_ports( config->name,
                                            config->tiles.net.ip_addr,
                                            3,
                                            udp_ports,
                                            1 ) ) )
    FD_LOG_ERR(( "fd_xdp_listen_udp_ports failed" ));
}

static void
fini_perm( fd_caps_ctx_t *  caps,
           config_t * const config ) {
  if( FD_UNLIKELY( config->development.netns.enabled ) )
    fd_caps_check_capability( caps, NAME, CAP_SYS_ADMIN, "enter a network namespace by calling `setns(2)`" );
}

static void
fini( config_t * const config ) {
  if( FD_UNLIKELY( fd_xdp_fini( config->name ) ) )
    FD_LOG_ERR(( "fd_xdp_fini failed" ));

  /* work around race condition, ugly hack due to kernel maybe removing
     some hooks in the background */
  nanosleep1( 1, 0 );

  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/fs/bpf/%s/%s", config->name, config->tiles.net.interface ) );
  if( FD_UNLIKELY( rmdir( path ) && errno != ENOENT ) ) FD_LOG_ERR(( "rmdir failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/fs/bpf/%s/lo", config->name ) );
  if( FD_UNLIKELY( rmdir( path ) && errno != ENOENT ) ) FD_LOG_ERR(( "rmdir failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/fs/bpf/%s", config->name ) );
  if( FD_UNLIKELY( rmdir( path ) && errno != ENOENT ) ) FD_LOG_ERR(( "rmdir failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static configure_result_t
check_xdp_ports( config_t * const config,
                 char const *     xdp_path ) {
  int fd = fd_bpf_obj_get( xdp_path );
  if( FD_UNLIKELY( fd==-1 ) ) {
    if( FD_UNLIKELY( errno==ENOENT ) ) PARTIALLY_CONFIGURED( "`%s` does not exist", xdp_path );
    else FD_LOG_ERR(( "open `%s` failed (%i-%s)", xdp_path, errno, fd_io_strerror( errno ) ));
  }

  ulong key = 0UL;
  uint value;

  /* There should never be any entry at key 0, we don't bind 0.0.0.0
      or port 0. */
  if( FD_UNLIKELY( !fd_bpf_map_lookup_elem( fd, &key, &value ) ) ) {
    if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    PARTIALLY_CONFIGURED( "udp_dsts bpf map had an entry at key zero" );
  }

  int seen_key[ 3 ] = {0};
  uint expected_port[ 3 ] = {
    config->tiles.quic.quic_transaction_listen_port,
    config->tiles.quic.regular_transaction_listen_port,
    config->tiles.shred.shred_listen_port,
  };

  for(;;) {
    ulong next_key;
    if( FD_UNLIKELY( -1==fd_bpf_map_get_next_key( fd, &key, &next_key ) ) ) {
      if( FD_LIKELY( errno==ENOENT ) ) break;
      else FD_LOG_ERR(( "fd_bpf_map_get_next_key failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }

    int recognized_key = 0;
    for( ulong i=0UL; i<sizeof( expected_port )/sizeof( expected_port[ 0 ] ); i++ ) {
      if( FD_LIKELY( next_key==fd_xdp_udp_dst_key( config->tiles.net.ip_addr, expected_port[ i ] ) ) ) {
        seen_key[ i ] = 1;
        recognized_key = 1;
        break;
      }
    }

    if( FD_UNLIKELY( !recognized_key ) ) {
      uint ip_addr = key>>16;
      ushort port  = fd_ushort_bswap( key&0xFFFF );
      if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      PARTIALLY_CONFIGURED( "udp_dsts bpf map has unexpected key for " FD_IP4_ADDR_FMT ":%u", FD_IP4_ADDR_FMT_ARGS( ip_addr ), port );
    }

    key = next_key;
  }

  for( ulong i=0UL; i<sizeof( expected_port )/sizeof( expected_port[ 0 ] ); i++ ) {
    if( FD_UNLIKELY( !seen_key[ i ] ) ) {
      if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      PARTIALLY_CONFIGURED( "udp_dsts bpf map missing key for " FD_IP4_ADDR_FMT ":%u", FD_IP4_ADDR_FMT_ARGS( config->tiles.net.ip_addr), expected_port[ i ] );
    }
  }

  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

struct libbpf_nla_req {
	struct nlmsghdr nh;
	union {
		struct ifinfomsg ifinfo;
		struct tcmsg tc;
		struct genlmsghdr gnl;
	};
	char buf[ 128 ];
};

static struct nlattr *nla_next(const struct nlattr *nla, int *remaining)
{
	int totlen = NLA_ALIGN(nla->nla_len);

	*remaining -= totlen;
	return (struct nlattr *)((void *)nla + totlen);
}

static int nla_ok(const struct nlattr *nla, int remaining)
{
	return remaining >= (int)sizeof(*nla) &&
	       nla->nla_len >= sizeof(*nla) &&
	       nla->nla_len <= remaining;
}

static int nla_type(const struct nlattr *nla)
{
	return nla->nla_type & NLA_TYPE_MASK;
}

static configure_result_t
check_xdp_program_mode( config_t * const config,
                        char const *     xdp_path ) {
  int fd = fd_bpf_obj_get( xdp_path );
  if( FD_UNLIKELY( fd==-1 ) ) {
    if( FD_UNLIKELY( errno==ENOENT ) ) PARTIALLY_CONFIGURED( "`%s` does not exist", xdp_path );
    else FD_LOG_ERR(( "open `%s` failed (%i-%s)", xdp_path, errno, fd_io_strerror( errno ) ));
  }

	struct libbpf_nla_req req = {
		.nh.nlmsg_len      = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
		.nh.nlmsg_type     = RTM_GETLINK,
		.nh.nlmsg_flags    = NLM_F_DUMP | NLM_F_REQUEST,
		.ifinfo.ifi_family = AF_PACKET,
	};

  struct sockaddr_nl sa = {
    .nl_family = AF_NETLINK,
    0
  };

  int sockfd = socket( AF_NETLINK, SOCK_RAW, NETLINK_ROUTE );
  if( FD_UNLIKELY( -1==sockfd ) ) FD_LOG_ERR(( "socket() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==bind( sockfd, (struct sockaddr *)&sa, sizeof( sa ) ) ) ) FD_LOG_ERR(( "bind() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  struct libbpf_nla_req req = {
		.nh.nlmsg_len      = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
		.nh.nlmsg_type     = RTM_GETLINK,
		.nh.nlmsg_flags    = NLM_F_DUMP | NLM_F_REQUEST,
    .nh.nlmsg_pid      = 0U,
    .nh.nlmsg_seq      = 0U,
		.ifinfo.ifi_family = AF_PACKET,
  };

  int sent = send( sockfd, &req, req.nh.nlmsg_len, 0 );
  if( FD_UNLIKELY( -1==sent ) ) FD_LOG_ERR(( "send() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( sent!=req.nh.nlmsg_len ) ) FD_LOG_ERR(( "failed to send whole netlink message" ));

  char buf[ 4096 ];
  long received = recv( sockfd, buf, sizeof( buf ), 0 );
  if( FD_UNLIKELY( -1==received ) ) FD_LOG_ERR(( "recv() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( 4096==received ) ) FD_LOG_ERR(( "recv() truncated (%i-%s)", errno, fd_io_strerror( errno ) ));

  struct nlmsghdr * nh = (struct nlmsghdr *)buf;
  for( nh = (struct nlmsghdr *)buf; NLMSG_OK( nh, received ); nh = NLMSG_NEXT( nh, received ) ) {
    FD_TEST( !(nh->nlmsg_flags & NLM_F_MULTI) );

    if( FD_UNLIKELY( nh->nlmsg_type==NLMSG_ERROR ) ) {
      struct nlmsgerr * err = NLMSG_DATA( nh );
      if( FD_UNLIKELY( err->error ) ) FD_LOG_ERR(( "netlink error %i", err->error ));
      break;
    }

    if( FD_UNLIKELY( nh->nlmsg_type==NLMSG_DONE ) ) break;

    FD_TEST( nh->nlmsg_type==RTM_NEWLINK );
    struct ifinfomsg * ifinfo = NLMSG_DATA( nh );

    int len = nh->nlmsg_len - NLMSG_LENGTH( sizeof( *ifinfo ) );
    struct nlattr * attr = ((void *)ifinfo + NLMSG_ALIGN( sizeof(*ifinfo)) );

#define libbpf_nla_for_each_attr(pos, head, len, rem) \
	for (pos = head, rem = len; \
	     nla_ok(pos, rem); \
	     pos = nla_next(pos, &(rem)))

    struct nlattr * tb[ IFLA_MAX+1UL ] = {0};

    struct nlattr * nla;
    int rem, err;
    libbpf_nla_for_each_attr(nla, attr, len, rem) {
      int type = nla_type(nla);
      if (type > IFLA_MAX) continue;
      tb[ type ] = nla;
    };

    if( FD_LIKELY( !tb[ IFLA_XDP ] ) ) continue;

    struct nlattr * xdp_tb[ IFLA_XDP_MAX+1UL ];
    struct nlattr * nla2;
    int rem2, err2;
    libbpf_nla_for_each_attr(nla2, tb[ IFLA_XDP ]+NLA_HDRLEN, tb[ IFLA_XDP ]->nla_len-NLA_HDRLEN, rem2) {
      int type = nla_type(nla2);
      if (type > IFLA_XDP_MAX) continue;
      xdp_tb[ type ] = nla2;
    };

    if( FD_UNLIKELY( !xdp_tb[ IFLA_XDP_ATTACHED ] ) ) {
      if( FD_UNLIKELY( close( sockfd ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      PARTIALLY_CONFIGURED( "XDP program not attached to interface %lu", ifinfo->ifi_index );
    }

    ulong modes = 0;
    char * xdp_mode = NULL;
    if( xdp_tb[ IFLA_XDP_PROG_ID ] ) {
      modes++;
      xdp_mode = "generic";
    } else if( xdp_tb[ IFLA_XDP_SKB_PROG_ID ] ) {
      modes++;
      xdp_mode = "skb";
    } else if( xdp_tb[ IFLA_XDP_DRV_PROG_ID ] ) {
      modes++;
      xdp_mode = "drv";
    } else if( xdp_tb[ IFLA_XDP_HW_PROG_ID ] ) {
      modes++;
      xdp_mode = "hw";
    }

    FD_TEST( modes==1UL );
    if( FD_UNLIKELY( strcmp( config->tiles.net.xdp_mode, xdp_mode ) ) ) {
      if( FD_UNLIKELY( close( sockfd ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      PARTIALLY_CONFIGURED( "XDP program attached to interface %lu but mode is not `%s`", ifinfo->ifi_index, xdp_mode );
    }
  }

  if( FD_UNLIKELY( close( sockfd ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  CONFIGURE_OK();
}

static configure_result_t
check_xdp_program_tag( config_t * const config,
                       char const *     xdp_path ) {
  int fd = fd_bpf_obj_get( xdp_path );
  if( FD_UNLIKELY( fd==-1 ) ) {
    if( FD_UNLIKELY( errno==ENOENT ) ) PARTIALLY_CONFIGURED( "`%s` does not exist", xdp_path );
    else FD_LOG_ERR(( "open `%s` failed (%i-%s)", xdp_path, errno, fd_io_strerror( errno ) ));
  }

  struct bpf_prog_info info = {0};
  int result = bpf_obj_get_info_by_fd( fd, &info, NULL );
  if( FD_UNLIKELY( result ) ) FD_LOG_ERR(( "bpf_obj_get_info_by_fd failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_sha512_t sha[1];
  FD_TEST( fd_sha512_init( fd_sha512_new( sha ) ) );

  fd_sha512_append( sha, fd_xdp_redirect_prog, fd_xdp_redirect_prog_sz );

  uchar hash[ 64 ];
  fd_sha512_fini( sha, hash );

  info.tag
  "555b207dad602ac7"


  char const * tag = info.tag;

  /* Use bpf_obj_get_info_by_fd syscall to get program tag*/
  {





    if( FD_UNLIKELY( info.info_len==0 ) ) {
      if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      PARTIALLY_CONFIGURED( "bpf_obj_get_info_by_fd returned zero length info" );
    }

    char * tag = NULL;
    for( ulong i=0; i<info.info_len; i++ ) {
      if( FD_LIKELY( info.info[ i ]=='\0' ) ) {
        tag = (char *)info.info;
        break;
      }
    }

    if( FD_UNLIKELY( !tag ) ) {
      if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      PARTIALLY_CONFIGURED( "bpf_obj_get_info_by_fd returned info without null terminator" );
    }

    if( FD_UNLIKELY( strcmp( tag, config->tiles.net.xdp_tag ) ) ) {
      if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      PARTIALLY_CONFIGURED( "XDP program tag is not `%s`", config->tiles.net.x
  }
  CONFIGURE_OK();
}

static configure_result_t
check( config_t * const config ) {
  char xdp_path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( xdp_path, PATH_MAX, NULL, "/sys/fs/bpf/%s", config->name ) );

  struct stat st;
  int result = stat( xdp_path, &st );
  if( FD_UNLIKELY( result && errno == ENOENT ) ) NOT_CONFIGURED( "`%s` does not exist", xdp_path );
  else if( FD_UNLIKELY( result ) ) PARTIALLY_CONFIGURED( "`%s` cannot be statted (%i-%s)", xdp_path, errno, fd_io_strerror( errno ) );

  CHECK( check_dir(  xdp_path, config->uid, config->uid, S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP ) );

  char * interfaces[] = { config->tiles.net.interface, "lo" };
  ulong interfaces_sz = !strcmp( config->tiles.net.interface, "lo" ) ? 1 : 2;
  for( ulong i=0; i<interfaces_sz; i++ ) {
    FD_TEST( fd_cstr_printf_check( xdp_path, PATH_MAX, NULL, "/sys/fs/bpf/%s/%s/xdp_link", config->name, interfaces[i] ) );
    CHECK( check_file( xdp_path,      config->uid, config->uid, S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP ) );

    FD_TEST( fd_cstr_printf_check( xdp_path, PATH_MAX, NULL, "/sys/fs/bpf/%s/%s/xdp_prog", config->name, interfaces[i] ) );
    CHECK( check_file( xdp_path,      config->uid, config->uid, S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP ) );

    FD_TEST( fd_cstr_printf_check( xdp_path, PATH_MAX, NULL, "/sys/fs/bpf/%s/%s/xsks", config->name, interfaces[i] ) );
    CHECK( check_file( xdp_path,      config->uid, config->uid, S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP ) );
  }

  FD_TEST( fd_cstr_printf_check( xdp_path, PATH_MAX, NULL, "/sys/fs/bpf/%s/udp_dsts", config->name ) );
  CHECK( check_file( xdp_path, config->uid, config->uid, S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP ) );

  CHECK( check_xdp_ports( config, xdp_path ) );
  CHECK( check_xdp_program_hash( config, xdp_path ) );
  CHECK( check_xdp_program_tag( config, xdp_path ) );

  CONFIGURE_OK();
}

configure_stage_t xdp = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = NULL,
  .init_perm       = init_perm,
  .fini_perm       = fini_perm,
  .init            = init,
  .fini            = fini,
  .check           = check,
};

#undef NAME

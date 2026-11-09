#include <stdio.h>
#include <errno.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
#include <sys/socket.h>
#include <unistd.h>
#include "fd_netdev_netlink.h"
#include "../../util/fd_util.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL,                     "normal" );
  ulong        page_cnt   = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL,                       4096UL );
  ulong        numa_idx   = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );
  ulong        dev_cnt    = fd_env_strip_cmdline_ulong( &argc, &argv, "--dev-cnt",  NULL,                        256UL );
  ulong        bond_cnt   = fd_env_strip_cmdline_ulong( &argc, &argv, "--bond-cnt", NULL,                          4UL );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  if( FD_UNLIKELY( !dev_cnt  ) ) FD_LOG_ERR(( "unsupported --dev-cnt"  ));
  if( FD_UNLIKELY( !bond_cnt ) ) FD_LOG_ERR(( "unsupported --bond-cnt" ));

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  ulong tbl_fp = fd_netdev_tbl_footprint( dev_cnt, bond_cnt );
  if( FD_UNLIKELY( !tbl_fp ) ) {
    FD_LOG_ERR(( "Invalid --dev-cnt or --page-cnt" ));
  }
  void * tbl_mem = fd_wksp_alloc_laddr( wksp, fd_netdev_tbl_align(), tbl_fp, 1UL );
  FD_TEST( tbl_mem );

  FD_TEST( fd_netdev_tbl_new( tbl_mem, dev_cnt, bond_cnt )==tbl_mem );
  fd_netdev_tbl_join_t tbl[1];
  FD_TEST( fd_netdev_tbl_join( tbl, tbl_mem )==tbl );

  int sv[2];
  FD_TEST( !socketpair( AF_UNIX, SOCK_DGRAM, 0, sv ) );
  struct {
    struct nlmsghdr nlh;
    struct ifinfomsg ifi;
    struct nlmsghdr bad;
  } dump = {
    .nlh = { .nlmsg_type=RTM_NEWLINK, .nlmsg_flags=NLM_F_MULTI, .nlmsg_len=NLMSG_LENGTH( sizeof(struct ifinfomsg) ), .nlmsg_seq=42U },
    .ifi = { .ifi_type=ARPHRD_LOOPBACK, .ifi_index=1 },
    .bad = { .nlmsg_len=sizeof(struct nlmsghdr)+1 }
  };
  FD_TEST( send( sv[1], &dump, sizeof(dump), 0 )==(long)sizeof(dump) );
  /* Queue the old dump's tail and the next request's response separately. */
  dump.ifi.ifi_index = 2;
  dump.bad = (struct nlmsghdr){ .nlmsg_type=NLMSG_DONE, .nlmsg_len=sizeof(struct nlmsghdr), .nlmsg_seq=42U };
  FD_TEST( send( sv[1], &dump, sizeof(dump), 0 )==(long)sizeof(dump) );
  dump.ifi.ifi_index = 3;
  dump.nlh.nlmsg_seq = dump.bad.nlmsg_seq = 43U;
  FD_TEST( send( sv[1], &dump, sizeof(dump), 0 )==(long)sizeof(dump) );
  fd_netlink_t mock = { .fd=sv[0], .seq=42U };
  FD_TEST( fd_netdev_netlink_load_table( tbl, &mock )==EPROTO );
  FD_TEST( !tbl->hdr->dev_cnt );
  struct nlmsghdr next;
  FD_TEST( recv( sv[0], &next, sizeof(next), MSG_PEEK|MSG_DONTWAIT )==(long)sizeof(next) );
  FD_TEST( next.nlmsg_seq==43U );
  FD_TEST( !fd_netdev_netlink_load_table( tbl, &mock ) );
  FD_TEST( tbl->hdr->dev_cnt==1U && tbl->dev_tbl[0].if_idx==3U );

  /* The kernel can mark either a data message or DONE as interrupted. */
  for( uint i=0U; i<2U; i++ ) {
    dump.nlh.nlmsg_seq = dump.bad.nlmsg_seq = mock.seq;
    dump.nlh.nlmsg_flags = (ushort)(NLM_F_MULTI | (i ? 0 : NLM_F_DUMP_INTR));
    dump.bad.nlmsg_flags = (ushort)(i ? NLM_F_DUMP_INTR : 0);
    FD_TEST( send( sv[1], &dump, sizeof(dump), 0 )==(long)sizeof(dump) );
    FD_TEST( fd_netdev_netlink_load_table( tbl, &mock )==EINTR );
    FD_TEST( !tbl->hdr->dev_cnt );
  }
  FD_TEST( !close( sv[0] ) );
  FD_TEST( !close( sv[1] ) );

  fd_netlink_t _netlink[1];
  fd_netlink_t * netlink = fd_netlink_init( _netlink, 42U );
  FD_TEST( netlink );

  int ld_err = fd_netdev_netlink_load_table( tbl, netlink );
  FD_TEST( !ld_err );
  if( FD_UNLIKELY( ld_err ) ) {
    FD_LOG_WARNING(( "Failed to load interfaces (error code %i)", ld_err ));
  }
  FD_LOG_NOTICE(( "Dumping interface table" ));
  fd_log_flush();
  fd_netdev_tbl_fprintf( tbl, stderr );
  fflush( stderr );

  fd_netlink_fini( netlink );
  fd_netdev_tbl_leave( tbl );
  fd_wksp_free_laddr( fd_netdev_tbl_delete( tbl_mem ) );
  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#include "fd_neigh4_netlink.h"
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h> /* AF_PACKET */
#include <net/if.h>
#include <linux/if_arp.h> /* ARPHRD_ETHER */
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "../../util/fd_util.h"

static void
dump_neighbor_table( fd_neigh4_hmap_t * map,
                     fd_netlink_t *     netlink1,
                     int                if_idx ) {
  fd_neigh4_netlink_request_dump( netlink1, (uint)if_idx );

  uchar buf[ 4096 ];
  fd_netlink_iter_t iter[1];
  for( fd_netlink_iter_init( iter, netlink1, buf, sizeof(buf) );
       !fd_netlink_iter_done( iter );
       fd_netlink_iter_next( iter, netlink1 ) ) {
    fd_neigh4_netlink_ingest_message( map, fd_netlink_iter_msg( iter ), (uint)if_idx );
  }

  char name[ IF_NAMESIZE ];
  fprintf( stderr, "# ip neigh show dev %s\n", if_indextoname( (uint)if_idx, name ) );
  fd_log_flush();
  fd_neigh4_hmap_fprintf( map, stderr );
  fputs( "\n", stderr );

  /* Reinitialize table */

  ulong  ele_max   = fd_neigh4_hmap_ele_max  ( map );
  ulong  lock_cnt  = fd_neigh4_hmap_lock_cnt ( map );
  ulong  probe_max = fd_neigh4_hmap_probe_max( map );
  ulong  seed      = fd_neigh4_hmap_seed     ( map );
  void * shmap     = fd_neigh4_hmap_shmap    ( map );
  void * shele     = fd_neigh4_hmap_shele    ( map );
  void * ljoin     = fd_neigh4_hmap_leave    ( map );
  fd_neigh4_hmap_delete( shmap );
  fd_memset( shele, 0, ele_max*sizeof(fd_neigh4_entry_t) );
  FD_TEST( fd_neigh4_hmap_new( shmap, ele_max, lock_cnt, probe_max, seed ) );
  FD_TEST( fd_neigh4_hmap_join( ljoin, shmap, shele ) );
}

static void
dump_all_neighbor_tables( fd_neigh4_hmap_t * map,
                          fd_netlink_t *     netlink0,
                          fd_netlink_t *     netlink1 ) {

  /* List all network interfaces */

  uint seq = netlink0->seq++;
  struct {
    struct nlmsghdr  nlh;
    struct ifinfomsg ifi;
  } request;
  request.nlh = (struct nlmsghdr){
    .nlmsg_len   = sizeof(request),
    .nlmsg_type  = RTM_GETLINK,
    .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
    .nlmsg_seq   = seq
  };
  request.ifi = (struct ifinfomsg){
    .ifi_family = AF_PACKET,
    .ifi_type   = ARPHRD_ETHER
  };

  long send_res = send( netlink0->fd, &request, sizeof(request), 0);
  if( FD_UNLIKELY( send_res<0 ) ) {
    FD_LOG_ERR(( "netlink send(RTM_GETLINK,NLM_F_REQUEST|NLM_F_DUMP,ARPHRD_ETHER) failed (%d-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( send_res!=sizeof(request) ) ) {
    FD_LOG_ERR(( "netlink send(RTM_GETLINK,NLM_F_REQUEST|NLM_F_DUMP,ARPHRD_ETHER) failed (short write)" ));
  }

  FD_LOG_NOTICE(( "Dumping neighbor tables for all Ethernet interfaces\n" ));
  fd_log_flush();

  uchar buf[ 4096 ];
  fd_netlink_iter_t iter[1];
  for( fd_netlink_iter_init( iter, netlink0, buf, sizeof(buf) );
       !fd_netlink_iter_done( iter );
       fd_netlink_iter_next( iter, netlink0 ) ) {
    struct nlmsghdr const * nlh = fd_netlink_iter_msg( iter );
    if( FD_UNLIKELY( nlh->nlmsg_type==NLMSG_ERROR ) ) {
      struct nlmsgerr * err = NLMSG_DATA( nlh );
      int nl_err = -err->error;
      FD_LOG_ERR(( "netlink RTM_GETLINK,NLM_F_REQUEST|NLM_F_DUMP,ARPHRD_ETHER failed (%d-%s)", nl_err, fd_io_strerror( nl_err ) ));
    }
    if( FD_UNLIKELY( nlh->nlmsg_type!=RTM_NEWLINK ) ) {
      FD_LOG_DEBUG(( "unexpected nlmsg_type %u", nlh->nlmsg_type ));
      continue;
    }
    struct ifinfomsg const * ifi = NLMSG_DATA( nlh );

    dump_neighbor_table( map, netlink1, ifi->ifi_index );
  }

}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--page-sz",  NULL, "gigantic"                 );
  ulong        page_cnt = fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt", NULL, 1UL                        );
  ulong        numa_idx = fd_env_strip_cmdline_ulong ( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx(cpu_idx) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  FD_LOG_NOTICE(( "Creating anonymous workspace with --page-cnt %lu --page-sz %s pages on --numa-idx %lu", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  fd_netlink_t _netlink[2];
  fd_netlink_t * netlink0 = fd_netlink_init( _netlink+0,  42U );
  fd_netlink_t * netlink1 = fd_netlink_init( _netlink+1, 999U );
  FD_TEST( netlink0 );
  FD_TEST( netlink1 );

  ulong  ele_max   = 16384UL;
  ulong  lock_cnt  = 4UL;
  ulong  probe_max = 16UL;
  ulong  seed      = 42UL;
  void * hmap_mem  = fd_wksp_alloc_laddr( wksp, fd_neigh4_hmap_align(), fd_neigh4_hmap_footprint( ele_max, lock_cnt, probe_max ), 1UL );
  void * ele_mem   = fd_wksp_alloc_laddr( wksp, alignof(fd_neigh4_entry_t), ele_max*sizeof(fd_neigh4_entry_t), 1UL );
  FD_TEST( hmap_mem ); FD_TEST( ele_mem );
  FD_TEST( fd_neigh4_hmap_new( hmap_mem, ele_max, lock_cnt, probe_max, seed ) );

  fd_neigh4_hmap_t _map[1];
  fd_neigh4_hmap_t * map = fd_neigh4_hmap_join( _map, hmap_mem, ele_mem );
  FD_TEST( map );

  dump_all_neighbor_tables( map, netlink0, netlink1 );

  fd_netlink_fini( netlink0 );
  fd_netlink_fini( netlink1 );

  fd_neigh4_hmap_leave( map );
  fd_wksp_free_laddr( fd_neigh4_hmap_delete( hmap_mem ) );
  fd_wksp_free_laddr( ele_mem );
  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#include "fd_snapct_test_topo.h"
#include "../fd_snapct_tile.h"
#include "../utils/fd_ssctrl.h"

#include "../../../disco/topo/fd_topob.h"
#include "../../../app/platform/fd_file_util.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>

struct fd_snapct_test_env {
  char  snapshots_path[ PATH_MAX ];
  ulong snapshots_path_len;
};

typedef struct fd_snapct_test_env fd_snapct_test_env_t;

static void
test_snapct_env_init( fd_snapct_test_env_t * env,
                     ulong                   full_slot,
                     ulong                   incr_slot ) {
  /* guaranteed to be a unique directory in tmp with mkdtemp */
  char tmp_path_template[] = "/tmp/test_snapct_tile.XXXXXX";
  char * tmp_path          = mkdtemp(tmp_path_template);
  if( FD_UNLIKELY( !tmp_path ) ) FD_LOG_ERR(( "mkdtemp(%s) failed (%i-%s)", tmp_path_template, errno, fd_io_strerror( errno )));

  fd_memcpy( env->snapshots_path, tmp_path, sizeof(tmp_path_template) );
  env->snapshots_path_len = sizeof(tmp_path_template);

  int dir_fd = open( env->snapshots_path, O_DIRECTORY|O_CLOEXEC );
  if( dir_fd == -1 ) FD_LOG_ERR(("open(%s) failed (%i-%s)", env->snapshots_path, errno, fd_io_strerror( errno )));

  char full_snapshot_name[ PATH_MAX ];
  fd_cstr_printf_check( full_snapshot_name, PATH_MAX, NULL, "snapshot-%lu-AAAA.tar.zst", full_slot );
  int full_snapshot_fd = openat( dir_fd, full_snapshot_name, O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR );
  if( full_snapshot_fd == -1 ) FD_LOG_ERR(("openat(%s) failed (%i-%s)", full_snapshot_name, errno, fd_io_strerror( errno )));

  char incr_snapshot_name[ PATH_MAX ];
  fd_cstr_printf_check( incr_snapshot_name, PATH_MAX, NULL, "snapshot-%lu-AAAA.tar.zst", incr_slot );
  int incr_snapshot_fd = openat( dir_fd, incr_snapshot_name, O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR );
  if( incr_snapshot_fd == -1 ) FD_LOG_ERR(("openat(%s) failed (%i-%s)", incr_snapshot_name, errno, fd_io_strerror( errno )));

  if( close( dir_fd ) ) FD_LOG_ERR(("close() failed (%i-%s)", errno, fd_io_strerror( errno )));
  if( close( full_snapshot_fd ) ) FD_LOG_ERR(("close() failed (%i-%s)", errno, fd_io_strerror( errno )));
  if( close( incr_snapshot_fd ) ) FD_LOG_ERR(("close() failed (%i-%s)", errno, fd_io_strerror( errno )));
}

static void
test_snapct_env_fini( fd_snapct_test_env_t * env ) {
  fd_file_util_rmtree( env->snapshots_path, 1 );
}

static fd_topo_t *
test_snapct_init_topo( fd_wksp_t * wksp ) {
  fd_topo_t * topo = fd_wksp_alloc_laddr( wksp, alignof(fd_topo_t), sizeof(fd_topo_t), 1UL );
  FD_TEST( topo );

  topo = fd_topob_new( topo, "snapct" );
  FD_TEST( topo );

  fd_topo_wksp_t * topo_wksp = fd_topob_wksp( topo, "snapct" );
  topo_wksp->wksp = wksp;

  fd_topob_tile( topo, "snapct", "snapct", "snapct", 0UL, 0, 0 );

  fd_restore_create_link( wksp, topo, "snapct_ld",   "snapct",  LINK_DEPTH, 280UL,       0, 0 );
  fd_restore_create_link( wksp, topo, "snapct_repr", "snapct",  LINK_DEPTH, 0UL,         1, 0 );
  fd_restore_create_link( wksp, topo, "snapld_dc",   "snapct",  LINK_DEPTH, USHORT_MAX,  0, 1 );
  fd_restore_create_link( wksp, topo, "snapls_ct",   "snapct",  LINK_DEPTH, 0UL,         0, 1 );
  fd_restore_create_link( wksp, topo, "gossip_out",  "snapct",  LINK_DEPTH, 128UL,       0, 1 );

  fd_topob_tile_in ( topo, "snapct", 0UL, "snapct", "snapls_ct",  0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in ( topo, "snapct", 0UL, "snapct", "snapld_dc",  0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in ( topo, "snapct", 0UL, "snapct", "gossip_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapct", 0UL,           "snapct_ld",   0UL                                     );
  fd_topob_tile_out( topo, "snapct", 0UL,           "snapct_repr", 0UL                                     );
  return topo;
}

static void
test_snapct_fini( fd_topo_t * topo ) {
  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[i];
    fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( link->mcache ) ) );
    fd_wksp_free_laddr( fd_dcache_delete( fd_dcache_leave( link->dcache ) ) );
  }
}

static void
test_full_effective_cancel_threshold_with_gossip_peer( fd_snapct_test_topo_t * snapct,
                                                       fd_snapct_test_env_t *  env,
                                                       fd_topo_t *             topo,
                                                       fd_wksp_t *             wksp ) {
  fd_snapct_test_topo_init( fd_snapct_test_topo_join( fd_snapct_test_topo_new( snapct ) ),
                            topo,
                            wksp,
                            "snapct",
                            1,
                            0,
                            NULL,
                            NULL,
                            NULL,
                            "snapls_ct",
                            env->snapshots_path,
                            env->snapshots_path_len );

  fd_ip4_port_t addr0 = { .addr = FD_IP4_ADDR( 35, 124, 174, 225 ), .port = fd_ushort_bswap( 8899 ) };
  uchar origin_pubkey0[ FD_HASH_FOOTPRINT ]; fd_memset( origin_pubkey0, 0xA, FD_HASH_FOOTPRINT );

  fd_snapct_test_topo_inject_ping( snapct, addr0, 10000UL );
  fd_snapct_test_topo_inject_snapshot_hash( snapct, origin_pubkey0, addr0, 0UL, FD_SNAPCT_TEST_TOPO_DEFAULT_FULL_SLOT, FD_SNAPCT_TEST_TOPO_DEFAULT_FULL_SLOT+100UL );

  int opt_poll_in = 0;
  int charge_busy = 0;
  fd_snapct_test_topo_after_credit( snapct, &opt_poll_in, &charge_busy );
  FD_TEST( fd_snapct_test_topo_get_state(snapct )==FD_SNAPCT_STATE_COLLECTING_PEERS );
  fd_snapct_test_topo_after_credit( snapct, &opt_poll_in, &charge_busy );
  FD_TEST( fd_snapct_test_topo_get_state(snapct )==FD_SNAPCT_STATE_READING_FULL_HTTP );

  FD_TEST( fd_restore_poll_link_in( &snapct->out_ld_in_view )==1UL );
  fd_ssctrl_init_t const * init_msg = fd_chunk_to_laddr_const( snapct->out_ld_in_view.mem, snapct->out_ld_in_view.result.chunk );
  FD_TEST( init_msg->file==0 );
  FD_TEST( init_msg->zstd==1 );
  FD_TEST( init_msg->slot==FD_SNAPCT_TEST_TOPO_DEFAULT_FULL_SLOT );
  FD_TEST( init_msg->addr.l==addr0.l );
  FD_TEST( init_msg->is_https==0 );

  /* inject a new snapshot hash that is 20001 slots ahead of the current snapshot */
  fd_ip4_port_t addr1 = { .addr = FD_IP4_ADDR( 35, 124, 175, 225 ), .port = fd_ushort_bswap( 8899 ) };
  uchar origin_pubkey1[ FD_HASH_FOOTPRINT ]; fd_memset( origin_pubkey1, 0xB, FD_HASH_FOOTPRINT );
  fd_snapct_test_topo_inject_ping( snapct, addr1, 10000UL );
  fd_snapct_test_topo_inject_snapshot_hash( snapct, origin_pubkey1, addr1, 1UL, FD_SNAPCT_TEST_TOPO_DEFAULT_FULL_SLOT+20000UL, FD_SNAPCT_TEST_TOPO_DEFAULT_FULL_SLOT+20101UL);
  FD_TEST( fd_snapct_test_topo_get_state(snapct )==FD_SNAPCT_STATE_FLUSHING_FULL_HTTP_RESET );

  /* flush ack message from end of snapshot pipeline */
  FD_TEST( fd_snapct_test_topo_returnable_frag( snapct, 0, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL )==0 );
  /* skip fail message to sent to ld */
  FD_TEST( fd_restore_poll_link_in( &snapct->out_ld_in_view )==1UL );

  fd_snapct_test_topo_after_credit( snapct, &opt_poll_in, &charge_busy );
  FD_TEST( fd_snapct_test_topo_get_state( snapct )==FD_SNAPCT_STATE_COLLECTING_PEERS );

  fd_snapct_test_topo_after_credit( snapct, &opt_poll_in, &charge_busy );
  FD_TEST( fd_snapct_test_topo_get_state( snapct )==FD_SNAPCT_STATE_READING_FULL_HTTP );

  FD_TEST( fd_restore_poll_link_in( &snapct->out_ld_in_view )==1UL );
  fd_ssctrl_init_t const * init_msg_2 = fd_chunk_to_laddr_const( snapct->out_ld_in_view.mem, snapct->out_ld_in_view.result.chunk );
  FD_TEST( init_msg_2->file==0 );
  FD_TEST( init_msg_2->zstd==1 );
  FD_TEST( init_msg_2->slot==FD_SNAPCT_TEST_TOPO_DEFAULT_FULL_SLOT+20000UL );
  FD_TEST( init_msg_2->addr.l==addr1.l );
  FD_TEST( init_msg_2->is_https==0 );

  fd_snapct_test_topo_fini( snapct );
}

static void
test_full_effective_cancel_threshold_with_server( fd_snapct_test_topo_t * snapct,
                                                  fd_snapct_test_env_t *  env,
                                                  fd_topo_t *             topo,
                                                  fd_wksp_t *             wksp ) {
  fd_ip4_port_t addr[2UL] = { { .addr = FD_IP4_ADDR( 35, 124, 174, 225 ), .port = fd_ushort_bswap( 8899 ) }, { .addr = FD_IP4_ADDR( 35, 124, 175, 226 ), .port = fd_ushort_bswap( 8899 ) } };
  char const * server_names[ 2UL ] = { "test-server-1", "test-server-2" };
  ulong server_names_len[ 2UL ]    = { 14UL, 14UL };
  fd_snapct_test_topo_init( fd_snapct_test_topo_join( fd_snapct_test_topo_new( snapct ) ),
                            topo,
                            wksp,
                            "snapct",
                            0,
                            2,
                            addr,
                            server_names,
                            server_names_len,
                            "snapls_ct",
                            env->snapshots_path,
                            env->snapshots_path_len );

  fd_snapct_test_topo_inject_ping( snapct, addr[0UL], 10000UL );
  fd_snapct_test_topo_inject_server_response( snapct, addr[0UL], FD_SNAPCT_TEST_TOPO_DEFAULT_FULL_SLOT, FD_SNAPCT_TEST_TOPO_DEFAULT_FULL_SLOT+100UL );

  int opt_poll_in = 0;
  int charge_busy = 0;
  fd_snapct_test_topo_after_credit( snapct, &opt_poll_in, &charge_busy );
  FD_TEST( fd_snapct_test_topo_get_state(snapct )==FD_SNAPCT_STATE_COLLECTING_PEERS );
  fd_snapct_test_topo_after_credit( snapct, &opt_poll_in, &charge_busy );
  FD_TEST( fd_snapct_test_topo_get_state(snapct )==FD_SNAPCT_STATE_READING_FULL_HTTP );

  FD_TEST( fd_restore_poll_link_in( &snapct->out_ld_in_view )==1UL );
  fd_ssctrl_init_t const * init_msg = fd_chunk_to_laddr_const( snapct->out_ld_in_view.mem, snapct->out_ld_in_view.result.chunk );
  FD_TEST( init_msg->file==0 );
  FD_TEST( init_msg->zstd==1 );
  FD_TEST( init_msg->slot==FD_SNAPCT_TEST_TOPO_DEFAULT_FULL_SLOT );
  FD_TEST( init_msg->addr.l==addr[0UL].l );
  FD_TEST( strcmp(init_msg->hostname, "test-server-1")==0 );
  FD_TEST( init_msg->is_https==0 );

  /* inject a server response that is 20001 slots ahead of the current snapshot */
  fd_snapct_test_topo_inject_ping( snapct, addr[1UL], 10000UL );
  fd_snapct_test_topo_inject_server_response( snapct, addr[1UL], FD_SNAPCT_TEST_TOPO_DEFAULT_FULL_SLOT+20000UL, FD_SNAPCT_TEST_TOPO_DEFAULT_FULL_SLOT+20101UL);
  FD_TEST( fd_snapct_test_topo_get_state(snapct )==FD_SNAPCT_STATE_FLUSHING_FULL_HTTP_RESET );

  /* flush ack message from end of snapshot pipeline */
  FD_TEST( fd_snapct_test_topo_returnable_frag( snapct, 0, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL )==0 );
  /* skip fail message to sent to ld */
  FD_TEST( fd_restore_poll_link_in( &snapct->out_ld_in_view )==1UL );

  fd_snapct_test_topo_after_credit( snapct, &opt_poll_in, &charge_busy );
  FD_TEST( fd_snapct_test_topo_get_state( snapct )==FD_SNAPCT_STATE_COLLECTING_PEERS );

  fd_snapct_test_topo_after_credit( snapct, &opt_poll_in, &charge_busy );
  FD_TEST( fd_snapct_test_topo_get_state( snapct )==FD_SNAPCT_STATE_READING_FULL_HTTP );

  FD_TEST( fd_restore_poll_link_in( &snapct->out_ld_in_view )==1UL );
  fd_ssctrl_init_t const * init_msg_2 = fd_chunk_to_laddr_const( snapct->out_ld_in_view.mem, snapct->out_ld_in_view.result.chunk );
  FD_TEST( init_msg_2->file==0 );
  FD_TEST( init_msg_2->zstd==1 );
  FD_TEST( init_msg_2->slot==FD_SNAPCT_TEST_TOPO_DEFAULT_FULL_SLOT+20000UL );
  FD_TEST( init_msg_2->addr.l==addr[1UL].l );
  FD_TEST( strcmp(init_msg_2->hostname, "test-server-2")==0 );
  FD_TEST( init_msg_2->is_https==0 );

  fd_snapct_test_topo_fini( snapct );
}

/* TODO: add more unit tests */
int main( int     argc,
    char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 12UL;
  char * _page_sz  = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );

  FD_TEST( wksp );
  fd_snapct_test_env_t env;
  test_snapct_env_init( &env, FD_SNAPCT_TEST_TOPO_DEFAULT_FULL_SLOT, FD_SNAPCT_TEST_TOPO_DEFAULT_FULL_SLOT+100UL );

  fd_snapct_test_topo_t snapct;
  fd_topo_t * topo = test_snapct_init_topo( wksp );
  test_full_effective_cancel_threshold_with_gossip_peer( &snapct, &env, topo, wksp );
  test_full_effective_cancel_threshold_with_server( &snapct, &env, topo, wksp );
  test_snapct_fini( topo );

  test_snapct_env_fini( &env );
  fd_wksp_delete( wksp );
  return 0;
}

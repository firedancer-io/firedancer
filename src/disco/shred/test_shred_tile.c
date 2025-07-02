#define FD_TILE_TEST
#define _GNU_SOURCE

#include <errno.h>    /* errno */
#include <sys/mman.h> /* MAP_FAILED, memfd_create */

// #include <unistd.h> /* getgid, getuid, setegid, seteuid */
// #include <sys/stat.h> /* stat */
// #include <dirent.h> /* DIR */

#include "../../app/platform/fd_file_util.h"
#include "../../app/shared/fd_config.h"
#include "../../app/shared/fd_obj_callbacks.c"
#include "../../app/shared/fd_action.h"

/* Frankendancer topology */
#include "../../app/fdctl/topology.c"


extern fd_topo_obj_callbacks_t fd_obj_cb_mcache;
extern fd_topo_obj_callbacks_t fd_obj_cb_dcache;
extern fd_topo_obj_callbacks_t fd_obj_cb_cnc;
extern fd_topo_obj_callbacks_t fd_obj_cb_fseq;
extern fd_topo_obj_callbacks_t fd_obj_cb_metrics;
extern fd_topo_obj_callbacks_t fd_obj_cb_opaque;
extern fd_topo_obj_callbacks_t fd_obj_cb_dbl_buf;
extern fd_topo_obj_callbacks_t fd_obj_cb_neigh4_hmap;
extern fd_topo_obj_callbacks_t fd_obj_cb_fib4;
extern fd_topo_obj_callbacks_t fd_obj_cb_keyswitch;
extern fd_topo_obj_callbacks_t fd_obj_cb_tile;

fd_topo_obj_callbacks_t * CALLBACKS[] = {
  &fd_obj_cb_mcache,
  &fd_obj_cb_dcache,
  &fd_obj_cb_cnc,
  &fd_obj_cb_fseq,
  &fd_obj_cb_metrics,
  &fd_obj_cb_opaque,
  &fd_obj_cb_dbl_buf,
  &fd_obj_cb_neigh4_hmap,
  &fd_obj_cb_fib4,
  &fd_obj_cb_keyswitch,
  &fd_obj_cb_tile,
  NULL,
};

/* Tile under test */
extern fd_topo_run_tile_t fd_tile_shred;

/* Dummy tiles to fill up the topology - Frankendancer. */
fd_topo_run_tile_t dummy_tile_net    = { .name = "net" };
fd_topo_run_tile_t dummy_tile_netlnk = { .name = "netlnk" };
fd_topo_run_tile_t dummy_tile_sock   = { .name = "sock" };
fd_topo_run_tile_t dummy_tile_quic   = { .name = "quic" };
fd_topo_run_tile_t dummy_tile_bundle = { .name = "bundle" };
fd_topo_run_tile_t dummy_tile_verify = { .name = "verify" };
fd_topo_run_tile_t dummy_tile_dedup  = { .name = "dedup" };
fd_topo_run_tile_t dummy_tile_pack   = { .name = "pack" };
// fd_topo_run_tile_t dummy_tile_shred  = { .name = "shred" }; /* replaced by fd_tile_shred */
fd_topo_run_tile_t dummy_tile_sign   = { .name = "sign" };
fd_topo_run_tile_t dummy_tile_metric = { .name = "metric" };
fd_topo_run_tile_t dummy_tile_cswtch = { .name = "cswtch" };
fd_topo_run_tile_t dummy_tile_gui    = { .name = "gui" };
fd_topo_run_tile_t dummy_tile_plugin = { .name = "plugin" };
fd_topo_run_tile_t dummy_tile_bencho = { .name = "bencho" };
fd_topo_run_tile_t dummy_tile_benchg = { .name = "benchg" };
fd_topo_run_tile_t dummy_tile_benchs = { .name = "benchs" };
fd_topo_run_tile_t dummy_tile_pktgen = { .name = "pktgen" };
fd_topo_run_tile_t dummy_tile_resolv = { .name = "resolv" };
fd_topo_run_tile_t dummy_tile_poh    = { .name = "poh" };
fd_topo_run_tile_t dummy_tile_bank   = { .name = "bank" };
fd_topo_run_tile_t dummy_tile_store  = { .name = "store" };


fd_topo_run_tile_t * TILES[] = {
  &dummy_tile_net,
  &dummy_tile_netlnk,
  &dummy_tile_sock,
  &dummy_tile_quic,
  &dummy_tile_bundle,
  &dummy_tile_verify,
  &dummy_tile_dedup,
  &dummy_tile_pack,
  // &dummy_tile_shred, /* replaced by fd_tile_shred */
  &dummy_tile_sign,
  &dummy_tile_metric,
  &dummy_tile_cswtch,
  &dummy_tile_gui,
  &dummy_tile_plugin,
  &dummy_tile_bencho,
  &dummy_tile_benchg,
  &dummy_tile_benchs,
  &dummy_tile_pktgen,
  &dummy_tile_resolv,
  &dummy_tile_poh,
  &dummy_tile_bank,
  &dummy_tile_store,
  &fd_tile_shred,
  NULL,
};

action_t * ACTIONS[] = {
  NULL,
};

#include "fd_shred_tile.c"

config_t config[1];


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * user_config_path = fd_env_strip_cmdline_cstr ( &argc, &argv, "--config",    NULL,            NULL );
  uint         rng_seed         = fd_env_strip_cmdline_uint ( &argc, &argv, "--rng-seed",  NULL,              0U );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, rng_seed, 0UL ) );

  int is_firedancer       = 0;
  int is_local_cluster    = 0;
  int netns = fd_env_strip_cmdline_contains( &argc, &argv, "--netns" );
  FD_IMPORT_BINARY( default_config, "src/app/fdctl/config/default.toml" );

  char * user_config = NULL;
  ulong user_config_sz = 0UL;
  if( FD_LIKELY( user_config_path ) ) {
    user_config = fd_file_util_read_all( user_config_path, &user_config_sz );
    if( FD_UNLIKELY( user_config==MAP_FAILED ) ) FD_LOG_ERR(( "failed to read user config file `%s` (%d-%s)", user_config_path, errno, fd_io_strerror( errno ) ));
  }
  fd_memset( config, 0, sizeof( config_t ) );
  fd_config_load( is_firedancer, netns, is_local_cluster, (const char *)default_config, default_config_sz, user_config, user_config_sz, user_config_path, config );
  fd_topo_initialize( config );

  fd_shmem_private_boot( &argc, &argv );
  fd_tile_private_boot( 0, NULL );

  for( ulong i=0UL; i<config->topo.wksp_cnt; i++ ) {
    fd_topo_wksp_t * wksp = &config->topo.workspaces[ i ];
    FD_LOG_NOTICE(( "Creating workspace %s (--page-cnt %lu, --page-sz %lu, --cpu-idx %lu)", wksp->name, wksp->page_cnt, wksp->page_sz, fd_shmem_cpu_idx( wksp->numa_idx ) ));
    wksp->wksp = fd_wksp_new_anonymous( wksp->page_sz,  wksp->page_cnt, fd_shmem_cpu_idx( wksp->numa_idx ), wksp->name, 0UL );
    FD_TEST( wksp->wksp );
    ulong offset = fd_wksp_alloc( wksp->wksp, fd_topo_workspace_align(), wksp->known_footprint, 1UL );
    if( FD_UNLIKELY( !offset ) ) FD_LOG_ERR(( "fd_wksp_alloc failed" ));
    /* FIXME assert offset==gaddr_lo */

    // fd_topo_join_workspace( &config->topo, wksp, FD_SHMEM_JOIN_MODE_READ_WRITE ); /* DO NOT USE - leave as reference */
    fd_topo_wksp_new( &config->topo, wksp, CALLBACKS );
    fd_topo_workspace_fill( &config->topo, wksp );
    // fd_topo_leave_workspace( &config->topo, wksp ); /* DO NOT USE - leave as reference */
  }

  /* Fill tile. */
  fd_topo_tile_t * test_tile = NULL;
  for( ulong i=0; i<config->topo.tile_cnt; i++ ) {
    if( !strcmp( config->topo.tiles[ i ].name, "shred" ) ) {
      test_tile = &config->topo.tiles[ i ];
      break;
    }
  }
  FD_TEST( test_tile );
  // fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE ); /* DO NOT USE - leave as reference */
  // fd_topo_join_tile_workspaces( &config->topo, test_tile ); /* DO NOT USE - leave as reference */
  fd_topo_fill_tile( &config->topo, test_tile );
  // initialize_stacks( config );  /* DO NOT USE - leave as reference */

  /* [tile-unit-test] unprivileged_init. */
  FD_LOG_NOTICE(( "[tile-unit-test] before_frag" ));
  ulong poh_shed_obj_id = fd_pod_query_ulong( config->topo.props, "poh_shred", ULONG_MAX );
  FD_TEST( poh_shed_obj_id!=ULONG_MAX );
  ulong * gossip_shred_version = fd_fseq_join( fd_topo_obj_laddr( &config->topo, poh_shed_obj_id ) );
  *gossip_shred_version = 0xcafeUL;
  unprivileged_init( &config->topo, test_tile );

  /* [tile-unit-test] config tile-unit-test. */
  ulong topo_shred_tile_idx = fd_topo_find_tile( &config->topo, "shred", 0UL );
  FD_TEST( topo_shred_tile_idx!=ULONG_MAX );
  fd_topo_tile_t * topo_shred_tile = &config->topo.tiles[ topo_shred_tile_idx ];
  fd_shred_ctx_t * shred_ctx       = fd_topo_obj_laddr( &config->topo, topo_shred_tile->tile_obj_id );
  FD_TEST( shred_ctx );

  ulong net_link_idx = fd_topo_find_link( &config->topo, "net_shred", 0UL );
  FD_TEST( net_link_idx!=ULONG_MAX );
  fd_topo_link_t * net_link      = &config->topo.links[ net_link_idx ];
  void *           net_link_base = fd_wksp_containing( net_link->dcache );
  ulong net_seq = 0UL;
  fd_frag_meta_t * net_mcache = net_link->mcache;
  ulong const net_depth  = fd_mcache_depth( net_mcache );
  ulong const net_chunk0 = fd_dcache_compact_chunk0( net_link_base, net_link->dcache );
  ulong const net_wmark  = fd_dcache_compact_wmark ( net_link_base, net_link->dcache, FD_NET_MTU );
  ulong       net_chunk  = net_chunk0;

  /* [tile-unit-test] before_frag .*/
  for( ulong i=0; i<4; i++ ) {
    FD_LOG_NOTICE(( "before_frag test %lu", i ));
    struct {
      fd_eth_hdr_t eth;
      fd_ip4_hdr_t ip4;
      fd_udp_hdr_t udp;
      uchar        data[ 22 ];
    } const rx_pkt_templ = {
      .eth = {
        .net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ),
      },
      .ip4 = {
        .verihl      = FD_IP4_VERIHL( 4, 5 ),
        .protocol    = FD_IP4_HDR_PROTOCOL_UDP,
        .net_tot_len = fd_ushort_bswap( 28 )
      },
      .udp = {
        .net_len   = fd_ushort_bswap( 8 ),
        .net_dport = fd_ushort_bswap( topo_shred_tile->shred.shred_listen_port )
      },
      .data = { 0xFF, 0xFF, (uchar)i }
    };
    fd_memcpy( fd_chunk_to_laddr( net_link_base, net_chunk ), &rx_pkt_templ, sizeof(rx_pkt_templ) );
    ulong sig = fd_disco_netmux_sig( 0, 0, 0, DST_PROTO_SHRED, 42 );
    fd_mcache_publish( net_mcache, net_depth, net_seq, sig, net_chunk, sizeof(rx_pkt_templ), 0, 0, 0 );
    ulong const net_in_idx = fd_topo_find_tile_in_link( &config->topo, topo_shred_tile, "net_shred", 0UL );
    FD_TEST( net_in_idx!=ULONG_MAX );
    FD_TEST( 0==before_frag( shred_ctx, net_in_idx, net_seq, sig ) ); /* accepted */
    net_seq   = fd_seq_inc( net_seq, 1UL );
    net_chunk = fd_dcache_compact_next( net_chunk, sizeof(rx_pkt_templ), net_chunk0, net_wmark );
  }

  /* Tear down tile-unit-test. */
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

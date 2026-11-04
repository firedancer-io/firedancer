#include "commands/configure/iavf.c"
#include "../../util/net/fd_ip4.h"

char const * FD_APP_NAME    = "test_iavf_configure";
char const * FD_BINARY_NAME = "test_iavf_configure";
configure_stage_t *  STAGES[]  = { &fd_cfg_stage_iavf, NULL };
action_t *          ACTIONS[] = { NULL };
fd_topo_run_tile_t * TILES[]   = { NULL };

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  static fd_config_t config;
  config.net.bind_address_parsed = FD_IP4_ADDR( 192, 0, 2, 1 );
  struct ethtool_rx_flow_spec rule = iavf_pf_ntuple_drop_rule_build( &config, 9000, 1U );
  struct ethtool_rx_flow_spec readback = rule;
  FD_TEST( iavf_pf_ntuple_rule_equal( &rule, &readback ) );

  /* i40e fills the unused IPv6 destination mask during IPv4 rule readback */
  memset( readback.m_u.udp_ip6_spec.ip6dst, 0xff, sizeof(readback.m_u.udp_ip6_spec.ip6dst) );
  FD_TEST( iavf_pf_ntuple_rule_equal( &rule, &readback ) );
  FD_TEST( iavf_pf_ntuple_rule_equal( &readback, &rule ) );

  readback.h_u.udp_ip4_spec.ip4dst ^= 1U;
  FD_TEST( !iavf_pf_ntuple_rule_equal( &rule, &readback ) );
  readback.h_u = rule.h_u;
  readback.m_u.udp_ip4_spec.pdst = 0U;
  FD_TEST( !iavf_pf_ntuple_rule_equal( &rule, &readback ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
}

#include "fd_config_auto.c" /* fd_auto_net is static */

/* Test the auto config resolution policy with hand built system
   info.  The scrape functions (uname, sysfs, bonding) are not
   covered here. */

static fd_config_t config[1];

static void
reset_auto( uint net_tile_cnt ) {
  memset( config, 0, sizeof(fd_config_t) );
  strcpy( config->net.provider,           "xdp"  );
  strcpy( config->net.xdp.xdp_mode,       "auto" );
  strcpy( config->net.xdp.poll_mode,      "auto" );
  strcpy( config->net.xdp.rss_queue_mode, "auto" );
  config->net.xdp.xdp_zero_copy = 2;
  config->net.xdp.native_bond   = 2;
  config->net.xdp.listen_gre    = 2;
  config->layout.net_tile_count = net_tile_cnt;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Supported NIC on a recent kernel */

  reset_auto( 1U );
  fd_auto_info_t info1 = { .linux_major=7, .linux_minor=0, .driver="mlx5_core" };
  fd_auto_net( config, &info1 );
  FD_TEST( 0==strcmp( config->net.xdp.xdp_mode,  "drv"      ) );
  FD_TEST( 0==strcmp( config->net.xdp.poll_mode, "prefbusy" ) );
  FD_TEST( 0==strcmp( config->net.xdp.rss_queue_mode, "auto" ) );
  FD_TEST( config->net.xdp.xdp_zero_copy==1 );
  FD_TEST( config->net.xdp.native_bond  ==0 );
  FD_TEST( config->net.xdp.listen_gre   ==0 );

  /* Unsupported NIC falls back to safe defaults */

  reset_auto( 1U );
  fd_auto_info_t info2 = { .linux_major=7, .linux_minor=0, .driver="ixgbe" };
  fd_auto_net( config, &info2 );
  FD_TEST( 0==strcmp( config->net.xdp.xdp_mode,  "skb"     ) );
  FD_TEST( 0==strcmp( config->net.xdp.poll_mode, "softirq" ) );
  FD_TEST( 0==strcmp( config->net.xdp.rss_queue_mode, "auto" ) );
  FD_TEST( config->net.xdp.xdp_zero_copy==0 );
  FD_TEST( config->net.xdp.native_bond  ==0 );
  FD_TEST( config->net.xdp.listen_gre   ==0 );

  /* An UP GRE interface enables GRE.  mlx5 supports GRE ntuple
     rules while an unsupported driver falls back to simple queue mode. */

  reset_auto( 1U );
  fd_auto_info_t info_gre_mlx5 = info1;
  info_gre_mlx5.is_using_gre = 1;
  fd_auto_net( config, &info_gre_mlx5 );
  FD_TEST( config->net.xdp.listen_gre==1 );
  FD_TEST( 0==strcmp( config->net.xdp.rss_queue_mode, "auto" ) );

  reset_auto( 1U );
  fd_auto_info_t info_gre_ixgbe = info2;
  info_gre_ixgbe.is_using_gre = 1;
  fd_auto_net( config, &info_gre_ixgbe );
  FD_TEST( config->net.xdp.listen_gre==1 );
  FD_TEST( 0==strcmp( config->net.xdp.rss_queue_mode, "simple" ) );

  /* Explicit values are not changed by auto configuration. */

  reset_auto( 1U );
  config->net.xdp.listen_gre = 0;
  strcpy( config->net.xdp.rss_queue_mode, "dedicated" );
  fd_auto_net( config, &info_gre_mlx5 );
  FD_TEST( config->net.xdp.listen_gre==0 );
  FD_TEST( 0==strcmp( config->net.xdp.rss_queue_mode, "dedicated" ) );

  /* Supported NIC on an old kernel falls back to safe defaults */

  reset_auto( 4U );
  fd_auto_info_t info3 = { .linux_major=1, .linux_minor=0, .driver="mlx5_core",
                           .is_virtual_if=1, .is_bonded_if=1, .bonded_if_slave_count=2U };
  fd_auto_net( config, &info3 );
  FD_TEST( 0==strcmp( config->net.xdp.xdp_mode,  "skb"     ) );
  FD_TEST( 0==strcmp( config->net.xdp.poll_mode, "softirq" ) );
  FD_TEST( 0==strcmp( config->net.xdp.rss_queue_mode, "auto" ) );
  FD_TEST( config->net.xdp.xdp_zero_copy==0 );
  FD_TEST( config->net.xdp.native_bond  ==0 );
  FD_TEST( config->net.xdp.listen_gre   ==0 );

  /* Bonded mlx5 on a recent kernel enables native bond and drv */

  reset_auto( 4U );
  fd_auto_info_t info4 = info3;
  info4.linux_major = 7;
  info4.linux_minor = 0;
  fd_auto_net( config, &info4 );
  FD_TEST( config->net.xdp.native_bond==1 );
  FD_TEST( 0==strcmp( config->net.xdp.xdp_mode, "drv" ) );
  FD_TEST( 0==strcmp( config->net.xdp.rss_queue_mode, "auto" ) );
  FD_TEST( config->net.xdp.xdp_zero_copy==1 );
  FD_TEST( config->net.xdp.listen_gre==0 );

  /* Non XDP provider still collapses "auto" fields to defaults */

  reset_auto( 1U );
  strcpy( config->net.provider, "socket" );
  fd_auto_net( config, &info1 );
  FD_TEST( 0==strcmp( config->net.xdp.xdp_mode,  "skb"     ) );
  FD_TEST( 0==strcmp( config->net.xdp.poll_mode, "softirq" ) );
  FD_TEST( 0==strcmp( config->net.xdp.rss_queue_mode, "simple" ) );
  FD_TEST( config->net.xdp.xdp_zero_copy==0 );
  FD_TEST( config->net.xdp.native_bond  ==0 );
  FD_TEST( config->net.xdp.listen_gre   ==0 );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
}

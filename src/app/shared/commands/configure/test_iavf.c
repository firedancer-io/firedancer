#define fd_cfg_stage_iavf fd_cfg_stage_iavf_test
#include "iavf.c"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  uchar mac[ 6 ];
  FD_TEST( !iavf_parse_mac( "52:14:b4:4a:43:27", mac ) );
  FD_TEST( mac[0]==0x52U && mac[1]==0x14U && mac[2]==0xb4U );
  FD_TEST( mac[3]==0x4aU && mac[4]==0x43U && mac[5]==0x27U );
  FD_TEST( iavf_parse_mac( "52:14:b4:4a:43",    mac ) );
  FD_TEST( iavf_parse_mac( "52:14:b4:4a:43:zz", mac ) );
  FD_TEST( iavf_parse_mac( "01:14:b4:4a:43:27", mac ) );
  FD_TEST( iavf_parse_mac( "00:00:00:00:00:00", mac ) );

  iavf_netlink_req_t req = {
    .nlh.nlmsg_len = NLMSG_LENGTH( sizeof(struct ifinfomsg) ),
  };
  struct rtattr * list = iavf_rta_nest_start( &req.nlh, sizeof(req), IFLA_VFINFO_LIST );
  struct rtattr * info = iavf_rta_nest_start( &req.nlh, sizeof(req), IFLA_VF_INFO );
  FD_TEST( list && info );
  struct ifla_vf_mac vf_mac = { .vf = 0U };
  fd_memcpy( vf_mac.mac, "\x52\x14\xb4\x4a\x43\x27", 6UL );
  struct ifla_vf_spoofchk spoofchk = { .vf = 0U, .setting = 0U };
  struct ifla_vf_trust trust = { .vf = 0U, .setting = 0U };
  struct ifla_vf_link_state link_state = { .vf = 0U, .link_state = IFLA_VF_LINK_STATE_AUTO };
  FD_TEST( !iavf_rta_add( &req.nlh, sizeof(req), IFLA_VF_MAC,        &vf_mac,     sizeof(vf_mac)     ) );
  FD_TEST( !iavf_rta_add( &req.nlh, sizeof(req), IFLA_VF_SPOOFCHK,   &spoofchk,   sizeof(spoofchk)   ) );
  FD_TEST( !iavf_rta_add( &req.nlh, sizeof(req), IFLA_VF_TRUST,      &trust,      sizeof(trust)      ) );
  FD_TEST( !iavf_rta_add( &req.nlh, sizeof(req), IFLA_VF_LINK_STATE, &link_state, sizeof(link_state) ) );
  iavf_rta_nest_end( &req.nlh, info );
  iavf_rta_nest_end( &req.nlh, list );

  iavf_vf_policy_t policy[ 1 ];
  fd_memset( policy, 0, sizeof(policy) );
  iavf_policy_parse_info( info, 0U, policy );
  FD_TEST( policy->mac_valid && !memcmp( policy->mac, vf_mac.mac, 6UL ) );
  FD_TEST( policy->spoofchk_valid && policy->spoofchk==0 );
  FD_TEST( policy->trust_valid && policy->trust==0 );
  FD_TEST( policy->link_state_valid && policy->link_state==IFLA_VF_LINK_STATE_AUTO );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

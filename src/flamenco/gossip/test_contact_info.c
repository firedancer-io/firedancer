#include "../../util/fd_util.h"
#include "../../util/net/fd_net_headers.h"
#include "fd_contact_info.h"

void
test_init(void){
  fd_contact_info_t contact_info;
  fd_contact_info_init( &contact_info );

  FD_TEST( contact_info.ci_crd.addrs == contact_info.addrs );
  FD_TEST( contact_info.ci_crd.sockets == contact_info.sockets );
  FD_TEST( contact_info.ci_crd.extensions == NULL );

  FD_TEST( contact_info.ci_crd.addrs_len == 0U );
  FD_TEST( contact_info.ci_crd.sockets_len == 0U );
  FD_TEST( contact_info.ci_crd.extensions_len == 0U );

  FD_TEST( contact_info.socket_tag_idx[0] == FD_CONTACT_INFO_SOCKET_TAG_NULL );
}

void
test_insertion(void){
  fd_contact_info_t contact_info;
  fd_contact_info_init( &contact_info );

  fd_gossip_peer_addr_t peer = { .addr = 0x01020304, .port = 1234 };

  FD_TEST( fd_contact_info_insert_socket( &contact_info, &peer, FD_GOSSIP_SOCKET_TAG_GOSSIP )==0 );
  FD_TEST( contact_info.ci_crd.addrs_len == 1U );
  FD_TEST( contact_info.ci_crd.sockets_len == 1U );
  FD_TEST( contact_info.ci_crd.addrs[0].inner.ip4 == peer.addr );
  FD_TEST( contact_info.ci_crd.sockets[0].key == FD_GOSSIP_SOCKET_TAG_GOSSIP );
  FD_TEST( contact_info.ci_crd.sockets[0].offset == 1234 );
  FD_TEST( contact_info.ci_crd.sockets[0].index == 0U );
  FD_TEST( contact_info.socket_tag_idx[FD_GOSSIP_SOCKET_TAG_GOSSIP] == 0U );
  FD_TEST( contact_info.ports[0] == 1234 );

  // Insert again, check that the socket is overwritten
  peer.port = 5678;
  FD_TEST( fd_contact_info_insert_socket( &contact_info, &peer, FD_GOSSIP_SOCKET_TAG_GOSSIP )==0 );
  FD_TEST( contact_info.ci_crd.addrs_len == 1U );
  FD_TEST( contact_info.ci_crd.sockets_len == 1U );
  FD_TEST( contact_info.ci_crd.addrs[0].inner.ip4 == peer.addr );
  FD_TEST( contact_info.ci_crd.sockets[0].key == FD_GOSSIP_SOCKET_TAG_GOSSIP );
  FD_TEST( contact_info.ci_crd.sockets[0].offset == 5678 );
  FD_TEST( contact_info.ci_crd.sockets[0].index == 0U );
  FD_TEST( contact_info.socket_tag_idx[FD_GOSSIP_SOCKET_TAG_GOSSIP] == 0U );
  FD_TEST( contact_info.ports[0] == 5678 );

  // Insert a new socket + new addr
  peer.addr = 0x05060708;
  peer.port = 1234;
  FD_TEST( fd_contact_info_insert_socket( &contact_info, &peer, FD_GOSSIP_SOCKET_TAG_TPU )==0 );
  FD_TEST( contact_info.ci_crd.addrs_len == 2U );
  FD_TEST( contact_info.ci_crd.sockets_len == 2U );
  FD_TEST( contact_info.ci_crd.addrs[1].inner.ip4 == peer.addr );
  FD_TEST( contact_info.ci_crd.sockets[0].key == FD_GOSSIP_SOCKET_TAG_TPU );
  FD_TEST( contact_info.ci_crd.sockets[0].offset == 1234 );
  FD_TEST( contact_info.ci_crd.sockets[0].index == 1U );
  FD_TEST( contact_info.socket_tag_idx[FD_GOSSIP_SOCKET_TAG_TPU] == 0U );
  FD_TEST( contact_info.ports[0] == 1234 );
  FD_TEST( contact_info.socket_tag_idx[FD_GOSSIP_SOCKET_TAG_TPU] == 0U );

  /* Check that gossip socket entry has been approprirately moved */
  FD_TEST( contact_info.socket_tag_idx[FD_GOSSIP_SOCKET_TAG_GOSSIP] == 1U );
  FD_TEST( contact_info.ci_crd.sockets[1].key == FD_GOSSIP_SOCKET_TAG_GOSSIP );
  FD_TEST( contact_info.ci_crd.sockets[1].offset == ( 5678 - 1234 ) );
  FD_TEST( contact_info.ci_crd.sockets[1].index == 0U );
  FD_TEST( contact_info.ports[1] == 5678 );
  FD_TEST( contact_info.socket_tag_idx[FD_GOSSIP_SOCKET_TAG_GOSSIP] == 1U );

  // Insert a new socket + existing addr
  peer.addr = 0x01020304;
  peer.port = 5679;
  FD_TEST( fd_contact_info_insert_socket( &contact_info, &peer, FD_GOSSIP_SOCKET_TAG_TVU )==0 );
  FD_TEST( contact_info.ci_crd.addrs_len == 2U );
  FD_TEST( contact_info.ci_crd.sockets_len == 3U );
  FD_TEST( contact_info.ci_crd.addrs[0].inner.ip4 == peer.addr );
  FD_TEST( contact_info.ci_crd.sockets[2].key == FD_GOSSIP_SOCKET_TAG_TVU );
  FD_TEST( contact_info.ci_crd.sockets[2].offset == 1 /* 5679 - 5678 */ );
  FD_TEST( contact_info.ports[2] == 5679 );
  FD_TEST( contact_info.ci_crd.sockets[2].index == 0U );
  FD_TEST( contact_info.socket_tag_idx[FD_GOSSIP_SOCKET_TAG_TVU] == 2U );
  FD_TEST( contact_info.socket_tag_idx[FD_GOSSIP_SOCKET_TAG_GOSSIP] == 1U );
  FD_TEST( contact_info.socket_tag_idx[FD_GOSSIP_SOCKET_TAG_TPU] == 0U );

  // Overwrite an existing socket, check for ip addr drop
  peer.addr = 0x01020304;
  peer.port = 1234;

  FD_TEST( fd_contact_info_insert_socket( &contact_info, &peer, FD_GOSSIP_SOCKET_TAG_TPU )==0 );
  FD_TEST( contact_info.ci_crd.addrs_len == 1U );
  FD_TEST( contact_info.addrs[0].inner.ip4 == peer.addr );
}

void
test_ci_v2_conversion(void){
  /* We simulate setting up a fd_gossip_contact_info_v2_t using
     a fd_contact_info_t and directly modifying relevant fields
     instead of using the API. */
  fd_contact_info_t reference;
  fd_contact_info_init( &reference );

  fd_contact_info_t contact_info;
  fd_contact_info_init( &contact_info );

  /* Info with a single entry (inserted) */
  fd_gossip_socket_entry_t * skts = reference.sockets;
  fd_gossip_ip_addr_t * addrs = reference.addrs;

  skts[0].key = FD_GOSSIP_SOCKET_TAG_GOSSIP;
  skts[0].offset = 1234;
  skts[0].index = 0U;
  reference.ci_crd.sockets_len++;

  fd_gossip_ip_addr_new_disc( &addrs[0], fd_gossip_ip_addr_enum_ip4 );
  addrs[0].inner.ip4 = 0x01020304;
  reference.ci_crd.addrs_len++;

  fd_contact_info_from_ci_v2( &reference.ci_crd, &contact_info );
  FD_TEST( contact_info.ci_crd.addrs_len == 1U );
  FD_TEST( contact_info.ci_crd.sockets_len == 1U );
  FD_TEST( contact_info.ports[0] == 1234 );
  FD_TEST( contact_info.socket_tag_idx[FD_GOSSIP_SOCKET_TAG_GOSSIP] == 0U );

  /* Add second socket entry (inserted) */
  skts[1].key = FD_GOSSIP_SOCKET_TAG_TPU;
  skts[1].offset = 5;
  skts[1].index = 0U;
  reference.ci_crd.sockets_len++;

  fd_contact_info_from_ci_v2( &reference.ci_crd, &contact_info );
  FD_TEST( contact_info.ci_crd.addrs_len == 1U );
  FD_TEST( contact_info.ci_crd.sockets_len == 2U );
  FD_TEST( contact_info.ports[0] == 1234 );
  FD_TEST( contact_info.ports[1] == 1239 );
  FD_TEST( contact_info.socket_tag_idx[FD_GOSSIP_SOCKET_TAG_GOSSIP] == 0U );
  FD_TEST( contact_info.socket_tag_idx[FD_GOSSIP_SOCKET_TAG_TPU] == 1U );

  /* Third socket entry, duplicate socket_tag (not inserted) */
  skts[2].key = FD_GOSSIP_SOCKET_TAG_TPU;
  skts[2].offset = 6;
  skts[2].index = 0U;
  reference.ci_crd.sockets_len++;

  fd_contact_info_from_ci_v2( &reference.ci_crd, &contact_info );
  FD_TEST( contact_info.ci_crd.addrs_len == 1U );
  FD_TEST( contact_info.ci_crd.sockets_len == 2U );
  FD_TEST( contact_info.ports[0] == 1234 );
  FD_TEST( contact_info.ports[1] == 1239 );
  FD_TEST( contact_info.socket_tag_idx[FD_GOSSIP_SOCKET_TAG_GOSSIP] == 0U );
  FD_TEST( contact_info.socket_tag_idx[FD_GOSSIP_SOCKET_TAG_TPU] == 1U );

  /* Third socket entry, invalid socket_tag (not inserted) */
  skts[2].key = FD_GOSSIP_SOCKET_TAG_MAX;
  skts[2].offset = 6;
  skts[2].index = 0U;

  fd_contact_info_from_ci_v2( &reference.ci_crd, &contact_info );
  FD_TEST( contact_info.ci_crd.addrs_len == 1U );
  FD_TEST( contact_info.ci_crd.sockets_len == 2U );

  /* Third socket entry, invalid addr index (not inserted) */
  skts[2].key = FD_GOSSIP_SOCKET_TAG_TVU;
  skts[2].offset = 6;
  skts[2].index = 1U;

  fd_contact_info_from_ci_v2( &reference.ci_crd, &contact_info );
  FD_TEST( contact_info.ci_crd.addrs_len == 1U );
  FD_TEST( contact_info.ci_crd.sockets_len == 2U );

  /* Fourth entry, offset correctly updated (inserted) */
  skts[3].key = FD_GOSSIP_SOCKET_TAG_SERVE_REPAIR;
  skts[3].offset = 7;
  skts[3].index = 0U;
  reference.ci_crd.sockets_len++;

  fd_contact_info_from_ci_v2( &reference.ci_crd, &contact_info );
  FD_TEST( contact_info.ci_crd.addrs_len == 1U );
  FD_TEST( contact_info.ci_crd.sockets_len == 3U );
  FD_TEST( contact_info.ports[0] == 1234 );
  FD_TEST( contact_info.ports[1] == 1239 );
  FD_TEST( contact_info.ports[2] == 1239+6+7 );
  FD_TEST( contact_info.sockets[2].offset == 6+7 );
  FD_TEST( contact_info.socket_tag_idx[FD_GOSSIP_SOCKET_TAG_SERVE_REPAIR] == 2U );
}

int
main( int argc, char ** argv ){
  fd_boot( &argc, &argv );
  test_init();
  test_insertion();
  test_ci_v2_conversion();
  fd_halt();
  return 0;
}

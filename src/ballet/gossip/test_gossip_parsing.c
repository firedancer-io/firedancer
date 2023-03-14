#include "fd_gossip_msg.h"
#include "fd_gossip_crds.h"
#include <stdlib.h>
#include <stdio.h>

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_IMPORT_BINARY( pull_request, "src/ballet/gossip/fixtures/pull_request.bin" );
  FD_IMPORT_BINARY( pull_response_contact_info, "src/ballet/gossip/fixtures/pull_response_contact_info.bin" );
  FD_IMPORT_BINARY( pull_response_node_instance, "src/ballet/gossip/fixtures/pull_response_node_instance.bin" );
  FD_IMPORT_BINARY( pull_response_snapshot_hashes, "src/ballet/gossip/fixtures/pull_response_snapshot_hashes.bin" );
  FD_IMPORT_BINARY( pull_response_version, "src/ballet/gossip/fixtures/pull_response_version.bin" );
  FD_IMPORT_BINARY( push_vote_message, "src/ballet/gossip/fixtures/push_vote_message.bin" );
  FD_IMPORT_BINARY( ping_message, "src/ballet/gossip/fixtures/ping_message.bin" );
  FD_IMPORT_BINARY( pong_message, "src/ballet/gossip/fixtures/pong_message.bin" );
  
  /* an obviously bad message in the input stream to test that parsing continues
     as normal after discarding a bad message and updating the parse context's state */
  char * bad_message = "\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61";

  uchar *output = malloc( 10*2048 );
  FD_TEST( output );

  uchar * input = malloc( 10*2048 );
  FD_TEST( input );

  /* Setup the gossip payloads in a contiguously packed buffer so as to simulate parsing of
     of a batch of gossip messages recently received over the network */
  uchar * ptr = input;
  memcpy( ptr, pull_request, pull_request_sz );
  ptr += pull_request_sz;
  memcpy( ptr, pull_response_contact_info, pull_response_contact_info_sz );
  ptr += pull_response_contact_info_sz;
  memcpy( ptr, pull_response_node_instance, pull_response_node_instance_sz );
  ptr += pull_response_node_instance_sz;
  memcpy( ptr, bad_message, 16 );
  ptr += 16;
  memcpy( ptr, pull_response_snapshot_hashes, pull_response_snapshot_hashes_sz );
  ptr += pull_response_snapshot_hashes_sz;
  memcpy( ptr, pull_response_version, pull_response_version_sz );
  ptr += pull_response_version_sz;
  memcpy( ptr, push_vote_message, push_vote_message_sz );
  ptr += push_vote_message_sz;

  fd_gossip_msg_t *msg = NULL;

  fd_bin_parse_ctx_t ctx;
  fd_bin_parse_init( &ctx, (void *)input, (ulong)(ptr - input), output, 10*2048 );

  fd_bin_parse_set_input_blob_size( &ctx, pull_request_sz );
  msg = fd_gossip_parse_msg( &ctx );
  FD_TEST( msg );
  fd_gossip_pretty_print( msg );

  fd_bin_parse_set_input_blob_size( &ctx, pull_response_contact_info_sz );
  msg = fd_gossip_parse_msg( &ctx );
  FD_TEST( msg );
  fd_gossip_pretty_print( msg );

  fd_bin_parse_set_input_blob_size( &ctx, pull_response_node_instance_sz );
  msg = fd_gossip_parse_msg( &ctx );
  FD_TEST( msg );
  fd_gossip_pretty_print( msg );

  fd_bin_parse_set_input_blob_size( &ctx, 16 );
  msg = fd_gossip_parse_msg( &ctx );
  FD_TEST( !msg );
  FD_LOG_WARNING(( "bad msg failed to parse as expected "));

  fd_bin_parse_set_input_blob_size( &ctx, pull_response_snapshot_hashes_sz );
  msg = fd_gossip_parse_msg( &ctx );
  FD_TEST( msg );
  fd_gossip_pretty_print( msg );

  fd_bin_parse_set_input_blob_size( &ctx, pull_response_version_sz );
  msg = fd_gossip_parse_msg( &ctx );
  FD_TEST( msg );
  fd_gossip_pretty_print( msg );

  fd_bin_parse_set_input_blob_size( &ctx, push_vote_message_sz );
  msg = fd_gossip_parse_msg( &ctx );
  FD_TEST( msg );
  fd_gossip_pretty_print( msg );

  /* test ping and pong messages observed via `solana-gossip spy` */
  fd_bin_parse_ctx_t ctx_ping;
  fd_bin_parse_init( &ctx_ping, (void *)ping_message, ping_message_sz, output, 10*2048 );
  fd_bin_parse_set_input_blob_size( &ctx_ping, ping_message_sz );
  msg = fd_gossip_parse_msg( &ctx_ping );
  FD_TEST( msg );
  fd_gossip_pretty_print( msg );

  fd_bin_parse_ctx_t ctx_pong;
  fd_bin_parse_init( &ctx_pong, (void *)pong_message, pong_message_sz, output, 10*2048 );
  fd_bin_parse_set_input_blob_size( &ctx_pong, pong_message_sz );
  msg = fd_gossip_parse_msg( &ctx_pong );
  FD_TEST( msg );
  fd_gossip_pretty_print( msg );

  FD_IMPORT_BINARY( gossip_msg_0, "src/ballet/gossip/fixtures/gossip_msg_0.bin" );
  FD_IMPORT_BINARY( gossip_msg_1, "src/ballet/gossip/fixtures/gossip_msg_1.bin" );
  FD_IMPORT_BINARY( gossip_msg_2, "src/ballet/gossip/fixtures/gossip_msg_2.bin" );
  FD_IMPORT_BINARY( gossip_msg_3, "src/ballet/gossip/fixtures/gossip_msg_3.bin" );
  FD_IMPORT_BINARY( gossip_msg_4, "src/ballet/gossip/fixtures/gossip_msg_4.bin" );
  FD_IMPORT_BINARY( gossip_msg_5, "src/ballet/gossip/fixtures/gossip_msg_5.bin" );
  FD_IMPORT_BINARY( gossip_msg_6, "src/ballet/gossip/fixtures/gossip_msg_6.bin" );
  FD_IMPORT_BINARY( gossip_msg_7, "src/ballet/gossip/fixtures/gossip_msg_7.bin" );
  FD_IMPORT_BINARY( gossip_msg_8, "src/ballet/gossip/fixtures/gossip_msg_8.bin" );
  FD_IMPORT_BINARY( gossip_msg_9, "src/ballet/gossip/fixtures/gossip_msg_9.bin" );
  FD_IMPORT_BINARY( gossip_msg_10, "src/ballet/gossip/fixtures/gossip_msg_10.bin" );
  
  fd_bin_parse_ctx_t ctx_additional;
  fd_bin_parse_init( &ctx_additional, (void *)gossip_msg_0, gossip_msg_0_sz, output, 10*2048 );
  fd_bin_parse_set_input_blob_size( &ctx_additional, gossip_msg_0_sz );
  msg = fd_gossip_parse_msg( &ctx_additional );
  FD_TEST( msg );
  fd_gossip_pretty_print( msg );

  fd_bin_parse_init( &ctx_additional, (void *)gossip_msg_1, gossip_msg_1_sz, output, 10*2048 );
  fd_bin_parse_set_input_blob_size( &ctx_additional, gossip_msg_1_sz );
  msg = fd_gossip_parse_msg( &ctx_additional );
  FD_TEST( msg );
  fd_gossip_pretty_print( msg );

  fd_bin_parse_init( &ctx_additional, (void *)gossip_msg_2, gossip_msg_2_sz, output, 10*2048 );
  fd_bin_parse_set_input_blob_size( &ctx_additional, gossip_msg_2_sz );
  msg = fd_gossip_parse_msg( &ctx_additional );
  FD_TEST( msg );
  fd_gossip_pretty_print( msg );

  fd_bin_parse_init( &ctx_additional, (void *)gossip_msg_3, gossip_msg_3_sz, output, 10*2048 );
  fd_bin_parse_set_input_blob_size( &ctx_additional, gossip_msg_3_sz );
  msg = fd_gossip_parse_msg( &ctx_additional );
  FD_TEST( msg );
  fd_gossip_pretty_print( msg );

  fd_bin_parse_init( &ctx_additional, (void *)gossip_msg_4, gossip_msg_4_sz, output, 10*2048 );
  fd_bin_parse_set_input_blob_size( &ctx_additional, gossip_msg_4_sz );
  msg = fd_gossip_parse_msg( &ctx_additional );
  FD_TEST( msg );
  fd_gossip_pretty_print( msg );

  fd_bin_parse_init( &ctx_additional, (void *)gossip_msg_5, gossip_msg_5_sz, output, 10*2048 );
  fd_bin_parse_set_input_blob_size( &ctx_additional, gossip_msg_5_sz );
  msg = fd_gossip_parse_msg( &ctx_additional );
  FD_TEST( msg );
  fd_gossip_pretty_print( msg );

  fd_bin_parse_init( &ctx_additional, (void *)gossip_msg_6, gossip_msg_6_sz, output, 10*2048 );
  fd_bin_parse_set_input_blob_size( &ctx_additional, gossip_msg_6_sz );
  msg = fd_gossip_parse_msg( &ctx_additional );
  FD_TEST( msg );
  fd_gossip_pretty_print( msg );

  fd_bin_parse_init( &ctx_additional, (void *)gossip_msg_7, gossip_msg_7_sz, output, 10*2048 );
  fd_bin_parse_set_input_blob_size( &ctx_additional, gossip_msg_7_sz );
  msg = fd_gossip_parse_msg( &ctx_additional );
  FD_TEST( msg );
  fd_gossip_pretty_print( msg );

  fd_bin_parse_init( &ctx_additional, (void *)gossip_msg_8, gossip_msg_8_sz, output, 10*2048 );
  fd_bin_parse_set_input_blob_size( &ctx_additional, gossip_msg_8_sz );
  msg = fd_gossip_parse_msg( &ctx_additional );
  FD_TEST( msg );
  fd_gossip_pretty_print( msg );

  fd_bin_parse_init( &ctx_additional, (void *)gossip_msg_9, gossip_msg_9_sz, output, 10*2048 );
  fd_bin_parse_set_input_blob_size( &ctx_additional, gossip_msg_9_sz );
  msg = fd_gossip_parse_msg( &ctx_additional );
  FD_TEST( msg );
  fd_gossip_pretty_print( msg );

  fd_bin_parse_init( &ctx_additional, (void *)gossip_msg_10, gossip_msg_10_sz, output, 10*2048 );
  fd_bin_parse_set_input_blob_size( &ctx_additional, gossip_msg_10_sz );
  msg = fd_gossip_parse_msg( &ctx_additional );
  FD_TEST( msg );
  fd_gossip_pretty_print( msg );

  /* Parse & pretty-print some ContactInfo CRDS objects. These are 'new' ContactInfo
     objects, rather than the existing ContactInfo objects that are now called
     LegacyContactInfo. Because the new ContactInfo object is not in use on any
     public Solana cluster yet, these are included to exercise this code path separately.
     for the same reason, these samples were generated by hacking on a testcase present in the 
     Solana validator rather than being full gossip messages seen pn the wire. */
  FD_IMPORT_BINARY( contact_info_crds_1, "src/ballet/gossip/fixtures/contact_info_crds_1.bin" );
  FD_IMPORT_BINARY( contact_info_crds_2, "src/ballet/gossip/fixtures/contact_info_crds_2.bin" );
  FD_IMPORT_BINARY( contact_info_crds_3, "src/ballet/gossip/fixtures/contact_info_crds_3.bin" );
  FD_IMPORT_BINARY( contact_info_crds_4, "src/ballet/gossip/fixtures/contact_info_crds_4.bin" );
  FD_IMPORT_BINARY( contact_info_crds_5, "src/ballet/gossip/fixtures/contact_info_crds_5.bin" );
  FD_IMPORT_BINARY( contact_info_crds_6, "src/ballet/gossip/fixtures/contact_info_crds_6.bin" );
  FD_IMPORT_BINARY( contact_info_crds_7, "src/ballet/gossip/fixtures/contact_info_crds_7.bin" );
  FD_IMPORT_BINARY( contact_info_crds_8, "src/ballet/gossip/fixtures/contact_info_crds_8.bin" );

  fd_bin_parse_ctx_t ctx_ci;
  ulong out_sz = 0;

  fd_bin_parse_init( &ctx_ci, (void *)contact_info_crds_1, contact_info_crds_1_sz, output, 10*2048 );
  fd_bin_parse_set_input_blob_size( &ctx_ci, contact_info_crds_1_sz );
  FD_TEST( fd_gossip_parse_crds_contact_info( &ctx_ci, output, 10*2048, &out_sz ) );
  fd_gossip_pretty_print_crds_object( output );

  fd_bin_parse_init( &ctx_ci, (void *)contact_info_crds_2, contact_info_crds_2_sz, output, 10*2048 );
  fd_bin_parse_set_input_blob_size( &ctx_ci, contact_info_crds_2_sz );
  FD_TEST( fd_gossip_parse_crds_contact_info( &ctx_ci, output, 10*2048, &out_sz ) );
  fd_gossip_pretty_print_crds_object( output );

  fd_bin_parse_init( &ctx_ci, (void *)contact_info_crds_3, contact_info_crds_3_sz, output, 10*2048 );
  fd_bin_parse_set_input_blob_size( &ctx_ci, contact_info_crds_3_sz );
  FD_TEST( fd_gossip_parse_crds_contact_info( &ctx_ci, output, 10*2048, &out_sz ) );
  fd_gossip_pretty_print_crds_object( output );

  fd_bin_parse_init( &ctx_ci, (void *)contact_info_crds_4, contact_info_crds_4_sz, output, 10*2048 );
  fd_bin_parse_set_input_blob_size( &ctx_ci, contact_info_crds_4_sz );
  FD_TEST( fd_gossip_parse_crds_contact_info( &ctx_ci, output, 10*2048, &out_sz ) );
  fd_gossip_pretty_print_crds_object( output );

  fd_bin_parse_init( &ctx_ci, (void *)contact_info_crds_5, contact_info_crds_5_sz, output, 10*2048 );
  fd_bin_parse_set_input_blob_size( &ctx_ci, contact_info_crds_5_sz );
  FD_TEST( fd_gossip_parse_crds_contact_info( &ctx_ci, output, 10*2048, &out_sz ) );
  fd_gossip_pretty_print_crds_object( output );

  fd_bin_parse_init( &ctx_ci, (void *)contact_info_crds_6, contact_info_crds_6_sz, output, 10*2048 );
  fd_bin_parse_set_input_blob_size( &ctx_ci, contact_info_crds_6_sz );
  FD_TEST( fd_gossip_parse_crds_contact_info( &ctx_ci, (void *)output, 10*2048, &out_sz ) );
  fd_gossip_pretty_print_crds_object( output );

  fd_bin_parse_init( &ctx_ci, (void *)contact_info_crds_7, contact_info_crds_7_sz, output, 10*2048 );
  fd_bin_parse_set_input_blob_size( &ctx_ci, contact_info_crds_7_sz );
  FD_TEST( fd_gossip_parse_crds_contact_info( &ctx_ci, output, 10*2048, &out_sz ) );
  fd_gossip_pretty_print_crds_object( output );

  fd_bin_parse_init( &ctx_ci, (void *)contact_info_crds_8, contact_info_crds_8_sz, output, 10*2048 );
  fd_bin_parse_set_input_blob_size( &ctx_ci, contact_info_crds_8_sz );
  FD_TEST( fd_gossip_parse_crds_contact_info( &ctx_ci, output, 10*2048, &out_sz ) );
  fd_gossip_pretty_print_crds_object( output );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

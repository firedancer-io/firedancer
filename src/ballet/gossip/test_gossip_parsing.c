#include "fd_gossip_msg.h"
#include "fd_gossip_crds.h"
#include <stdlib.h>

int main() {

  fd_log_level_stderr_set( 3 );

  FD_IMPORT_BINARY( pull_request, "src/ballet/gossip/fixtures/pull_request.bin" );
  FD_IMPORT_BINARY( pull_response_contact_info, "src/ballet/gossip/fixtures/pull_response_contact_info.bin" );
  FD_IMPORT_BINARY( pull_response_node_instance, "src/ballet/gossip/fixtures/pull_response_node_instance.bin" );
  FD_IMPORT_BINARY( pull_response_snapshot_hashes, "src/ballet/gossip/fixtures/pull_response_snapshot_hashes.bin" );
  FD_IMPORT_BINARY( pull_response_version, "src/ballet/gossip/fixtures/pull_response_version.bin" );
  FD_IMPORT_BINARY( push_vote_message, "src/ballet/gossip/fixtures/push_vote_message.bin" );
  
  /* an obviously bad message in the input stream to test that parsing continues
     as normal after discarding a bad message and updating the parse context's state */
  char * bad_message = "\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61";

  uchar *output = malloc( 1000000 );
  FD_TEST( output );

  /* Setup the gossip payloads in a contiguously packed buffer so as to simulate parsing of
     of a batch of gossip messages recently received over the network */
  uchar * input = malloc(1000000);
  FD_TEST( input );

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
  fd_bin_parse_init( &ctx, (void *)input, (ulong)(ptr - input), output, 1000000 );

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

  fd_bin_parse_set_input_blob_size( &ctx, 16 );  /* parse an obviously invalid msg */
  msg = fd_gossip_parse_msg( &ctx );

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

  return 0;
}
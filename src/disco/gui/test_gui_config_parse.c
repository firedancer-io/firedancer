#include "fd_gui_config_parse.h"
#include "fd_gui_peers.h"
#include "../../waltz/http/fd_http_server_private.h"

#include "../../util/fd_util.h"

#include <stdlib.h>

/* Builds a ConfigProgram account: ConfigKeys of length 2 with the
   Va1idator1nfo key first and the identity second, then the bincode
   length-prefixed JSON.  Returns the account size. */

static ulong
build_account( uchar *      out,
               ulong        out_sz,
               uchar        identity_is_signer,
               char const * json ) {
  static uchar const validator_info_key[ 32UL ] = { 0x07, 0x51, 0x97, 0x01, 0x74, 0x48, 0xf2, 0xac, 0x5d, 0xc2, 0x3c, 0x9e, 0xbc, 0x7a, 0xc7, 0x8c, 0x0a, 0x27, 0x25, 0x7a, 0xc6, 0x14, 0x45, 0x8d, 0xe0, 0xa4, 0xf1, 0x6f, 0x80, 0x00, 0x00, 0x00 };
  ulong json_sz = strlen( json );
  memset( out, 0, out_sz );
  ulong i = 0UL;
  out[ i++ ] = 2;
  memcpy( out+i, validator_info_key, 32UL ); i += 32UL; out[ i++ ] = 0;
  memset( out+i, 0x42, 32UL );              i += 32UL; out[ i++ ] = identity_is_signer;
  FD_STORE( ulong, out+i, json_sz );        i += sizeof(ulong);
  memcpy( out+i, json, json_sz );           i += json_sz;
  FD_TEST( i<=out_sz );
  return out_sz;
}

/* Copies of one identity's account arrive in any order across snapin
   tiles: the newest slot wins whether it is populated or cleared, and a
   cleared copy reads as no info.  Each change to a known peer's info is
   broadcast, so clients see a clear and the info coming back. */

static void
test_newest_copy( void ) {
  fd_http_server_params_t params = { .max_connection_cnt = 1UL, .max_ws_connection_cnt = 1UL, .max_request_len = 1024UL,
                                     .max_ws_recv_frame_len = 2048UL, .max_ws_send_frame_cnt = 100UL, .outgoing_buffer_sz = 1UL<<20 };
  fd_http_server_callbacks_t callbacks = {0};
  void * http_mem = aligned_alloc( fd_http_server_align(), fd_http_server_footprint( params ) );
  fd_http_server_t * http = fd_http_server_join( fd_http_server_new( http_mem, params, callbacks, NULL ) );
  FD_TEST( http );
  void * peers_mem = aligned_alloc( fd_gui_peers_align(), fd_gui_peers_footprint( 1UL ) );
  FD_TEST( peers_mem );

  uchar populated[ 1024UL ], cleared[ 1024UL ];
  ulong psz = build_account( populated, sizeof(populated), 1, "{\"name\":\"alice\"}" );
  ulong csz = build_account( cleared,   sizeof(cleared),   1, "{\"name\":\"\"}" );
  fd_pubkey_t id; memset( id.uc, 0x42, 32UL );

  for( int order=0; order<2; order++ ) {
    fd_gui_peers_ctx_t * peers = fd_gui_peers_join( fd_gui_peers_new( peers_mem, http, NULL, 1UL, "", 0UL, 0L ) );
    FD_TEST( peers );
    if( order ) { fd_gui_peers_handle_config_account( peers, cleared,   csz, 200UL ); fd_gui_peers_handle_config_account( peers, populated, psz, 100UL ); }
    else        { fd_gui_peers_handle_config_account( peers, populated, psz, 100UL ); fd_gui_peers_handle_config_account( peers, cleared,   csz, 200UL ); }
    fd_gui_config_parse_info_t const * info = fd_gui_peers_node_info_map_ele_query_const( peers->node_info_map, &id, NULL, peers->node_info_pool );
    FD_TEST( info && info->slot==200UL && info->cleared );

    /* and a newer populated copy replaces the cleared one in place */
    fd_gui_peers_handle_config_account( peers, populated, psz, 300UL );
    FD_TEST( fd_gui_peers_node_info_map_ele_query_const( peers->node_info_map, &id, NULL, peers->node_info_pool )==info );
    FD_TEST( info->slot==300UL && !info->cleared && !strcmp( info->name, "alice" ) );
    FD_TEST( fd_gui_peers_node_info_pool_used( peers->node_info_pool )==1UL );
  }

  /* a known peer: populated@100, cleared@200, populated@300 each broadcast */
  fd_gui_peers_ctx_t * peers = fd_gui_peers_join( fd_gui_peers_new( peers_mem, http, NULL, 1UL, "", 0UL, 0L ) );
  fd_gui_peers_node_t * peer = &peers->contact_info_table[ 0 ];
  peer->row.valid  = 1;
  peer->row.pubkey = id;
  fd_gui_peers_node_pubkey_map_idx_insert( peers->node_pubkey_map, 0UL, peers->contact_info_table );
  fd_gui_peers_live_table_idx_insert( peers->live_table, 0UL, peers->contact_info_table );
  ulong const * bufs[3] = { (ulong *)populated, (ulong *)cleared, (ulong *)populated };
  ulong         szs [3] = { psz, csz, psz };
  char const *  want[3] = { "alice", "", "alice" };
  for( ulong k=0UL; k<3UL; k++ ) {
    ulong off = http->stage_off;
    fd_gui_peers_handle_config_account( peers, (uchar const *)bufs[ k ], szs[ k ], 100UL*(k+1UL) );
    FD_TEST( http->stage_off>off );
    FD_TEST( !strcmp( peer->row.name, want[ k ] ) );
  }

  free( peers_mem );
  free( fd_http_server_delete( fd_http_server_leave( http ) ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  uchar account[ 1024UL ];
  fd_gui_config_parse_info_t info[1];

  /* signed identity: accepted */
  ulong sz = build_account( account, sizeof(account), 1, "{\"name\":\"alice\",\"website\":\"https://example.com\"}" );
  FD_TEST( fd_gui_config_parse_validator_info( account, sz, info ) );
  FD_TEST( info->pubkey.uc[ 0 ]==0x42 && info->pubkey.uc[ 31 ]==0x42 );
  FD_TEST( !strcmp( info->name, "alice" ) );
  FD_TEST( !strcmp( info->website, "https://example.com" ) );
  FD_TEST( !info->details[ 0 ] );

  /* unsigned identity: anyone could have written it, rejected */
  sz = build_account( account, sizeof(account), 0, "{\"name\":\"spoof\"}" );
  FD_TEST( !fd_gui_config_parse_validator_info( account, sz, info ) );

  /* malformed bool */
  sz = build_account( account, sizeof(account), 2, "{\"name\":\"spoof\"}" );
  FD_TEST( !fd_gui_config_parse_validator_info( account, sz, info ) );

  /* malformed JSON */
  sz = build_account( account, sizeof(account), 1, "{\"name\":" );
  FD_TEST( !fd_gui_config_parse_validator_info( account, sz, info ) );

  test_newest_copy();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

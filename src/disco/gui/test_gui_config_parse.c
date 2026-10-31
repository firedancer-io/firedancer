#define _GNU_SOURCE
#include "fd_gui_config_parse.h"
#include "fd_gui_peers.h"
#include "../../waltz/http/fd_http_server_private.h"

#include "../../util/fd_util.h"
#include "../../flamenco/stakes/fd_vote_stakes.h"

#include <stdlib.h>
#include <sys/mman.h>

static uchar dctx_scratch[ 10UL<<20 ] __attribute__((aligned(128)));
static int   geoip_fd;

extern uchar const dbip_f[]; /* fd_gui_peers.c */
extern ulong const dbip_f_sz;

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
    fd_gui_peers_ctx_t * peers = fd_gui_peers_join( fd_gui_peers_new( peers_mem, http, NULL, dctx_scratch, geoip_fd, 1UL, "", 0UL, 0L ) );
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
  fd_gui_peers_ctx_t * peers = fd_gui_peers_join( fd_gui_peers_new( peers_mem, http, NULL, dctx_scratch, geoip_fd, 1UL, "", 0UL, 0L ) );
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

  /* geoip: tiered lookups match a binary search over the full image
     at block-edge and sampled segment starts, start-1 and random IPs */
  fd_gui_ip_db_t const * db = &peers->dbip;
  ulong f0     = ZSTD_findFrameCompressedSize( dbip_f, dbip_f_sz );
  ulong img_sz = ZSTD_getFrameContentSize( dbip_f, f0 )+ZSTD_getFrameContentSize( dbip_f+f0, dbip_f_sz-f0 );
  uchar * img = aligned_alloc( 16UL, fd_ulong_align_up( img_sz, 16UL ) );
  FD_TEST( img && ZSTD_decompress( img, img_sz, dbip_f, dbip_f_sz )==img_sz );
  uchar const * p = img+8UL+2UL*FD_LOAD( ulong, img );
  ulong city_cnt = FD_LOAD( ulong, p ); p += 8UL;
  for( ulong i=0UL; i<city_cnt; i++ ) p += strlen( (char const *)p )+1UL;
  p = img+fd_ulong_align_up( (ulong)(p-img), 4UL );
  ulong seg_cnt = FD_LOAD( ulong, p ); p += 8UL;
  FD_TEST( seg_cnt==db->seg_cnt && seg_cnt>FD_GUI_GEOIP_BLK_SEGS && city_cnt==db->city_cnt );
  uint  const * seg_start   = (uint const *)p;
  uchar const * seg_country = p+4UL*seg_cnt;
  uint  const * seg_city    = (uint const *)( seg_country+fd_ulong_align_up( seg_cnt, 4UL ) );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 7U, 0UL ) );
  ulong named = 0UL;
  for( ulong i=0UL; i<2UL*seg_cnt+(1UL<<18); i++ ) {
    ulong k = i%seg_cnt;
    if( i<2UL*seg_cnt && k%FD_GUI_GEOIP_BLK_SEGS>1UL && k%FD_GUI_GEOIP_BLK_SEGS<FD_GUI_GEOIP_BLK_SEGS-1UL && k%61UL ) continue;
    uint ip = i<seg_cnt ? seg_start[ k ] : i<2UL*seg_cnt ? seg_start[ k ]-1U : fd_rng_uint( rng );
    ulong lo = 0UL, hi = seg_cnt;
    while( hi-lo>1UL ) { ulong mid = (lo+hi)>>1; if( seg_start[ mid ]<=ip ) lo = mid; else hi = mid; }
    uchar country; uint city;
    fd_gui_peers_geoip_lookup( db, fd_uint_bswap( ip ), &country, &city );
    FD_TEST( country==seg_country[ lo ] && city==seg_city[ lo ] );
    if( city!=UINT_MAX ) {
      FD_TEST( strlen( db->image+db->city_name_off[ city ] )<FD_GUI_GEOIP_MAX_CITY_NAME_SZ );
      named++;
    }
  }
  FD_TEST( named );
  free( img );

  free( peers_mem );
  free( fd_http_server_delete( fd_http_server_leave( http ) ) );
}

/* A ranked peer reads delinquent only once a full window has been
   watched and its last reward cert vote is that far behind. */

static void
test_delinquent( void ) {
  fd_http_server_params_t params = { .max_connection_cnt = 1UL, .max_ws_connection_cnt = 1UL, .max_request_len = 1024UL,
                                     .max_ws_recv_frame_len = 2048UL, .max_ws_send_frame_cnt = 100UL, .outgoing_buffer_sz = 1UL<<20 };
  fd_http_server_callbacks_t callbacks = {0};
  void * http_mem = aligned_alloc( fd_http_server_align(), fd_http_server_footprint( params ) );
  fd_http_server_t * http = fd_http_server_join( fd_http_server_new( http_mem, params, callbacks, NULL ) );
  void * peers_mem = aligned_alloc( fd_gui_peers_align(), fd_gui_peers_footprint( 1UL ) );
  fd_gui_peers_ctx_t * peers = fd_gui_peers_join( fd_gui_peers_new( peers_mem, http, NULL, dctx_scratch, geoip_fd, 1UL, "", 0UL, 0L ) );

  fd_pubkey_t id; memset( id.uc, 0x42, sizeof(fd_pubkey_t) );
  fd_gui_peers_node_t * peer = &peers->contact_info_table[ 0 ];
  memset( &peer->row, 0, sizeof(peer->row) );
  peer->row.country_code_idx = UCHAR_MAX;
  peer->row.city_name_idx    = UINT_MAX;
  peer->row.valid  = 1;
  peer->row.pubkey = id;
  fd_gui_peers_node_pubkey_map_idx_insert( peers->node_pubkey_map, 0UL, peers->contact_info_table );
  fd_gui_peers_live_table_idx_insert( peers->live_table, 0UL, peers->contact_info_table );

  uchar epoch_msg[ FD_EPOCH_INFO_MSG_HEADER_SZ+sizeof(fd_vote_stake_weight_t) ] __attribute__((aligned(alignof(fd_epoch_info_msg_t))));
  memset( epoch_msg, 0, sizeof(epoch_msg) );
  fd_epoch_info_msg_t * epoch_info = (fd_epoch_info_msg_t *)epoch_msg;
  epoch_info->epoch           = 1UL;
  epoch_info->start_slot      = 1000UL;
  epoch_info->staked_vote_cnt = 1UL;
  fd_vote_stake_weight_t * w = fd_epoch_info_msg_stake_weights( epoch_info );
  w->id_key = id; w->stake = 1UL; w->rank = 5;
  fd_gui_peers_handle_epoch_info( peers, epoch_info, 0L );

  static fd_block_footer_t voted, absent; /* zero: no reward certs */
  voted.has_notar_reward_cert = 1;
  fd_bls_set_insert( voted.notar_reward_cert.signer_set, 5UL );

  ulong r0 = 1000UL+FD_NUM_SLOTS_FOR_REWARD;
  fd_gui_peers_handle_slot_completed( peers, r0, 1UL, &voted );
  /* still warming up: no verdict */
  for( ulong s=r0+1UL; s<r0+128UL; s++ ) fd_gui_peers_handle_slot_completed( peers, s, 1UL, &absent );
  FD_TEST( !peer->row.delinquent );
  /* a full window without its vote */
  fd_gui_peers_handle_slot_completed( peers, r0+128UL, 1UL, &absent );
  FD_TEST( peer->row.delinquent );
  /* voting again clears it */
  fd_gui_peers_handle_slot_completed( peers, r0+129UL, 1UL, &voted );
  FD_TEST( !peer->row.delinquent );
  /* dropped from the stake set but still in gossip, signing a stale rank */
  epoch_info->staked_vote_cnt = 0UL; epoch_info->epoch = 3UL; epoch_info->start_slot = 3000UL;
  fd_gui_peers_handle_epoch_info( peers, epoch_info, 0L );
  for( ulong s=3000UL+FD_NUM_SLOTS_FOR_REWARD; s<=3000UL+FD_NUM_SLOTS_FOR_REWARD+128UL; s++ ) fd_gui_peers_handle_slot_completed( peers, s, 3UL, &voted );
  FD_TEST( peer->row.delinquent );
  /* rejoining clears it */
  epoch_info->staked_vote_cnt = 1UL; epoch_info->epoch = 5UL; epoch_info->start_slot = 5000UL;
  fd_gui_peers_handle_epoch_info( peers, epoch_info, 0L );
  for( ulong s=5000UL+FD_NUM_SLOTS_FOR_REWARD; s<=5000UL+FD_NUM_SLOTS_FOR_REWARD+128UL; s++ ) fd_gui_peers_handle_slot_completed( peers, s, 5UL, &voted );
  FD_TEST( !peer->row.delinquent );
  /* unranked peers cannot vote */
  w->rank = FD_VOTE_STAKES_ALPENGLOW_RANK_NULL; epoch_info->epoch = 7UL; epoch_info->start_slot = 7000UL;
  fd_gui_peers_handle_epoch_info( peers, epoch_info, 0L );
  for( ulong s=7000UL+FD_NUM_SLOTS_FOR_REWARD; s<=7000UL+FD_NUM_SLOTS_FOR_REWARD+128UL; s++ ) fd_gui_peers_handle_slot_completed( peers, s, 7UL, &voted );
  FD_TEST( peer->row.delinquent );

  free( peers_mem );
  free( fd_http_server_delete( fd_http_server_leave( http ) ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  geoip_fd = memfd_create( "test_gui_geoip", 0U );
  FD_TEST( geoip_fd>=0 );

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
  test_delinquent();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#include "../fd_quic.h"
#include "fd_quic_test_helpers.h"

/* test_quic_client_flood sends a flood of QUIC INITIAL frames. */

#include <stdlib.h>
#include <stdio.h>

#include "../../../ballet/sha512/fd_sha512.h"
#include "../../../ballet/ed25519/fd_ed25519.h"
#include "../../../waltz/quic/fd_quic_private.h"
#include "../../../util/fd_util.h"
#include "../../../util/net/fd_eth.h"
#include "../../../util/net/fd_ip4.h"

static _Bool g_unreliable;

int
my_stream_rx_cb( fd_quic_conn_t * conn,
                 ulong            stream_id,
                 ulong            offset,
                 uchar const *    data,
                 ulong            data_sz,
                 int              fin ) {
  (void)conn; (void)stream_id; (void)fin;
  FD_LOG_DEBUG(( "received data from peer (size=%lu offset=%lu)", data_sz, offset ));
  FD_LOG_HEXDUMP_DEBUG(( "stream data", data, data_sz ));
  return FD_QUIC_SUCCESS;
}

fd_quic_conn_t * client_conn = NULL;

int client_complete = 0;

/* Client handshake complete */
void my_handshake_complete( fd_quic_conn_t * conn, void * vp_context ) {
  (void)conn;
  (void)vp_context;

  FD_LOG_INFO(( "client handshake complete" ));
  client_complete = 1;
}

/* Connection closed */
void my_connection_closed( fd_quic_conn_t * conn, void * vp_context ) {
  (void)vp_context;

  FD_LOG_INFO(( "client conn closed (code=%u)", conn->reason ));
  client_conn     = NULL;
  client_complete = 1;
}

void
run_quic_client(
  fd_quic_t *               quic,
  fd_quic_udpsock_t const * udpsock,
  uint                      dst_ip,
  ushort                    dst_port,
  uint                      batch_sz ) {

# define MSG_SZ_MIN (1UL)
# define MSG_SZ_MAX (1232UL-64UL-32UL)
# define MSG_SIZE_RANGE (MSG_SZ_MAX - MSG_SZ_MIN + 1UL)
  fd_aio_pkt_info_t batches[MSG_SIZE_RANGE][1];

  do {
    /* Reset locals */
    client_conn     = NULL;
    client_complete = 0;

    quic->cb.conn_hs_complete = my_handshake_complete;
    quic->cb.conn_final       = my_connection_closed;
    quic->cb.stream_rx        = my_stream_rx_cb;

    /* use XSK XDP AIO for QUIC ingress/egress */
    fd_quic_set_aio_net_tx( quic, udpsock->aio );

    FD_TEST( fd_quic_init( quic ) );

    FD_LOG_NOTICE(( "Starting QUIC client" ));

    /* make a connection from client to the server */
    client_conn = fd_quic_connect( quic, dst_ip, dst_port, 0U, 0 );

    /* do general processing */
    while ( !client_complete ) {
      fd_quic_service( quic );
      fd_quic_udpsock_service( udpsock );
    }

    if( !client_conn ) {
      FD_LOG_WARNING(( "QUIC handshake failed" ));
      break;
    }
    FD_LOG_NOTICE(( "QUIC handshake complete" ));

    FD_TEST( client_conn->state == FD_QUIC_CONN_STATE_ACTIVE );

    /* create and sign fake ref message txns */
    /* generate a message for every possible message size, using code from verify_synth_load */
    fd_rng_t _rng[ 1 ];
    uint seed = (uint)fd_tile_id();
    fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
    if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_join failed" ));

    fd_sha512_t _sha[1];
    fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );
    if( FD_UNLIKELY( !sha ) ) FD_LOG_ERR(( "fd_sha512 join failed" ));

    ulong ref_msg_mem_footprint = 0UL;
    for( ulong msg_sz=MSG_SZ_MIN; msg_sz<=MSG_SZ_MAX; msg_sz++ ) ref_msg_mem_footprint += fd_ulong_align_up( msg_sz + 96UL, 128UL );
    uchar * ref_msg_mem = fd_alloca( 128UL, ref_msg_mem_footprint );
    if( FD_UNLIKELY( !ref_msg_mem ) ) FD_LOG_ERR(( "fd_alloc failed" ));

    uchar * ref_msg[ MSG_SZ_MAX - MSG_SZ_MIN + 1UL ];
    for( ulong msg_sz=MSG_SZ_MIN; msg_sz<=MSG_SZ_MAX; msg_sz++ ) {
      /* ref_msg[i] is a pointer to the message with size i */
      ref_msg[ msg_sz - MSG_SZ_MIN ] = ref_msg_mem;
      uchar * public_key = ref_msg_mem;
      uchar * sig        = public_key  + 32UL;
      uchar * msg        = sig         + 64UL;
      ref_msg_mem += fd_ulong_align_up( msg_sz + 96UL, 128UL );

      /* Generate a public_key / private_key pair for this message */
      ulong private_key[4]; for( ulong i=0UL; i<4UL; i++ ) private_key[i] = fd_rng_ulong( rng );
      fd_ed25519_public_from_private( public_key, (uchar *)private_key, sha );

      /* Make a random message */
      for( ulong b=0UL; b<msg_sz; b++ ) msg[b] = fd_rng_uchar( rng );

      /* Sign it */
      fd_ed25519_sign( sig, msg, msg_sz, public_key, (uchar *)private_key, sha );
    }

    /* Sanity check the ref messages verify */
    for( ulong msg_sz=MSG_SZ_MIN; msg_sz<=MSG_SZ_MAX; msg_sz++ ) {
      uchar * public_key = ref_msg[ msg_sz - MSG_SZ_MIN ];
      uchar * sig        = public_key + 32UL;
      uchar * msg        = sig        + 64UL;
      FD_TEST( fd_ed25519_verify( msg, msg_sz, sig, public_key, sha )==FD_ED25519_SUCCESS );
    }

    /* Create the QUIC batches, each with a single message in. */
    for( ulong msg_sz=MSG_SZ_MIN; msg_sz<=MSG_SZ_MAX; msg_sz++ ) {
      batches[msg_sz - MSG_SZ_MIN]->buf = ref_msg[ msg_sz - MSG_SZ_MIN ];
      batches[msg_sz - MSG_SZ_MIN]->buf_sz = (ushort)msg_sz;
    }

    fd_sha512_delete ( fd_sha512_leave( sha    ) );
    fd_rng_delete    ( fd_rng_leave   ( rng    ) );
  } while(0);

  ulong stream_cnt = 0;
  ulong tot_sz     = 0;
  long  t0         = fd_log_wallclock();
  ulong msg_sz     = MSG_SZ_MIN;

  /* Continually send data while we have a valid connection */
  while(1) {
    if( !client_conn ) {
      break;
    }

    fd_quic_service( quic );
    fd_quic_udpsock_service( udpsock );

    /* obtain a free stream */
    for( ulong j = 0; j < batch_sz; ++j ) {
      if( !client_conn ) break;
      fd_quic_stream_t * stream = fd_quic_conn_new_stream( client_conn );
      if( !stream ) break;

      fd_aio_pkt_info_t * chunk = batches[msg_sz - MSG_SZ_MIN];
      int res = fd_quic_stream_send( stream, chunk->buf, chunk->buf_sz, 1 /* fin */ ); /* fin: close stream after sending. last byte of transmission */
      stream_cnt += res==FD_QUIC_SUCCESS;
      tot_sz     += fd_ulong_if( res==FD_QUIC_SUCCESS, chunk->buf_sz, 0 );

      msg_sz++;
      msg_sz = fd_ulong_if( msg_sz>MSG_SZ_MAX, MSG_SZ_MIN, msg_sz );
    }

    long t1 = fd_log_wallclock();
    if( t1 >= t0 ) {
      printf( "streams=%lu sz=%g\n", stream_cnt, (double)tot_sz );
      stream_cnt = 0;
      tot_sz     = 0;
      t0 = t1 + (long)1e9;
    }

    /* Reclaim packet metas */
    if ( g_unreliable ) {
      /* treat all packets as ACKed (freeing handshake data, etc.) */
      static const uint            enc_level  =  fd_quic_enc_level_appdata_id;
      fd_quic_pkt_meta_tracker_t * tracker   =  &client_conn->pkt_meta_tracker;
      fd_quic_pkt_meta_ds_t      * sent       =  &tracker->sent_pkt_metas[enc_level];
      fd_quic_pkt_meta_t         * pool       =  fd_quic_get_state( quic )->pkt_meta_pool;

      fd_quic_pkt_meta_t* prev = NULL;

      for( fd_quic_pkt_meta_ds_fwd_iter_t iter = fd_quic_pkt_meta_ds_fwd_iter_init( sent, pool );
                                                 !fd_quic_pkt_meta_ds_fwd_iter_done( iter );
                                                 iter = fd_quic_pkt_meta_ds_fwd_iter_next( iter, pool ) ) {
        if( FD_LIKELY( prev ) ) {
          fd_quic_pkt_meta_pool_ele_release( pool, prev );
        }
        fd_quic_pkt_meta_t * e = fd_quic_pkt_meta_ds_fwd_iter_ele( iter, pool );
        fd_quic_reclaim_pkt_meta( client_conn, e, enc_level );
        prev = e;
      }
      if( FD_LIKELY( prev ) ) {
        fd_quic_pkt_meta_pool_ele_release( pool, prev );
      }

      fd_quic_pkt_meta_ds_clear( tracker, enc_level );
    }
  }

  do {
    /* close the connections */
    if( client_conn ) {
      fd_quic_conn_close( client_conn, 0 );
      client_conn = NULL;
    }

    fd_quic_fini( quic );

    FD_LOG_NOTICE(( "Finished QUIC client" ));
  } while(0);
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz  = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--page-sz",        NULL, "gigantic"                   );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt",       NULL, 1UL                          );
  ulong        numa_idx  = fd_env_strip_cmdline_ulong ( &argc, &argv, "--numa-idx",       NULL, fd_shmem_numa_idx(cpu_idx)   );
  char const * _dst_ip   = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--dst-ip",         NULL, NULL                         );
  ushort       dst_port  = fd_env_strip_cmdline_ushort( &argc, &argv, "--dst-port",       NULL, 9090U                        );
  char const * _gateway  = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--gateway",        NULL, "00:00:00:00:00:00"          );
  uint         batch     = fd_env_strip_cmdline_uint  ( &argc, &argv, "--batch",          NULL, 16U                          );
  /*         */g_unreliable = (_Bool)fd_env_strip_cmdline_contains( &argc, &argv, "--unreliable" );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  if( FD_UNLIKELY( !_dst_ip  ) ) FD_LOG_ERR(( "missing --dst-ip"   ));
  if( FD_UNLIKELY( !dst_port ) ) FD_LOG_ERR(( "missing --dst-port" ));

  if( FD_UNLIKELY( !_gateway ) ) FD_LOG_ERR(( "missing --gateway" ));
  uchar gateway[ 6 ]={0};
  if( FD_UNLIKELY( !fd_cstr_to_mac_addr( _gateway, gateway ) ) )
    FD_LOG_ERR(( "invalid gateway \"%s\"", _gateway ));

  uint dst_ip;
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( _dst_ip, &dst_ip  ) ) ) FD_LOG_ERR(( "invalid --dst-ip" ));

  FD_LOG_NOTICE(( "Creating workspace with --page-cnt %lu --page-sz %s pages on --numa-idx %lu", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  fd_quic_limits_t quic_limits = {0};
  fd_quic_limits_from_env( &argc, &argv, &quic_limits );
  quic_limits.stream_id_cnt = quic_limits.stream_pool_cnt;

  ulong quic_footprint = fd_quic_footprint( &quic_limits );
  FD_TEST( quic_footprint );
  FD_LOG_NOTICE(( "QUIC footprint: %lu bytes", quic_footprint ));

  FD_LOG_NOTICE(( "Creating client QUIC" ));
  fd_quic_t * quic = fd_quic_new_anonymous( wksp, &quic_limits, FD_QUIC_ROLE_CLIENT, rng );
  FD_TEST( quic );
  quic->cb.stream_notify = NULL;

  fd_quic_udpsock_t _udpsock[1];
  fd_quic_udpsock_t * udpsock = fd_quic_udpsock_create( _udpsock, &argc, &argv, wksp, fd_quic_get_aio_net_rx( quic ) );
  FD_TEST( udpsock );

  fd_quic_config_t * client_cfg = &quic->config;
  client_cfg->role = FD_QUIC_ROLE_CLIENT;
  FD_TEST( fd_quic_config_from_env( &argc, &argv, client_cfg ) );

  /* loop continually, so that if the connection dies we try again */
  while (1) {
    run_quic_client( quic, udpsock, dst_ip, (ushort)dst_port, batch );
  }

  FD_TEST( fd_quic_fini( quic ) );

  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( quic ) ) );
  fd_quic_udpsock_destroy( udpsock );
  fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

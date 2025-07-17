#include "fd_gui_peers.h"
#include "fd_gui_printf.h"

#include "../../ballet/json/cJSON.h"


FD_FN_CONST ulong
fd_gui_peers_align( void ) {
  ulong a = 128UL;
  a = fd_ulong_max( a, alignof(fd_gui_peers_ctx_t) );
  a = fd_ulong_max( a, fd_gui_peers_live_table_align() );
  a = fd_ulong_max( a, fd_gui_peers_node_pubkey_map_align() );
  a = fd_ulong_max( a, fd_gui_peers_node_sock_map_align() );
  a = fd_ulong_max( a, alignof(fd_gui_peers_ws_conn_viewport_t) );
  a = fd_ulong_max( a, alignof(fd_gui_peers_node_t) );
  return a;
}

FD_FN_CONST ulong
fd_gui_peers_footprint( ulong max_ws_connection_cnt ) {
  ulong pubkey_chain_cnt = fd_gui_peers_node_pubkey_map_chain_cnt_est( FD_CONTACT_INFO_TABLE_SIZE );
  ulong sock_chain_cnt   = fd_gui_peers_node_sock_map_chain_cnt_est( FD_CONTACT_INFO_TABLE_SIZE );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_gui_peers_ctx_t),              sizeof(fd_gui_peers_ctx_t)                                      );
  l = FD_LAYOUT_APPEND( l, fd_gui_peers_live_table_align(),          fd_gui_peers_live_table_footprint( FD_CONTACT_INFO_TABLE_SIZE ) );
  l = FD_LAYOUT_APPEND( l, fd_gui_peers_node_pubkey_map_align(),     fd_gui_peers_node_pubkey_map_footprint( pubkey_chain_cnt )      );
  l = FD_LAYOUT_APPEND( l, fd_gui_peers_node_sock_map_align(),       fd_gui_peers_node_sock_map_footprint( sock_chain_cnt )          );
  l = FD_LAYOUT_APPEND( l, alignof(fd_gui_peers_ws_conn_viewport_t), max_ws_connection_cnt*sizeof(fd_gui_peers_ws_conn_viewport_t)   );

  return FD_LAYOUT_FINI( l, fd_gui_peers_align() );
}

void *
fd_gui_peers_new( void * shmem, fd_http_server_t * http, ulong max_ws_connection_cnt ) {
    if( FD_UNLIKELY( !shmem ) ) {
      FD_LOG_WARNING(( "NULL shmem" ));
      return NULL;
    }

    if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_gui_peers_align() ) ) ) {
      FD_LOG_WARNING(( "misaligned shmem" ));
      return NULL;
    }

    ulong pubkey_chain_cnt = fd_gui_peers_node_pubkey_map_chain_cnt_est( FD_CONTACT_INFO_TABLE_SIZE );
    ulong sock_chain_cnt   = fd_gui_peers_node_sock_map_chain_cnt_est  ( FD_CONTACT_INFO_TABLE_SIZE );

    FD_SCRATCH_ALLOC_INIT( l, shmem );
    fd_gui_peers_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gui_peers_ctx_t),              sizeof(fd_gui_peers_ctx_t)                                      );
    void * _live_table       = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_peers_live_table_align(),          fd_gui_peers_live_table_footprint( FD_CONTACT_INFO_TABLE_SIZE ) );
    void * _pubkey_map       = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_peers_node_pubkey_map_align(),     fd_gui_peers_node_pubkey_map_footprint( pubkey_chain_cnt )      );
    void * _sock_map         = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_peers_node_sock_map_align(),       fd_gui_peers_node_sock_map_footprint( sock_chain_cnt )          );
    ctx->client_viewports    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gui_peers_ws_conn_viewport_t), max_ws_connection_cnt*sizeof(fd_gui_peers_ws_conn_viewport_t)   );

    ctx->http = http;
    ctx->max_ws_connection_cnt = max_ws_connection_cnt;
    for( ulong i = 0; i<FD_CONTACT_INFO_TABLE_SIZE; i++) ctx->contact_info_table[ i ].valid = 0;
    ctx->live_table      = fd_gui_peers_live_table_new( _live_table, FD_CONTACT_INFO_TABLE_SIZE                                                          );
    ctx->contact_info_table_sz = 0UL;
    fd_gui_peers_live_table_seed( ctx->contact_info_table, FD_CONTACT_INFO_TABLE_SIZE, 42UL );
    ctx->node_pubkey_map = fd_gui_peers_node_pubkey_map_new( _pubkey_map, fd_gui_peers_node_pubkey_map_chain_cnt_est( FD_CONTACT_INFO_TABLE_SIZE ), 42UL );
    ctx->node_sock_map   = fd_gui_peers_node_sock_map_new  ( _sock_map,   fd_gui_peers_node_sock_map_chain_cnt_est( FD_CONTACT_INFO_TABLE_SIZE ),   42UL );
    return shmem;
}

fd_gui_peers_ctx_t *
fd_gui_peers_join( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_gui_peers_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  fd_gui_peers_ctx_t * ctx = (fd_gui_peers_ctx_t *)shmem;

  ctx->live_table      = fd_gui_peers_live_table_join     ( ctx->live_table      );
  ctx->node_pubkey_map = fd_gui_peers_node_pubkey_map_join( ctx->node_pubkey_map );
  ctx->node_sock_map   = fd_gui_peers_node_sock_map_join  ( ctx->node_sock_map   );
  return ctx;
}

static int
fd_gui_peers_contact_info_eq( fd_contact_info_t const * ci1,
                              fd_contact_info_t const * ci2 ) {
  int ci_eq =
       ci1->shred_version                    == ci2->shred_version
    && ci1->instance_creation_wallclock_nanos== ci2->instance_creation_wallclock_nanos
 // && ci1->wallclock_nanos                  == ci2->wallclock_nanos
    && ci1->version.client                   == ci2->version.client
    && ci1->version.major                    == ci2->version.major
    && ci1->version.minor                    == ci2->version.minor
    && ci1->version.patch                    == ci2->version.patch
    && ci1->version.commit                   == ci2->version.commit
    && ci1->version.feature_set              == ci2->version.feature_set;

    if( FD_LIKELY( !ci_eq ) ) return 0;
    for( ulong j=0UL; j<(FD_CONTACT_INFO_SOCKET_LAST+1UL); j++ ) {
      if( FD_LIKELY( !(ci1->sockets[ j ].addr==ci2->sockets[ j ].addr && ci1->sockets[ j ].port==ci2->sockets[ j ].port) ) ) return 0;
    }

    return 1;
}

void
fd_gui_peers_handle_gossip_message( fd_gui_peers_ctx_t *  peers,
                                    uchar const *         payload,
                                    ulong                 payload_sz,
                                    fd_ip4_port_t const * peer_sock,
                                    int                   is_rx ) {
    fd_gui_peers_node_t * peer = fd_gui_peers_node_sock_map_ele_query( peers->node_sock_map, peer_sock, NULL, peers->contact_info_table );

    /* We can only update peer stats once we've seen their contact info.
       This simplifies code at the expense of missing out on some data
       sent at the start. */
    if( FD_UNLIKELY( !peer ) ) return;

    fd_gossip_view_t view[ 1 ];
    ulong decode_sz = fd_gossip_msg_parse( view, payload, payload_sz );
    if( FD_UNLIKELY( decode_sz ) ) {
        FD_LOG_WARNING(( "failed to parse gossip msg" ));
        return;
    }


    /* accumulate metric */
    fd_ptr_if( is_rx, (ulong *)peer->cur.gossvf.bytes_rx, (ulong *)peer->cur.gossip.bytes_tx )[ view->tag ] += payload_sz;
}

int
fd_gui_peers_handle_gossip_update( fd_gui_peers_ctx_t *               peers,
                                   fd_gossip_update_message_t const * update ) {
    switch( update->tag ) {
      case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO: {
        /* origin_pubkey should be the same as the contact info pubkey */
        FD_TEST( !memcmp( update->origin_pubkey, update->contact_info.contact_info->pubkey.uc, 32UL ) );

        fd_gui_peers_node_t * peer = peers->contact_info_table + update->contact_info.idx;

        if( FD_LIKELY( peer->valid ) ) {
          /* A new pubkey is not allowed to overwrite an existing valid index */
          FD_TEST( !memcmp( &peer->contact_info.pubkey, &update->origin_pubkey, 32UL ) );
          FD_TEST( fd_gui_peers_node_pubkey_map_ele_query_const( peers->node_pubkey_map, (fd_pubkey_t * )update->origin_pubkey, NULL, peers->contact_info_table ) );

          int ci_eq = fd_gui_peers_contact_info_eq( &peer->contact_info, update->contact_info.contact_info );
          fd_memcpy( &peer->contact_info, update->contact_info.contact_info, sizeof(peer->contact_info) );
          return fd_int_if( ci_eq, FD_GUI_PEERS_NODE_NOP, FD_GUI_PEERS_NODE_UPDATE );
        } else {
          peers->contact_info_table_sz++; /* todo ... broadcast update */
          peer->valid = 1;
          fd_memcpy( &peer->contact_info, update->contact_info.contact_info, sizeof(peer->contact_info) );
          fd_gui_peers_node_sock_map_ele_insert( peers->node_sock_map, peer, peers->contact_info_table );
          fd_gui_peers_node_pubkey_map_ele_insert( peers->node_pubkey_map, peer, peers->contact_info_table );
          // fd_gui_peers_live_table_ele_insert( peers->live_table, peers->contact_info_table, peer );
          return FD_GUI_PEERS_NODE_ADD;
        }

        break;
      }
      case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE: {
        fd_gui_peers_node_t * peer = peers->contact_info_table + update->contact_info.idx;
        FD_TEST( fd_gui_peers_node_pubkey_map_ele_query_const( peers->node_pubkey_map, (fd_pubkey_t * )update->origin_pubkey, NULL, peers->contact_info_table ) );
        FD_TEST( peer->valid ); /* Should have already been in the table */

        fd_gui_peers_node_t * peer_sock = fd_gui_peers_node_sock_map_ele_remove( peers->node_sock_map, &peer->contact_info.sockets[ FD_CONTACT_INFO_SOCKET_GOSSIP ], NULL, peers->contact_info_table );
        fd_gui_peers_node_t * peer_pubkey = fd_gui_peers_node_pubkey_map_ele_remove( peers->node_pubkey_map, &peer->contact_info.pubkey, NULL, peers->contact_info_table );
        if( FD_UNLIKELY( !(peer_sock && peer_pubkey && peer_pubkey==peer_sock ) ) ) FD_LOG_ERR(("contact info table sync error. peer_sock=%lu peer_pubkey=%lu", (ulong)peer_sock, (ulong)peer_pubkey ));
        peer->valid = 0;
        peers->contact_info_table_sz--; /* todo ... broadcast update */
        break;
      }
      default: break;
    }

    return FD_GUI_PEERS_NODE_NOP;
}

static void
fd_gui_peers_viewport_snap( fd_gui_peers_ctx_t * peers, ulong ws_conn_id ) {
  for( fd_gui_peers_live_table_fwd_iter_t iter = fd_gui_peers_live_table_fwd_iter_init( peers->live_table, &peers->client_viewports[ ws_conn_id ].sort_key, peers->contact_info_table ), j = 0;
       !fd_gui_peers_live_table_fwd_iter_done( iter );
       iter = fd_gui_peers_live_table_fwd_iter_next( iter, peers->contact_info_table ), j++ ) {
    fd_gui_peers_node_t * cur = fd_gui_peers_live_table_fwd_iter_ele( iter, peers->contact_info_table );
    fd_gui_peers_node_t * ref = &peers->client_viewports[ ws_conn_id ].viewport[ j ];

    for( ulong i=0UL; i<FD_METRICS_ENUM_GOSSIP_MESSAGE_CNT; i++ ) {
      cur->diff.gossvf.bytes_rx[ i ] = cur->cur.gossvf.bytes_rx[ i ] - ref->cur.gossvf.bytes_rx[ i ];
      cur->diff.gossip.bytes_tx[ i ] = cur->cur.gossip.bytes_tx[ i ] - ref->cur.gossip.bytes_tx[ i ];
    } 

    fd_memcpy( ref, cur, sizeof(fd_gui_peers_node_t) );
  }
}

static int
fd_gui_peers_request_scroll( fd_gui_peers_ctx_t * peers,
                             ulong                ws_conn_id,
                             ulong                request_id,
                             cJSON const *        params ) {
  if( FD_UNLIKELY( !peers->client_viewports[ ws_conn_id ].connected ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  const cJSON * start_row_param = cJSON_GetObjectItemCaseSensitive( params, "start_row" );
  if( FD_UNLIKELY( !cJSON_IsNumber( start_row_param ) ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  ulong _start_row = start_row_param->valueulong;

  const cJSON * end_row_param = cJSON_GetObjectItemCaseSensitive( params, "end_row" );
  if( FD_UNLIKELY( !cJSON_IsNumber( end_row_param ) ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  ulong _end_row = end_row_param->valueulong;

  if( FD_UNLIKELY( _start_row > _end_row || _end_row - _start_row + 1 > FD_GUI_PEERS_WS_VIEWPORT_MAX_SZ ) ) {
    fd_gui_printf_null_query_response( peers->http, "gossip", "query_scroll", request_id );
    FD_TEST( !fd_http_server_ws_send( peers->http, ws_conn_id ) );
    return 0;
  }

  if( FD_UNLIKELY( peers->client_viewports[ ws_conn_id ].start_row==_start_row && (peers->client_viewports[ ws_conn_id ].start_row + peers->client_viewports[ ws_conn_id ].row_cnt)==_end_row+1UL ) ) {
    return 0; /* NOP */
  }

  /* update the client's viewport */
  peers->client_viewports[ ws_conn_id ].start_row = _start_row;
  peers->client_viewports[ ws_conn_id ].row_cnt   = _end_row - _start_row + 1UL;

  fd_gui_printf_peers_viewport_request( peers, "query_scroll", ws_conn_id, request_id );
  FD_TEST( !fd_http_server_ws_send( peers->http, ws_conn_id ) );
  return 0;
}

static int
fd_gui_peers_request_sort( fd_gui_peers_ctx_t * peers,
                           ulong                ws_conn_id,
                           ulong                request_id,
                           cJSON const *        params ) {
  if( FD_UNLIKELY( !peers->client_viewports[ ws_conn_id ].connected ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  const cJSON * col_id_param = cJSON_GetObjectItemCaseSensitive( params, "col_id" );
  if( FD_UNLIKELY( !cJSON_IsString( col_id_param ) ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  char * _col_name = col_id_param->valuestring;

  ulong _col_idx = fd_gui_peers_live_table_col_name_to_idx( peers->live_table, _col_name );
  if( FD_UNLIKELY( _col_idx==ULONG_MAX) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  ulong sort_idx = ULONG_MAX;
  for( ulong i=0UL; i<FD_GUI_PEERS_CI_TABLE_SORT_KEY_CNT; i++ ) {
    if( FD_UNLIKELY( _col_idx==peers->client_viewports[ ws_conn_id ].sort_key.col[ i ] ) ) {
      sort_idx = i;
      break;
    }
  }
  FD_TEST( sort_idx!=ULONG_MAX );

  const cJSON * dir_param = cJSON_GetObjectItemCaseSensitive( params, "dir" );
  if( FD_UNLIKELY( !cJSON_IsNumber( dir_param ) ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  int _dir = dir_param->valueint;

  if( FD_UNLIKELY( _dir > 1 || _dir < -1 ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  if( FD_UNLIKELY( peers->client_viewports[ ws_conn_id ].sort_key.dir[ sort_idx ]==_dir ) ) return 0; /* NOP */

  /* update the client's viewport */
  for( ulong i=sort_idx; i>0; i-- ) {
    peers->client_viewports[ ws_conn_id ].sort_key.col[ i ] = peers->client_viewports[ ws_conn_id ].sort_key.col[ i-1UL ];
    peers->client_viewports[ ws_conn_id ].sort_key.dir[ i ] = peers->client_viewports[ ws_conn_id ].sort_key.dir[ i-1UL ];
  }
  peers->client_viewports[ ws_conn_id ].sort_key.col[ 0 ] = _col_idx;
  peers->client_viewports[ ws_conn_id ].sort_key.dir[ 0 ] = _dir;

  if( FD_UNLIKELY( peers->client_viewports[ ws_conn_id ].row_cnt==0 )) return 0; /* NOP */

  fd_gui_printf_peers_viewport_request( peers, "query_sort_col", ws_conn_id, request_id );
  FD_TEST( !fd_http_server_ws_send( peers->http, ws_conn_id ) );
  return 0;
}


/* todo ... move json parsing logic into separate header. Deduplicates
   this code and can stick rpc reponse parsers there too. */
int
fd_gui_peers_ws_message( fd_gui_peers_ctx_t * peers,
                         ulong                ws_conn_id,
                         uchar const *        data,
                         ulong                data_len ) {
  /* TODO: cJSON allocates, might fail SIGSYS due to brk(2)...
     switch off this (or use wksp allocator) */
  const char * parse_end;
  cJSON * json = cJSON_ParseWithLengthOpts( (char *)data, data_len, &parse_end, 0 );
  if( FD_UNLIKELY( !json ) ) {
    return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  }

  const cJSON * node = cJSON_GetObjectItemCaseSensitive( json, "id" );
  if( FD_UNLIKELY( !cJSON_IsNumber( node ) ) ) {
    cJSON_Delete( json );
    return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  }
  ulong id = node->valueulong;

  const cJSON * topic = cJSON_GetObjectItemCaseSensitive( json, "topic" );
  if( FD_UNLIKELY( !cJSON_IsString( topic ) || topic->valuestring==NULL ) ) {
    cJSON_Delete( json );
    return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  }

  const cJSON * key = cJSON_GetObjectItemCaseSensitive( json, "key" );
  if( FD_UNLIKELY( !cJSON_IsString( key ) || key->valuestring==NULL ) ) {
    cJSON_Delete( json );
    return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
  }

  if( FD_LIKELY( !strcmp( topic->valuestring, "gossip" ) && !strcmp( key->valuestring, "query_sort_col" ) ) ) {
    const cJSON * params = cJSON_GetObjectItemCaseSensitive( json, "params" );
    if( FD_UNLIKELY( !cJSON_IsObject( params ) ) ) {
      cJSON_Delete( json );
      return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
    }

    int result = fd_gui_peers_request_sort( peers, ws_conn_id, id, params );
    cJSON_Delete( json );
    return result;
  } else if( FD_LIKELY( !strcmp( topic->valuestring, "gossip" ) && !strcmp( key->valuestring, "query_scroll" ) ) ) {
    const cJSON * params = cJSON_GetObjectItemCaseSensitive( json, "params" );
    if( FD_UNLIKELY( !cJSON_IsObject( params ) ) ) {
      cJSON_Delete( json );
      return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
    }

    int result = fd_gui_peers_request_scroll( peers, ws_conn_id, id, params );
    cJSON_Delete( json );
    return result;
  }

  cJSON_Delete( json );
  return FD_HTTP_SERVER_CONNECTION_CLOSE_UNKNOWN_METHOD;
}

int
fd_gui_peers_poll( fd_gui_peers_ctx_t * peers  ) {
  long now = fd_log_wallclock();
  int did_work = 0;

  if( FD_LIKELY( now - peers->last_sample_1000millis > FD_GUI_PEERS_WS_VIEWPORT_UPDATE_INTERVAL_MILLIS * 1000000L ) ) {
    for( ulong i=0UL; i<peers->max_ws_connection_cnt; i++ ) {
      if( FD_LIKELY( !peers->client_viewports[ i ].connected ) ) continue;
      if( FD_UNLIKELY( peers->client_viewports[ i ].row_cnt==0 )) continue;

      /* broadcast the diff as cell updates */
      fd_gui_printf_peers_viewport_update( peers, i );
      FD_TEST( !fd_http_server_ws_send( peers->http, i ) );

      /* update client state to the latest viewport */
      fd_gui_peers_viewport_snap( peers, i );
    }

    peers->last_sample_1000millis = now;
    did_work = 1;
  }

  return did_work;
}

void
fd_gui_peers_ws_open( fd_gui_peers_ctx_t * peers, ulong ws_conn_id ) {
  peers->client_viewports[ ws_conn_id ].connected = 1;
  peers->client_viewports[ ws_conn_id ].row_cnt = 0;
  fd_memcpy( &peers->client_viewports[ ws_conn_id ].sort_key, fd_gui_peers_live_table_default_sort_key( peers->live_table ), sizeof(fd_gui_peers_live_table_t) );
  fd_gui_peers_viewport_snap( peers, ws_conn_id );
}

void
fd_gui_peers_ws_close( fd_gui_peers_ctx_t * peers, ulong ws_conn_id ) {
  peers->client_viewports[ ws_conn_id ].connected = 0;
}

/* todo ... get vote account info, validator info from rpc call */

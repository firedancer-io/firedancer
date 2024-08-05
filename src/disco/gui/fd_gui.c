#include "fd_gui.h"

#include "../fd_disco.h"
#include "../plugin/fd_plugin.h"

#include "../../ballet/base58/fd_base58.h"

FD_FN_CONST ulong
fd_gui_align( void ) {
  return 128UL;
}

FD_FN_CONST ulong
fd_gui_footprint( void ) {
  return sizeof(fd_gui_t);
}

void *
fd_gui_new( void *             shmem,
            fd_http_server_t * server,
            fd_alloc_t *       alloc,
            char const *       version,
            char const *       cluster,
            char const *       identity_key_base58 ) {
  fd_gui_t * gui = (fd_gui_t *)shmem;

  gui->server              = server;
  gui->alloc               = alloc;

  gui->summary.version             = version;
  gui->summary.cluster             = cluster;
  gui->summary.identity_key_base58 = identity_key_base58;

  gui->summary.slot_rooted                   = 0UL;
  gui->summary.slot_optimistically_confirmed = 0UL;
  gui->summary.slot_completed                = 0UL;
  gui->summary.slot_estimated                = 0UL;

  gui->gossip.peer_cnt = 0UL;

  return gui;
}

fd_gui_t *
fd_gui_join( void * shmem ) {
  return (fd_gui_t *)shmem;
}

void
fd_gui_ws_open( fd_gui_t *         gui,
                ulong              conn_id ) {
  void * buffer = fd_alloc_malloc( gui->alloc, 1UL, 1024UL );
  FD_TEST( buffer );
  ulong message_len;
  FD_TEST( fd_cstr_printf_check( buffer, 1024UL, &message_len, "{\n    \"topic\": \"summary\",\n    \"key\": \"version\",\n    \"value\": \"%s\",\n}\n", gui->summary.version ) );
  fd_http_server_ws_send( gui->server, conn_id, buffer, message_len );

  buffer = fd_alloc_malloc( gui->alloc, 1UL, 1024UL );
  FD_TEST( buffer );
  FD_TEST( fd_cstr_printf_check( buffer, 1024UL, &message_len, "{\n    \"topic\": \"summary\",\n    \"key\": \"cluster\",\n    \"value\": \"%s\",\n}\n", gui->summary.cluster ) );
  fd_http_server_ws_send( gui->server, conn_id, buffer, message_len );

  buffer = fd_alloc_malloc( gui->alloc, 1UL, 1024UL );
  FD_TEST( buffer );
  FD_TEST( fd_cstr_printf_check( buffer, 1024UL, &message_len, "{\n    \"topic\": \"summary\",\n    \"key\": \"identity_key\",\n    \"value\": \"%s\",\n}\n", gui->summary.identity_key_base58 ) );
  fd_http_server_ws_send( gui->server, conn_id, buffer, message_len );

  buffer = fd_alloc_malloc( gui->alloc, 1UL, 1024UL );
  FD_TEST( buffer );
  FD_TEST( fd_cstr_printf_check( buffer, 1024UL, &message_len, "{\n    \"topic\": \"summary\",\n    \"key\": \"root_slot\",\n    \"value\": %lu,\n}\n", gui->summary.slot_rooted ) );
  fd_http_server_ws_send( gui->server, conn_id, buffer, message_len );

  buffer = fd_alloc_malloc( gui->alloc, 1UL, 1024UL );
  FD_TEST( buffer );
  FD_TEST( fd_cstr_printf_check( buffer, 1024UL, &message_len, "{\n    \"topic\": \"summary\",\n    \"key\": \"optimistically_confirmed_slot\",\n    \"value\": %lu,\n}\n", gui->summary.slot_optimistically_confirmed ) );
  fd_http_server_ws_send( gui->server, conn_id, buffer, message_len );

  buffer = fd_alloc_malloc( gui->alloc, 1UL, 1024UL );
  FD_TEST( buffer );
  FD_TEST( fd_cstr_printf_check( buffer, 1024UL, &message_len, "{\n    \"topic\": \"summary\",\n    \"key\": \"completed_slot\",\n    \"value\": %lu,\n}\n", gui->summary.slot_completed ) );
  fd_http_server_ws_send( gui->server, conn_id, buffer, message_len );

  buffer = fd_alloc_malloc( gui->alloc, 1UL, 1024UL );
  FD_TEST( buffer );
  FD_TEST( fd_cstr_printf_check( buffer, 1024UL, &message_len, "{\n    \"topic\": \"summary\",\n    \"key\": \"estimated_slot\",\n    \"value\": %lu,\n}\n", gui->summary.slot_estimated ) );
  fd_http_server_ws_send( gui->server, conn_id, buffer, message_len );

  const ulong buffer_size = 1024UL * 1024UL;
  char * buffer1 = fd_alloc_malloc( gui->alloc, 1UL, buffer_size );
  FD_TEST( buffer1 );
  FD_TEST( fd_cstr_printf_check( buffer1, buffer_size, &message_len, "{\n    \"topic\": \"gossip\",\n    \"key\": \"update\",\n    \"value\": {\n        \"add\": [\n" ) );

  for( ulong i=0UL; i<gui->gossip.peer_cnt; i++ ) {
    char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( gui->gossip.peers[ i ].pubkey->uc, NULL, identity_base58 );
    ulong line_len;
    FD_TEST( fd_cstr_printf_check( buffer1+message_len, buffer_size-message_len, &line_len,
      "            {\n"
      "                \"identity\": \"%s\",\n"
      "                \"version\": \"%u.%u.%u\",\n"
      "                \"feature_set\": \"%u\",\n"
      "                \"wallclock\": \"%lu\",\n"
      "                \"shred_version\": \"%u\",\n"
      "                \"sockets\": {\n",
      identity_base58,
      gui->gossip.peers[ i ].version.major,
      gui->gossip.peers[ i ].version.minor,
      gui->gossip.peers[ i ].version.patch,
      gui->gossip.peers[ i ].version.feature_set,
      gui->gossip.peers[ i ].wallclock,
      gui->gossip.peers[ i ].shred_version ) );
    message_len += line_len;
    for( ulong j=0UL; j<12UL; j++ ) {
      if( FD_LIKELY( !gui->gossip.peers[ i ].sockets[ j ].ipv4 && !gui->gossip.peers[ i ].sockets[ j ].port ) ) continue;
      char const * tag;
      switch( j ) {
        case  0: tag = "gossip";            break;
        case  1: tag = "rpc";               break;
        case  2: tag = "rpb_pubsub";        break;
        case  3: tag = "serve_repair";      break;
        case  4: tag = "serve_repair_quic"; break;
        case  5: tag = "tpu";               break;
        case  6: tag = "tpu_quic";          break;
        case  7: tag = "tvu";               break;
        case  8: tag = "tvu_quic";          break;
        case  9: tag = "tpu_forwards";      break;
        case 10: tag = "tpu_forwards_quic"; break;
        case 11: tag = "tpu_vote";          break;
      }
      if( FD_UNLIKELY( j==11 ) )
        FD_TEST( fd_cstr_printf_check( buffer1+message_len, buffer_size-message_len, &line_len, "                    \"%s\": \"" FD_IP4_ADDR_FMT ":%u\"\n", tag, FD_IP4_ADDR_FMT_ARGS(gui->gossip.peers[ i ].sockets[ j ].ipv4 ), gui->gossip.peers[ i ].sockets[ j ].port ) );
      else
        FD_TEST( fd_cstr_printf_check( buffer1+message_len, buffer_size-message_len, &line_len, "                    \"%s\": \"" FD_IP4_ADDR_FMT ":%u\",\n", tag, FD_IP4_ADDR_FMT_ARGS(gui->gossip.peers[ i ].sockets[ j ].ipv4 ), gui->gossip.peers[ i ].sockets[ j ].port ) );
      message_len += line_len;
    }
    if( FD_UNLIKELY( i==gui->gossip.peer_cnt-1UL ) )
      FD_TEST( fd_cstr_printf_check( buffer1+message_len, buffer_size-message_len, &line_len, "                }\n            }\n" ) );
    else
      FD_TEST( fd_cstr_printf_check( buffer1+message_len, buffer_size-message_len, &line_len, "                }\n            },\n" ) );
    message_len += line_len;
  }

  ulong x_len;
  FD_TEST( fd_cstr_printf_check( buffer1+message_len, buffer_size, &x_len, "        ]\n    }\n}\n" ) );
  message_len += x_len;

  fd_http_server_ws_broadcast( gui->server, (uchar const *)buffer1, message_len );
}

void
fd_gui_plugin_message( fd_gui_t *    gui,
                       ulong         plugin_msg,
                       uchar const * msg,
                       ulong         msg_len ) {
  (void)msg_len;

  switch( plugin_msg ) {
    case FD_PLUGIN_MSG_SLOT_ROOTED:
      gui->summary.slot_rooted = *(ulong const *)msg;
      char * buffer = fd_alloc_malloc( gui->alloc, 1UL, 1024UL );
      FD_TEST( buffer );
      ulong message_len;
      FD_TEST( fd_cstr_printf_check( buffer, 1024UL, &message_len, "{\n    \"topic\": \"summary\",\n    \"key\": \"slot_rooted\",\n    \"value\": %lu,\n}\n", gui->summary.slot_rooted ) );
      fd_http_server_ws_broadcast( gui->server, (uchar const *)buffer, message_len );
      break;
    case FD_PLUGIN_MSG_SLOT_OPTIMISTICALLY_CONFIRMED:
      gui->summary.slot_optimistically_confirmed = *(ulong const *)msg;
      buffer = fd_alloc_malloc( gui->alloc, 1UL, 1024UL );
      FD_TEST( buffer );
      FD_TEST( fd_cstr_printf_check( buffer, 1024UL, &message_len, "{\n    \"topic\": \"summary\",\n    \"key\": \"slot_optimistically_confirmed\",\n    \"value\": %lu,\n}\n", gui->summary.slot_optimistically_confirmed ) );
      fd_http_server_ws_broadcast( gui->server, (uchar const *)buffer, message_len );
      break;
    case FD_PLUGIN_MSG_SLOT_COMPLETED:
      gui->summary.slot_completed = *(ulong const *)msg;
      buffer = fd_alloc_malloc( gui->alloc, 1UL, 1024UL );
      FD_TEST( buffer );
      FD_TEST( fd_cstr_printf_check( buffer, 1024UL, &message_len, "{\n    \"topic\": \"summary\",\n    \"key\": \"slot_completed\",\n    \"value\": %lu,\n}\n", gui->summary.slot_completed ) );
      fd_http_server_ws_broadcast( gui->server, (uchar const *)buffer, message_len );
      break;
    case FD_PLUGIN_MSG_SLOT_ESTIMATED:
      gui->summary.slot_estimated = *(ulong const *)msg;
      buffer = fd_alloc_malloc( gui->alloc, 1UL, 1024UL );
      FD_TEST( buffer );
      FD_TEST( fd_cstr_printf_check( buffer, 1024UL, &message_len, "{\n    \"topic\": \"summary\",\n    \"key\": \"slot_estimated\",\n    \"value\": %lu,\n}\n", gui->summary.slot_estimated ) );
      fd_http_server_ws_broadcast( gui->server, (uchar const *)buffer, message_len );
      break;
    case FD_PLUGIN_MSG_LEADER_SCHEDULE:
      break;
    case FD_PLUGIN_MSG_GOSSIP_UPDATE: {
      ulong const * header = (ulong const *)fd_type_pun_const( msg );
      ulong peer_cnt = header[ 0 ];

      ulong update_cnt = 0UL;
      ulong updated[ 40200 ] = {0};

      ulong removed_cnt = 0UL;
      fd_pubkey_t removed[ 40200 ] = {0};

      uchar const * data = (uchar const *)(header+1UL);
      for( ulong i=0UL; i<gui->gossip.peer_cnt; i++ ) {
        int found = 0;
        for( ulong j=0UL; j<peer_cnt; j++ ) {
          if( FD_UNLIKELY( !memcmp( gui->gossip.peers[ i ].pubkey, data+j*(58UL+12UL*6UL), 32UL ) ) ) {
            found = 1;
            break;
          }
        }

        if( FD_UNLIKELY( !found ) ) {
          fd_memcpy( removed[ removed_cnt++ ].uc, gui->gossip.peers[ i ].pubkey->uc, 32UL );
          if( FD_LIKELY( i+1UL!=gui->gossip.peer_cnt ) ) {
            fd_memcpy( &gui->gossip.peers[ i ], &gui->gossip.peers[ gui->gossip.peer_cnt-1UL ], sizeof(struct fd_gui_gossip_peer) );
            gui->gossip.peer_cnt--;
            i--;
          }
        }
      }

      ulong before_peer_cnt = gui->gossip.peer_cnt;
      for( ulong i=0UL; i<peer_cnt; i++ ) {
        int found = 0;
        ulong found_idx;
        for( ulong j=0UL; j<gui->gossip.peer_cnt; j++ ) {
          if( FD_UNLIKELY( !memcmp( gui->gossip.peers[ j ].pubkey, data+i*(58UL+12UL*6UL), 32UL ) ) ) {
            found_idx = j;
            found = 1;
            break;
          }
        }

        if( FD_UNLIKELY( !found ) ) {
          fd_memcpy( gui->gossip.peers[ gui->gossip.peer_cnt ].pubkey->uc, data+i*(58UL+12UL*6UL), 32UL );
          gui->gossip.peers[ gui->gossip.peer_cnt ].wallclock = *(ulong const *)(data+i*(58UL+12UL*6UL)+32UL);
          gui->gossip.peers[ gui->gossip.peer_cnt ].shred_version = *(ushort const *)(data+i*(58UL+12UL*6UL)+40UL);
          gui->gossip.peers[ gui->gossip.peer_cnt ].has_version = *(data+i*(58UL+12UL*6UL)+42UL);
          if( FD_LIKELY( gui->gossip.peers[ gui->gossip.peer_cnt ].has_version ) ) {
            gui->gossip.peers[ gui->gossip.peer_cnt ].version.major = *(ushort const *)(data+i*(58UL+12UL*6UL)+43UL);
            gui->gossip.peers[ gui->gossip.peer_cnt ].version.minor = *(ushort const *)(data+i*(58UL+12UL*6UL)+45UL);
            gui->gossip.peers[ gui->gossip.peer_cnt ].version.patch = *(ushort const *)(data+i*(58UL+12UL*6UL)+47UL);
            gui->gossip.peers[ gui->gossip.peer_cnt ].version.has_commit = *(data+i*(58UL+12UL*6UL)+49UL);
            if( FD_LIKELY( gui->gossip.peers[ gui->gossip.peer_cnt ].version.has_commit ) ) {
              gui->gossip.peers[ gui->gossip.peer_cnt ].version.commit = *(uint const *)(data+i*(58UL+12UL*6UL)+50UL);
            }
            gui->gossip.peers[ gui->gossip.peer_cnt ].version.has_feature_set = *(data+i*(58UL+12UL*6UL)+54UL);
          }

          for( ulong j=0UL; j<12UL; j++ ) {
            gui->gossip.peers[ gui->gossip.peer_cnt ].sockets[ j ].ipv4 = *(uint const *)(data+i*(58UL+12UL*6UL)+58UL+j*6UL);
            gui->gossip.peers[ gui->gossip.peer_cnt ].sockets[ j ].port = *(ushort const *)(data+i*(58UL+12UL*6UL)+58UL+j*6UL+4UL);
          }

          gui->gossip.peer_cnt++;
        } else {
          int peer_updated = gui->gossip.peers[ gui->gossip.peer_cnt ].shred_version!=*(ushort const *)(data+i*(58UL+12UL*6UL)+40UL) ||
                             gui->gossip.peers[ gui->gossip.peer_cnt ].wallclock!=*(ulong const *)(data+i*(58UL+12UL*6UL)+32UL) ||
                             gui->gossip.peers[ gui->gossip.peer_cnt ].has_version!=*(data+i*(58UL+12UL*6UL)+42UL);
          if( FD_LIKELY( !peer_updated && gui->gossip.peers[ gui->gossip.peer_cnt ].has_version ) ) {
            peer_updated = gui->gossip.peers[ gui->gossip.peer_cnt ].version.major!=*(ushort const *)(data+i*(58UL+12UL*6UL)+43UL) ||
                           gui->gossip.peers[ gui->gossip.peer_cnt ].version.minor!=*(ushort const *)(data+i*(58UL+12UL*6UL)+45UL) ||
                           gui->gossip.peers[ gui->gossip.peer_cnt ].version.patch!=*(ushort const *)(data+i*(58UL+12UL*6UL)+47UL) ||
                           gui->gossip.peers[ gui->gossip.peer_cnt ].version.has_commit!=*(data+i*(58UL+12UL*6UL)+49UL) ||
                           (gui->gossip.peers[ gui->gossip.peer_cnt ].version.has_commit && gui->gossip.peers[ gui->gossip.peer_cnt ].version.commit!=*(uint const *)(data+i*(58UL+12UL*6UL)+50UL)) ||
                           gui->gossip.peers[ gui->gossip.peer_cnt ].version.has_feature_set!=*(data+i*(58UL+12UL*6UL)+54UL);

            if( FD_LIKELY( !peer_updated ) ) {
              for( ulong j=0UL; j<12UL; j++ ) {
                peer_updated = gui->gossip.peers[ gui->gossip.peer_cnt ].sockets[ j ].ipv4!=*(uint const *)(data+i*(58UL+12UL*6UL)+58UL+j*6UL) ||
                               gui->gossip.peers[ gui->gossip.peer_cnt ].sockets[ j ].port!=*(ushort const *)(data+i*(58UL+12UL*6UL)+58UL+j*6UL+4UL);
                if( FD_LIKELY( peer_updated ) ) break;
              }
            }
          }

          if( FD_UNLIKELY( peer_updated ) ) {
            updated[ update_cnt++ ] = found_idx;
            gui->gossip.peers[ found_idx ].shred_version = *(ushort const *)(data+i*(58UL+12UL*6UL)+40UL);
            gui->gossip.peers[ found_idx ].wallclock = *(ulong const *)(data+i*(58UL+12UL*6UL)+32UL);
            gui->gossip.peers[ found_idx ].has_version = *(data+i*(58UL+12UL*6UL)+42UL);
            if( FD_LIKELY( gui->gossip.peers[ found_idx ].has_version ) ) {
              gui->gossip.peers[ found_idx ].version.major = *(ushort const *)(data+i*(58UL+12UL*6UL)+43UL);
              gui->gossip.peers[ found_idx ].version.minor = *(ushort const *)(data+i*(58UL+12UL*6UL)+45UL);
              gui->gossip.peers[ found_idx ].version.patch = *(ushort const *)(data+i*(58UL+12UL*6UL)+47UL);
              gui->gossip.peers[ found_idx ].version.has_commit = *(data+i*(58UL+12UL*6UL)+49UL);
              if( FD_LIKELY( gui->gossip.peers[ found_idx ].version.has_commit ) ) {
                gui->gossip.peers[ found_idx ].version.commit = *(uint const *)(data+i*(58UL+12UL*6UL)+50UL);
              }
              gui->gossip.peers[ found_idx ].version.has_feature_set = *(data+i*(58UL+12UL*6UL)+54UL);
            }

            for( ulong j=0UL; j<12UL; j++ ) {
              gui->gossip.peers[ found_idx ].sockets[ j ].ipv4 = *(uint const *)(data+i*(58UL+12UL*6UL)+68UL+j*6UL);
              gui->gossip.peers[ found_idx ].sockets[ j ].port = *(ushort const *)(data+i*(58UL+12UL*6UL)+72UL+j*6UL+2UL);
            }
          }
        }
      }

      const ulong buffer_size = 8192UL;
      buffer = fd_alloc_malloc( gui->alloc, 1UL, buffer_size );
      FD_TEST( buffer );
      FD_TEST( fd_cstr_printf_check( buffer, buffer_size, &message_len, "{\n    \"topic\": \"gossip\",\n    \"key\": \"update\",\n    \"value\": {\n        \"add\": [\n" ) );

      for( ulong i=before_peer_cnt; i<gui->gossip.peer_cnt; i++ ) {
        char identity_base58[ FD_BASE58_ENCODED_32_SZ ];
        fd_base58_encode_32( gui->gossip.peers[ i ].pubkey->uc, NULL, identity_base58 );
        ulong line_len;
        FD_TEST( fd_cstr_printf_check( buffer+message_len, buffer_size-message_len, &line_len,
          "            {\n"
          "                \"identity\": \"%s\",\n"
          "                \"version\": \"%u.%u.%u\",\n"
          "                \"feature_set\": \"%u\",\n"
          "                \"wallclock\": \"%lu\",\n"
          "                \"shred_version\": \"%u\",\n"
          "                \"sockets\": {\n",
          identity_base58,
          gui->gossip.peers[ i ].version.major,
          gui->gossip.peers[ i ].version.minor,
          gui->gossip.peers[ i ].version.patch,
          gui->gossip.peers[ i ].version.feature_set,
          gui->gossip.peers[ i ].wallclock,
          gui->gossip.peers[ i ].shred_version ) );
        message_len += line_len;
        for( ulong j=0UL; j<12UL; j++ ) {
          if( FD_LIKELY( !gui->gossip.peers[ i ].sockets[ j ].ipv4 && !gui->gossip.peers[ i ].sockets[ j ].port ) ) continue;
          char const * tag;
          switch( j ) {
            case  0: tag = "gossip";            break;
            case  1: tag = "rpc";               break;
            case  2: tag = "rpb_pubsub";        break;
            case  3: tag = "serve_repair";      break;
            case  4: tag = "serve_repair_quic"; break;
            case  5: tag = "tpu";               break;
            case  6: tag = "tpu_quic";          break;
            case  7: tag = "tvu";               break;
            case  8: tag = "tvu_quic";          break;
            case  9: tag = "tpu_forwards";      break;
            case 10: tag = "tpu_forwards_quic"; break;
            case 11: tag = "tpu_vote";          break;
          }
          if( FD_UNLIKELY( j==11 ) )
            FD_TEST( fd_cstr_printf_check( buffer+message_len, buffer_size-message_len, &line_len, "                    \"%s\": \"" FD_IP4_ADDR_FMT ":%u\"\n", tag, FD_IP4_ADDR_FMT_ARGS(gui->gossip.peers[ i ].sockets[ j ].ipv4 ), gui->gossip.peers[ i ].sockets[ j ].port ) );
          else
            FD_TEST( fd_cstr_printf_check( buffer+message_len, buffer_size-message_len, &line_len, "                    \"%s\": \"" FD_IP4_ADDR_FMT ":%u\",\n", tag, FD_IP4_ADDR_FMT_ARGS(gui->gossip.peers[ i ].sockets[ j ].ipv4 ), gui->gossip.peers[ i ].sockets[ j ].port ) );
          message_len += line_len;
        }
        if( FD_UNLIKELY( i==gui->gossip.peer_cnt-1UL ) )
          FD_TEST( fd_cstr_printf_check( buffer+message_len, buffer_size-message_len, &line_len, "                }\n            }\n" ) );
        else
          FD_TEST( fd_cstr_printf_check( buffer+message_len, buffer_size-message_len, &line_len, "                }\n            },\n" ) );
        message_len += line_len;
      }

      ulong x_len;
      FD_TEST( fd_cstr_printf_check( buffer+message_len, buffer_size, &x_len, "        ]\n    }\n}\n" ) );
      message_len += x_len;

      fd_http_server_ws_broadcast( gui->server, (uchar const *)buffer, message_len );
      break;

      (void)updated;
    }
    default:
      break;
  }
}

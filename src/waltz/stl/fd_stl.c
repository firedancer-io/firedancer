#include "fd_stl.h"

ulong
fd_stl_footprint( fd_stl_limits_t const * limits ) {
  /* AMAN TODO - revisit impl to use limits */
  (void)limits;
  return sizeof(fd_stl_t) + sizeof(fd_stl_state_private_t);
}

static ulong
fd_stl_clock_wallclock( void * ctx FD_PARAM_UNUSED ) {
  return (ulong)fd_log_wallclock();
}

void *
fd_stl_new( void* mem,
            fd_stl_limits_t const * limits ) {
  if( FD_UNLIKELY( !mem ) ) return NULL;
  if( FD_UNLIKELY( !limits ) ) return NULL;

  ulong align = fd_stl_align();
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, align ) ) ) return NULL;

  if( FD_UNLIKELY( limits->conn_cnt == 0UL ) ) {
    FD_LOG_WARNING(( "invalid limits" ));
    return NULL;
  }

  /* Zero the entire memory region */
  fd_stl_t * stl = (fd_stl_t *)mem;
  memset( stl, 0, fd_stl_footprint(limits) );

  /* default timing equipment */
  stl->cb.now = fd_stl_clock_wallclock;
  stl->cb.now_ctx = NULL;

  /* Store the limits */
  stl->limits = *limits;

  /* Initialize private data */
  fd_stl_state_private_t* priv = (fd_stl_state_private_t*)(stl+1);

  /* Initialize session arrays */
  priv->session_sz = 0;
  priv->client_hs_sz = 0;
  priv->server_hs_sz = 0;
  fd_rng_join( fd_rng_new( priv->_rng, 32, 44 ) );

  /* Set magic number to indicate successful initialization */
  FD_COMPILER_MFENCE();
  stl->magic = FD_STL_MAGIC;
  FD_COMPILER_MFENCE();

  return stl;
}

fd_stl_t *
fd_stl_join( void* shstl ) {
  /* AMAN TODO - revisit impl? */
  return shstl;
}


fd_stl_t *
fd_stl_init( fd_stl_t* stl ) {
  /* AMAN TODO - revisit impl? */
  return stl;
}

fd_stl_t *
fd_stl_fini( fd_stl_t* stl ) {
  /* AMAN TODO - revisit impl? */
  return stl;
}

int
fd_stl_service_timers( fd_stl_t * stl ) {
  /* AMAN TODO - implement me */
  (void)stl;
  return ~0;
}


int
fd_stl_send( fd_stl_t * stl,
             stl_net_ctx_t *  dst,
             void const *     data,
             ulong            data_sz) {
  dst->parts.padding = 0x0; /* always clear */
  /* TODO better error handling */
  if( data_sz > STL_BASIC_PAYLOAD_MTU ) {
    return -1;
  }

  /* first check if we already have a connection */
  fd_stl_state_private_t* priv = (fd_stl_state_private_t*)(stl+1);
  uchar i;
  for( i=0; i<FD_STL_MAX_SESSION_TMP; ++i ) {
    if( priv->sessions[i].socket_addr == dst->b ) {
      break;
    }
  }
  uchar buf[STL_MTU];
  long sz = 0;
  if( i < FD_STL_MAX_SESSION_TMP ) {
    /* we have a connection, just send on it */
    sz = fd_stl_s0_encode_appdata( priv->sessions+i, data, (ushort)data_sz, buf );
    if( sz < 0 ) {
      /* TODO - error handling */
      return -2;
    }
  } else {

    fd_stl_s0_client_hs_t* hs = NULL;
    for( i=0; i<priv->client_hs_sz; ++i ) {
      if( priv->client_hs[i].socket_addr == dst->b ) {
        hs = priv->client_hs + i;
        break;
      }
    }

    /* no pending hs, start one */
    if( !hs ) {
      if( priv->session_sz >= FD_STL_MAX_SESSION_TMP ) {
        FD_LOG_NOTICE(("STL session overflow")); /* TODO - change this */
      }

      hs = priv->client_hs + priv->client_hs_sz++;
      fd_stl_s0_client_hs_new( hs );
      hs->socket_addr = dst->b;

      fd_stl_s0_client_params_t params[1];
      sz = fd_stl_s0_client_initial( params , hs, buf );
    }

    /* buffer data */
    if( hs->buffers_sz >= FD_STL_MAX_BUF ) {
      FD_LOG_NOTICE(("STL buffer overflow")); /* TODO - change this */
      return -3;
    }

    fd_stl_payload_t* payload_buf = hs->buffers + hs->buffers_sz++;
    payload_buf->sz = (ushort)data_sz;
    fd_memcpy( payload_buf->data, data, data_sz );
  }

  if( sz > 0 ) {
    stl->cb.tx( stl, dst, buf, (ulong)sz );
  }
  return 0;
}

void
fd_stl_process_packet( fd_stl_t *     stl,
                       const uchar *  data,
                       ulong          data_sz,
                       uint          src_ip,
                       ushort          src_port ) {
  /* AMAN TODO - implement me */

  /* Create network context for the sender */
  stl_net_ctx_t sender = FD_STL_NET_CTX_T_EMPTY;
  sender.parts.ip4 = src_ip;
  sender.parts.port = src_port;

  /* Now data points to the STL payload and data_sz is the payload size */

  stl_s0_hs_pkt_t * pkt = (stl_s0_hs_pkt_t *)data;
  fd_stl_state_private_t* priv = (fd_stl_state_private_t*)(stl+1);

  uchar buf[STL_MTU];
  long send_sz = 0;

  int type = stl_hdr_type( &pkt->hs.base );

  if( FD_LIKELY( type == STL_TYPE_APP_SIMPLE ) ) {
    ushort i;
    for( i=0; i<priv->session_sz; ++i ) {
      /* TODO: clean up all the ulong/uchar[] punning */
      if( memcmp( &(priv->sessions[i].session_id), pkt->hs.base.session_id, STL_SESSION_ID_SZ ) == 0 ) {
        break;
      }
    }

    if( i == priv->session_sz ) {
      FD_LOG_ERR(("STL session not found"));
      return;
    }

    fd_stl_sesh_t* sesh = priv->sessions + i;

    /* check that the session IP and incoming IP match */
    if( sesh->socket_addr != sender.b ) {
      FD_LOG_ERR(("STL session IP mismatch"));
      return;
    }

    long rec_sz = fd_stl_s0_decode_appdata( sesh, data, (ushort)data_sz, buf );
    if( rec_sz < 0 ) {
      FD_LOG_ERR(("STL decode appdata failed"));
      return;
    }
    stl->cb.rx( stl, &sender, buf, (ulong)rec_sz );

    send_sz = 0;
  } else if( FD_UNLIKELY( type == STL_TYPE_HS_CLIENT_INITIAL ) ) {
    fd_stl_s0_server_hs_t* hs = priv->server_hs + priv->server_hs_sz++;
    send_sz = fd_stl_s0_server_handle_initial( &stl->server_params,
                                          &sender,
                                          pkt,
                                          buf,
                                          hs );
    if( send_sz < 0 ) {
      FD_LOG_ERR(("STL server handle initial failed"));
      return;
    }
  } else if( FD_UNLIKELY( type == STL_TYPE_HS_CLIENT_ACCEPT ) ) {
    ushort i;
    for( i=0; i<priv->server_hs_sz; ++i ) {
      if( memcmp( priv->server_hs[i].session_id, pkt->hs.base.session_id, STL_SESSION_ID_SZ ) == 0 ) {
        break;
      }
    }
    if( i == priv->server_hs_sz ) {
      FD_LOG_ERR(("STL server hs not found"));
      return;
    }
    fd_stl_s0_server_hs_t* hs = priv->server_hs + i;
    fd_stl_sesh_t* sesh = priv->sessions + priv->session_sz++;
    uchar to_sign[32]; //FIXME: need to sign this
    send_sz = fd_stl_s0_server_handle_accept( &stl->server_params,
                                          &sender,
                                          pkt,
                                          buf,
                                          to_sign,
                                          hs,
                                          sesh );
    if( send_sz < 0 ) {
      FD_LOG_ERR(("STL server handle accept failed"));
      return;
    }
  } else if( FD_UNLIKELY( type == STL_TYPE_HS_SERVER_CONTINUE ) ) {
    ushort i;
    for( i=0; i<priv->client_hs_sz; ++i ) {
      if( priv->client_hs[i].socket_addr == sender.b ) {
        break;
      }
    }
    if( i == priv->client_hs_sz ) {
      FD_LOG_ERR(("STL client hs not found"));
      return;
    }
    fd_stl_s0_client_hs_t* hs = priv->client_hs + i;

    uchar to_sign[32]; //FIXME: need to sign this
    send_sz = fd_stl_s0_client_handle_continue( &stl->client_params,
                                          pkt,
                                          buf,
                                          to_sign,
                                          hs );
    if( send_sz < 0 ) {
      FD_LOG_ERR(("STL client handle continue failed"));
      return;
    }
  } else if( FD_UNLIKELY( type == STL_TYPE_HS_SERVER_ACCEPT ) ) {
    ushort i;
    for( i=0; i<priv->client_hs_sz; ++i ) {
      if( priv->client_hs[i].socket_addr == sender.b ) {
        break;
      }
    }
    if( i == priv->client_hs_sz ) {
      FD_LOG_HEXDUMP_ERR(("STL client hs not found for session id:", pkt->hs.base.session_id, STL_SESSION_ID_SZ));
      return;
    }
    fd_stl_s0_client_hs_t* hs = priv->client_hs + i;
    send_sz = fd_stl_s0_client_handle_accept( stl,
                                         &stl->client_params,
                                         pkt,
                                         hs );
    if( send_sz < 0 ) {
      FD_LOG_ERR(("STL client handle accept failed"));
      return;
    }

    /* resend buffered */
    for( i=0; i<priv->session_sz; ++i ) {
      if( priv->sessions[i].session_id == FD_LOAD( ulong, hs->session_id ) ) {
        break;
      }
    }
    FD_TEST( i < priv->session_sz );
    fd_stl_sesh_t* sesh = priv->sessions + i;

    uchar scratch[STL_MTU];
    stl_net_ctx_t sock_addr = FD_STL_NET_CTX_T_EMPTY;
    for (uchar i = 0; i < hs->buffers_sz; i++) {
      long sz = fd_stl_s0_encode_appdata( sesh, hs->buffers[i].data, hs->buffers[i].sz, scratch );
      if (sz > 0) {
        sock_addr.b = sesh->socket_addr;
        stl->cb.tx( stl, &sock_addr, scratch, (ulong)sz );
      }
    }

  } else {
    FD_LOG_NOTICE(("stl_process_packet: Unknown hdr type %d", type));
  }
  if( send_sz > 0 ) {
    stl->cb.tx( stl, &sender, buf, (ulong)send_sz );
  }
}


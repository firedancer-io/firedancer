#include "fd_snp.h"

ulong
fd_snp_footprint( fd_snp_limits_t const * limits ) {
  /* AMAN TODO - revisit impl to use limits */
  (void)limits;
  return sizeof(fd_snp_t) + sizeof(fd_snp_state_private_t);
}

static ulong
fd_snp_clock_wallclock( void * ctx FD_PARAM_UNUSED ) {
  return (ulong)fd_log_wallclock();
}

void *
fd_snp_new( void* mem,
            fd_snp_limits_t const * limits ) {
  if( FD_UNLIKELY( !mem ) ) return NULL;
  if( FD_UNLIKELY( !limits ) ) return NULL;

  ulong align = fd_snp_align();
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, align ) ) ) return NULL;

  if( FD_UNLIKELY( limits->conn_cnt == 0UL ) ) {
    FD_LOG_WARNING(( "invalid limits" ));
    return NULL;
  }

  /* Zero the entire memory region */
  fd_snp_t * snp = (fd_snp_t *)mem;
  memset( snp, 0, fd_snp_footprint(limits) );

  /* default timing equipment */
  snp->cb.now = fd_snp_clock_wallclock;
  snp->cb.now_ctx = NULL;

  /* Store the limits */
  snp->limits = *limits;

  /* Initialize private data */
  fd_snp_state_private_t* priv = (fd_snp_state_private_t*)(snp+1);

  /* Initialize session arrays */
  priv->session_sz = 0;
  priv->client_hs_sz = 0;
  priv->server_hs_sz = 0;
  fd_rng_join( fd_rng_new( priv->_rng, 32, 44 ) );

  /* Set magic number to indicate successful initialization */
  FD_COMPILER_MFENCE();
  snp->magic = FD_SNP_MAGIC;
  FD_COMPILER_MFENCE();

  return snp;
}

fd_snp_t *
fd_snp_join( void* shsnp ) {
  /* AMAN TODO - revisit impl? */
  return shsnp;
}


fd_snp_t *
fd_snp_init( fd_snp_t* snp ) {
  /* AMAN TODO - revisit impl? */
  return snp;
}

fd_snp_t *
fd_snp_fini( fd_snp_t* snp ) {
  /* AMAN TODO - revisit impl? */
  return snp;
}

int
fd_snp_service_timers( fd_snp_t * snp ) {
  /* AMAN TODO - implement me */
  (void)snp;
  return ~0;
}


int
fd_snp_send( fd_snp_t * snp,
             snp_net_ctx_t *  dst,
             void const *     data,
             ulong            data_sz) {
  dst->parts.padding = 0x0; /* always clear */
  /* TODO better error handling */
  if( data_sz > SNP_BASIC_PAYLOAD_MTU ) {
    return -1;
  }

  /* first check if we already have a connection */
  fd_snp_state_private_t* priv = (fd_snp_state_private_t*)(snp+1);
  uchar i;
  for( i=0; i<FD_SNP_MAX_SESSION_TMP; ++i ) {
    if( priv->sessions[i].socket_addr == dst->b ) {
      break;
    }
  }
  uchar buf[SNP_MTU];
  long sz = 0;
  if( i < FD_SNP_MAX_SESSION_TMP ) {
    /* we have a connection, just send on it */
    sz = fd_snp_s0_encode_appdata( priv->sessions+i, data, (ushort)data_sz, buf );
    if( sz < 0 ) {
      /* TODO - error handling */
      return -2;
    }
  } else {

    fd_snp_s0_client_hs_t* hs = NULL;
    for( i=0; i<priv->client_hs_sz; ++i ) {
      if( priv->client_hs[i].socket_addr == dst->b ) {
        hs = priv->client_hs + i;
        break;
      }
    }

    /* no pending hs, start one */
    if( !hs ) {
      if( priv->session_sz >= FD_SNP_MAX_SESSION_TMP ) {
        FD_LOG_NOTICE(("SNP session overflow: %u", priv->session_sz)); /* TODO - change this */
      }

      hs = priv->client_hs + priv->client_hs_sz++;
      fd_snp_s0_client_hs_new( hs );
      hs->socket_addr = dst->b;

      fd_snp_s0_client_params_t params[1];
      sz = fd_snp_s0_client_initial( params , hs, buf );
    }

    /* buffer data */
    if( hs->buffers_sz >= FD_SNP_MAX_BUF ) {
      FD_LOG_NOTICE(("SNP buffer overflow %u", hs->buffers_sz)); /* TODO - change this */
      return -3;
    }

    fd_snp_payload_t* payload_buf = hs->buffers + hs->buffers_sz++;
    payload_buf->sz = (ushort)data_sz;
    fd_memcpy( payload_buf->data, data, data_sz );
  }

  if( sz > 0 ) {
    snp->cb.tx( snp, dst, buf, (ulong)sz );
  }
  return 0;
}

void
fd_snp_process_packet( fd_snp_t *     snp,
                       const uchar *  data,
                       ulong          data_sz,
                       uint           src_ip,
                       ushort         src_port ) {
  /* AMAN TODO - implement me */

  /* Create network context for the sender */
  snp_net_ctx_t sender = FD_SNP_NET_CTX_T_EMPTY;
  sender.parts.ip4 = src_ip;
  sender.parts.port = src_port;

  /* Now data points to the SNP payload and data_sz is the payload size */

  snp_s0_hs_pkt_t * pkt = (snp_s0_hs_pkt_t *)data;
  fd_snp_state_private_t* priv = (fd_snp_state_private_t*)(snp+1);

  uchar buf[SNP_MTU];
  long send_sz = 0;

  int type = snp_hdr_type( &pkt->hs.base );

  if( FD_LIKELY( type == SNP_TYPE_APP_SIMPLE ) ) {
    ushort i;
    for( i=0; i<priv->session_sz; ++i ) {
      /* TODO: clean up all the ulong/uchar[] punning */
      if( memcmp( &(priv->sessions[i].session_id), pkt->hs.base.session_id, SNP_SESSION_ID_SZ ) == 0 ) {
        break;
      }
    }

    if( i == priv->session_sz ) {
      FD_LOG_ERR(("SNP session not found"));
      return;
    }

    fd_snp_sesh_t* sesh = priv->sessions + i;

    /* check that the session IP and incoming IP match */
    if( sesh->socket_addr != sender.b ) {
      FD_LOG_ERR(("SNP session IP mismatch"));
      return;
    }

    long rec_sz = fd_snp_s0_decode_appdata( sesh, data, (ushort)data_sz, buf );
    if( rec_sz < 0 ) {
      FD_LOG_ERR(("SNP decode appdata failed"));
      return;
    }
    snp->cb.rx( snp, &sender, buf, (ulong)rec_sz );

    send_sz = 0;
  } else if( FD_UNLIKELY( type == SNP_TYPE_HS_CLIENT_INITIAL ) ) {
    fd_snp_s0_server_hs_t* hs = priv->server_hs + priv->server_hs_sz++;
    send_sz = fd_snp_s0_server_handle_initial( &snp->server_params,
                                          &sender,
                                          pkt,
                                          buf,
                                          hs );
    if( send_sz < 0 ) {
      FD_LOG_ERR(("SNP server handle initial failed"));
      return;
    }
  } else if( FD_UNLIKELY( type == SNP_TYPE_HS_CLIENT_ACCEPT ) ) {
    ushort i;
    for( i=0; i<priv->server_hs_sz; ++i ) {
      if( memcmp( priv->server_hs[i].session_id, pkt->hs.base.session_id, SNP_SESSION_ID_SZ ) == 0 ) {
        break;
      }
    }
    if( i == priv->server_hs_sz ) {
      FD_LOG_ERR(("SNP server hs not found"));
      return;
    }
    fd_snp_s0_server_hs_t* hs = priv->server_hs + i;
    fd_snp_sesh_t* sesh = priv->sessions + priv->session_sz++;
    uchar to_sign[32]; //FIXME: need to sign this
    send_sz = fd_snp_s0_server_handle_accept( &snp->server_params,
                                          &sender,
                                          pkt,
                                          buf,
                                          to_sign,
                                          hs,
                                          sesh );
    if( send_sz < 0 ) {
      FD_LOG_ERR(("SNP server handle accept failed"));
      return;
    }
  } else if( FD_UNLIKELY( type == SNP_TYPE_HS_SERVER_CONTINUE ) ) {
    ushort i;
    for( i=0; i<priv->client_hs_sz; ++i ) {
      if( priv->client_hs[i].socket_addr == sender.b ) {
        break;
      }
    }
    if( i == priv->client_hs_sz ) {
      FD_LOG_ERR(("SNP client hs not found"));
      return;
    }
    fd_snp_s0_client_hs_t* hs = priv->client_hs + i;

    uchar to_sign[32]; //FIXME: need to sign this
    send_sz = fd_snp_s0_client_handle_continue( &snp->client_params,
                                          pkt,
                                          buf,
                                          to_sign,
                                          hs );
    if( send_sz < 0 ) {
      FD_LOG_ERR(("SNP client handle continue failed"));
      return;
    }
  } else if( FD_UNLIKELY( type == SNP_TYPE_HS_SERVER_ACCEPT ) ) {
    ushort i;
    for( i=0; i<priv->client_hs_sz; ++i ) {
      if( priv->client_hs[i].socket_addr == sender.b ) {
        break;
      }
    }
    if( i == priv->client_hs_sz ) {
      FD_LOG_HEXDUMP_ERR(("SNP client hs not found for session id:", pkt->hs.base.session_id, SNP_SESSION_ID_SZ));
      return;
    }
    fd_snp_s0_client_hs_t* hs = priv->client_hs + i;
    send_sz = fd_snp_s0_client_handle_accept( snp,
                                         &snp->client_params,
                                         pkt,
                                         hs );
    if( send_sz < 0 ) {
      FD_LOG_ERR(("SNP client handle accept failed"));
      return;
    }

    /* resend buffered */
    for( i=0; i<priv->session_sz; ++i ) {
      if( priv->sessions[i].session_id == FD_LOAD( ulong, hs->session_id ) ) {
        break;
      }
    }
    FD_TEST( i < priv->session_sz );
    fd_snp_sesh_t* sesh = priv->sessions + i;

    uchar scratch[SNP_MTU];
    snp_net_ctx_t sock_addr = FD_SNP_NET_CTX_T_EMPTY;
    for (uchar i = 0; i < hs->buffers_sz; i++) {
      long sz = fd_snp_s0_encode_appdata( sesh, hs->buffers[i].data, hs->buffers[i].sz, scratch );
      if (sz > 0) {
        sock_addr.b = sesh->socket_addr;
        snp->cb.tx( snp, &sock_addr, scratch, (ulong)sz );
      }
    }

  } else {
    FD_LOG_NOTICE(("snp_process_packet: Unknown hdr type %d", type));
  }
  if( send_sz > 0 ) {
    snp->cb.tx( snp, &sender, buf, (ulong)send_sz );
  }
}


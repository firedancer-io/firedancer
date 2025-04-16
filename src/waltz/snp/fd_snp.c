#include "fd_snp.h"

ulong
fd_snp_footprint( fd_snp_limits_t const * limits ) {
  /* AMAN TODO - revisit impl to use limits */
  (void)limits;
  return sizeof(fd_snp_t);// + sizeof(fd_snp_state_private_t);
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
  fd_snp_state_private_t* priv = snp->priv;

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
  return shsnp;
}


fd_snp_t *
fd_snp_init( fd_snp_t * snp ) {

  /* Initialize apps */
  if( FD_UNLIKELY( snp->apps_cnt > sizeof(snp->apps)/sizeof(fd_snp_applications_t) ) ) {
    FD_LOG_WARNING(( "[snp] invalid apps_cnt=%lu", snp->apps_cnt ));
    return NULL;
  }
  for( ulong j=0; j<snp->apps_cnt; j++ ) {
    if( FD_UNLIKELY( snp->apps[j].port==0 ) ) {
      FD_LOG_WARNING(( "[snp] invalid apps[%lu].port=%hu", j, snp->apps[j].port ));
      return NULL;
    }  
    fd_ip4_udp_hdr_init( snp->apps[j].net_hdr, 0, 0, snp->apps[j].port );
  }

  return snp;
}

fd_snp_t *
fd_snp_fini( fd_snp_t* snp ) {
  return snp;
}

int
fd_snp_service_timers( fd_snp_t * snp ) {
  (void)snp;
  return ~0;
}

static inline int
fd_snp_finalize_udp_and_invoke_tx_cb( 
  fd_snp_t *    snp,
  uchar *       packet,
  ulong         packet_sz, 
  fd_snp_meta_t meta
) {
  if( FD_UNLIKELY( packet_sz==0 ) ) {
    return 0;
  }

  uchar snp_app_id;
  ushort dst_port;
  uint dst_ip;
  fd_snp_meta_into_parts( NULL, &snp_app_id, &dst_ip, &dst_port, meta );

  fd_ip4_udp_hdrs_t * hdr = (fd_ip4_udp_hdrs_t *)packet;
  *hdr = *( snp->apps[ snp_app_id ].net_hdr );
  fd_ip4_hdr_t * ip4 = hdr->ip4;
  ip4->daddr  = dst_ip;
  ip4->net_id = fd_ushort_bswap( snp->apps[ snp_app_id ].net_id++ );
  ip4->check  = 0U;
  ip4->check  = fd_ip4_hdr_check_fast( ip4 );
  hdr->udp->net_dport  = fd_ushort_bswap( dst_port );
  hdr->udp->net_len    = fd_ushort_bswap( (ushort)( packet_sz - sizeof(fd_ip4_udp_hdrs_t) + sizeof(fd_udp_hdr_t) ) );

  return snp->cb.tx ? snp->cb.tx( snp->cb.ctx, packet, packet_sz, meta ) : (int)packet_sz;
}

/* Workflow:
   - Validate input
   - If proto==UDP, send packet as UDP
   - Query connection by peer (meta)
   - If we have a connection, send packet (connect only: return)
   - Else, create a new connection
   - Cache current packet (connect only: do nothing)
   - Prepare client_initial, overwrite packet
   - Send packet */
int
fd_snp_send( fd_snp_t *    snp,
             uchar *       packet,
             ulong         packet_sz, 
             fd_snp_meta_t meta ) {
  // dst->parts.padding = 0x0; /* always clear */
  /* TODO better error handling */
  if( packet_sz > SNP_BASIC_PAYLOAD_MTU ) {
    return -1;
  }

  ulong proto = meta & FD_SNP_META_PROTO_MASK;
  if( proto==FD_SNP_META_PROTO_UDP ) {
    FD_LOG_INFO(( "[SNP] UDP send" ));
    return fd_snp_finalize_udp_and_invoke_tx_cb( snp, packet, packet_sz, meta );
  }

  /* first check if we already have a connection */
  fd_snp_state_private_t* priv = snp->priv;
  uchar i;
  for( i=0; i<FD_SNP_MAX_SESSION_TMP; ++i ) {
    if( priv->sessions[i].socket_addr == meta ) {
      break;
    }
  }

  long sz = 0;
  if( i < FD_SNP_MAX_SESSION_TMP ) {
    if( FD_UNLIKELY( packet_sz==0 ) ) {
      FD_LOG_INFO(( "[SNP] connect only" ));
      return 0;
    }

    /* we have a connection, just send on it */
    sz = fd_snp_s0_finalize_packet( priv->sessions+i, packet, (ushort)packet_sz );
    if( sz < 0 ) {
      /* TODO - error handling */
      return -2;
    }
    FD_LOG_INFO(( "[SNP] send" ));
    return fd_snp_finalize_udp_and_invoke_tx_cb( snp, packet, packet_sz, meta );
  }

  fd_snp_s0_client_hs_t* hs = NULL;
  for( i=0; i<priv->client_hs_sz; ++i ) {
    if( priv->client_hs[i].socket_addr == meta ) {
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
    hs->socket_addr = meta & FD_SNP_META_PEER_MASK;

    /* buffer data */
    if( hs->buffers_sz >= FD_SNP_MAX_BUF ) {
      FD_LOG_NOTICE(("SNP buffer overflow %u", hs->buffers_sz)); /* TODO - change this */
      return -3;
    }
    if( packet_sz > 0 ) {
      fd_snp_payload_t* payload_buf = hs->buffers + hs->buffers_sz++;
      payload_buf->sz = (ushort)packet_sz;
      fd_memcpy( payload_buf->data, packet, packet_sz );
    }

    FD_LOG_INFO(( "[SNP] client initial" ));
    fd_snp_s0_client_params_t params[1];
    sz = fd_snp_s0_client_initial( params, hs, packet + sizeof(fd_ip4_udp_hdrs_t) ); //TODO: client_initial only touches UDP payload
  }

  if( sz > 0 ) {
    return fd_snp_finalize_udp_and_invoke_tx_cb( snp, packet, (ulong)sz + sizeof(fd_ip4_udp_hdrs_t), meta );
  }
  return 0;
}

/* Workflow:
   - Validate input
   - Derive meta (which app to send the packet to)
   - If proto==UDP, recv packet as UDP
   - Query connection by sid
   - If connection is established, recv packet (validate integrity, etc.)
   - Process handshake
   - Send packet */
int
fd_snp_process_packet( fd_snp_t * snp,
                       uchar *    packet,
                       ulong      packet_sz ) {

  /* Create network context for the sender */
  fd_ip4_udp_hdrs_t * hdr  = (fd_ip4_udp_hdrs_t *)packet;
  uint src_ip = hdr->ip4->saddr;
  ushort src_port = fd_ushort_bswap( hdr->udp->net_sport );
  ushort dst_port = fd_ushort_bswap( hdr->udp->net_dport );
  uchar snp_app_id;
  for( snp_app_id=0U; snp_app_id<snp->apps_cnt; snp_app_id++ ) {
    if( snp->apps[ snp_app_id ].port == dst_port ) {
      break;
    }
  }
  if( FD_UNLIKELY( snp_app_id>=snp->apps_cnt ) ) {
    /* The packet is not for SNP, ignore */
    FD_LOG_WARNING(( "[SNP] app not found for dst_port=%u", dst_port ));
    return -1;
  }

  uchar const * magic = packet + sizeof(fd_ip4_udp_hdrs_t) + 1;
  ulong proto = FD_SNP_META_PROTO_UDP;
  if( (*magic)=='S' && (*(magic+1))=='O' && (*(magic+2))=='L' ) {
    proto = FD_SNP_META_PROTO_V1;
  }

  //FIXME app_id from src_port
  fd_snp_meta_t meta = fd_snp_meta_from_parts( proto, snp_app_id, src_ip, src_port );
  FD_LOG_WARNING(( "meta=%lu proto=%lu dst_ip=%u dst_port=%u", meta, proto, src_ip, src_port ));
  if( proto==FD_SNP_META_PROTO_UDP ) {
    return snp->cb.rx( snp->cb.ctx, packet, packet_sz, meta );
  }

  snp_net_ctx_t sender = FD_SNP_NET_CTX_T_EMPTY;
  sender.b = meta & FD_SNP_META_PEER_MASK;
  //FIXME
  // sender.parts.ip4 = src_ip;
  // sender.parts.port = src_port;

  /* Now data points to the SNP payload and data_sz is the payload size */

  snp_s0_hs_pkt_t * pkt = (snp_s0_hs_pkt_t *)(packet + sizeof(fd_ip4_udp_hdrs_t));
  fd_snp_state_private_t* priv = snp->priv;

  // uchar _buf[SNP_MTU];
  uchar * buf = packet + sizeof(fd_ip4_udp_hdrs_t);
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
      return -1;
    }

    fd_snp_sesh_t* sesh = priv->sessions + i;

    /* check that the session IP and incoming IP match */
    if( sesh->socket_addr != sender.b ) {
      FD_LOG_ERR(("SNP session IP mismatch"));
      return -1;
    }

    // FIXME: responsibility of fd_snp_app_recv()
    // long rec_sz = fd_snp_s0_decode_appdata( sesh, data, (ushort)data_sz, buf );
    // if( rec_sz < 0 ) {
    //   FD_LOG_ERR(("SNP decode appdata failed"));
    //   return;
    // }
    return snp->cb.rx( snp->cb.ctx, packet, packet_sz, sesh->socket_addr );
  } 
  
  if( FD_UNLIKELY( type == SNP_TYPE_HS_CLIENT_INITIAL ) ) {
    fd_snp_s0_server_hs_t* hs = priv->server_hs + priv->server_hs_sz++;
    FD_LOG_INFO(( "[SNP] server initial" ));
    send_sz = fd_snp_s0_server_handle_initial( &snp->server_params,
                                          &sender,
                                          pkt,
                                          buf,
                                          hs );
    if( send_sz < 0 ) {
      FD_LOG_ERR(("SNP server handle initial failed"));
      return -1;
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
      return -1;
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
    FD_LOG_INFO(( "[SNP] server accept session_id=%lu", sesh->session_id ));
    if( send_sz < 0 ) {
      FD_LOG_ERR(("SNP server handle accept failed"));
      return -1;
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
      return -1;
    }
    fd_snp_s0_client_hs_t* hs = priv->client_hs + i;

    uchar to_sign[32]; //FIXME: need to sign this
    FD_LOG_INFO(( "[SNP] client continue" ));
    send_sz = fd_snp_s0_client_handle_continue( &snp->client_params,
                                          pkt,
                                          buf,
                                          to_sign,
                                          hs );
    if( send_sz < 0 ) {
      FD_LOG_ERR(("SNP client handle continue failed"));
      return -1;
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
      return -1;
    }
    fd_snp_s0_client_hs_t* hs = priv->client_hs + i;
    fd_snp_sesh_t* sesh = priv->sessions + priv->session_sz++;
    send_sz = fd_snp_s0_client_handle_accept( snp,
                                         &snp->client_params,
                                         pkt,
                                         hs,
                                         sesh );
    if( send_sz < 0 ) {
      FD_LOG_ERR(("SNP client handle accept failed"));
      return -1;
    }

    /* resend buffered */
    // for( i=0; i<priv->session_sz; ++i ) {
    //   if( priv->sessions[i].session_id == FD_LOAD( ulong, hs->session_id ) ) {
    //     break;
    //   }
    // }
    // FD_TEST( i < priv->session_sz ); //FIXME
    // i = 0;

    // uchar scratch[SNP_MTU];
    // snp_net_ctx_t sock_addr = FD_SNP_NET_CTX_T_EMPTY;
    for (uchar i = 0; i < hs->buffers_sz; i++) {
      FD_LOG_INFO(( "[SNP] client send (buffered) session_id=%lu", sesh->session_id ));
      long sz = fd_snp_s0_finalize_packet( sesh, hs->buffers[i].data, (ushort)hs->buffers[i].sz );
      if (sz > 0) {
        // sock_addr.b = sesh->socket_addr;
        meta |= FD_SNP_META_OPT_BUFFERED;
        FD_LOG_INFO(( "[SNP] send (buffered)" ));
        return fd_snp_finalize_udp_and_invoke_tx_cb( snp, hs->buffers[i].data, hs->buffers[i].sz, meta );
      }
    }

  } else {
    FD_LOG_NOTICE(("snp_process_packet: Unknown hdr type %d", type));
  }
  if( send_sz > 0 ) {
    FD_LOG_INFO(( "[SNP] send (unbuffered)" ));
    return fd_snp_finalize_udp_and_invoke_tx_cb( snp, packet, (ulong)send_sz + sizeof(fd_ip4_udp_hdrs_t), meta );
  }
  return 0;
}


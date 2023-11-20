#include "fd_quic_tls.h"
#include "../fd_quic_private.h"
#include "../../../ballet/ed25519/fd_ed25519.h"
#include "../../../ballet/ed25519/fd_x25519.h"
#include "../../../ballet/x509/fd_x509_mock.h"
#include "../../../util/fd_util.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/uio.h>

/* fd_tls callbacks provided by fd_quic *******************************/

/* fd_quic_tls_sendmsg is called by fd_tls when fd_quic should send a
   CRYPTO frame to the peer.  Currently, we can assume that the
   encryption_level will never decrease (INITIAL => HANDSHAKE => APP) */

int
fd_quic_tls_sendmsg( void const * handshake,
                     void const * record,
                     ulong        record_sz,
                     uint         encryption_level,
                     int          flush );

/* fd_quic_tls_secrets is called by fd_tls when new encryption keys
   become available.  Currently, this is called at most two times per
   connection:  For the handshake secrets, and for the initial app-level
   secrets. */

void
fd_quic_tls_secrets( void const * handshake,
                     void const * recv_secret,
                     void const * send_secret,
                     uint         encryption_level );

/* fd_quic_tls_rand is the RNG provided to fd_tls.  Note: This is
   a layering violation ... The user should pass the CSPRNG handle to
   both fd_quic and fd_tls.  Currently, implemented via the getrandom()
   syscall ... Inefficient! */

void *
fd_quic_tls_rand( void * ctx,
                  void * buf,
                  ulong  bufsz );

/* fd_quic_tls_tp_self is called by fd_tls to retrieve fd_quic's QUIC
   transport parameters. */

ulong
fd_quic_tls_tp_self( void *  handshake,
                     uchar * quic_tp,
                     ulong   quic_tp_bufsz );

/* fd_quic_tls_tp_self is called by fd_tls to inform fd_quic of the
   peer's QUIC transport parameters. */

void
fd_quic_tls_tp_peer( void *        handshake,
                     uchar const * quic_tp,
                     ulong         quic_tp_sz );

/* fd_quic_tls lifecycle API ******************************************/

ulong
fd_quic_tls_align( void ) {
  return alignof( fd_quic_tls_t );
}

/* fd_quic_tls_layout_t describes the memory layout on an fd_quic_tls_t */
struct fd_quic_tls_layout {
  ulong handshakes_off;
  ulong handshakes_used_off;
};
typedef struct fd_quic_tls_layout fd_quic_tls_layout_t;

ulong
fd_quic_tls_footprint_ext( ulong handshake_cnt,
                           fd_quic_tls_layout_t * layout ) {

  ulong off  = sizeof( fd_quic_tls_t );

        off  = fd_ulong_align_up( off, alignof( fd_quic_tls_hs_t ) );
  layout->handshakes_off = off;
        off += handshake_cnt * sizeof( fd_quic_tls_hs_t );

        /* no align required */
  layout->handshakes_used_off = off;
        off += handshake_cnt; /* used handshakes */

  return off;
}

ulong
fd_quic_tls_footprint( ulong handshake_cnt ) {
  fd_quic_tls_layout_t layout;
  return fd_quic_tls_footprint_ext( handshake_cnt, &layout );
}

static void
fd_quic_tls_init( fd_tls_t * tls );

fd_quic_tls_t *
fd_quic_tls_new( void *              mem,
                 fd_quic_tls_cfg_t * cfg ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !cfg ) ) {
    FD_LOG_WARNING(( "NULL cfg" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, alignof( fd_quic_tls_t ) ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong handshake_cnt = cfg->max_concur_handshakes;

  fd_quic_tls_layout_t layout = {0};
  ulong footprint = fd_quic_tls_footprint_ext( handshake_cnt, &layout );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "invalid footprint for config" ));
    return NULL;
  }

  fd_quic_tls_t * self = (fd_quic_tls_t *)mem;

  self->alert_cb              = cfg->alert_cb;
  self->secret_cb             = cfg->secret_cb;
  self->handshake_complete_cb = cfg->handshake_complete_cb;
  self->max_concur_handshakes = cfg->max_concur_handshakes;

  ulong handshakes_laddr = (ulong)mem + layout.handshakes_off;
  fd_quic_tls_hs_t * handshakes = (fd_quic_tls_hs_t *)(handshakes_laddr);
  self->handshakes = handshakes;

  /* FIXME use a bitmap instead of an array */
  ulong used_handshakes_laddr = (ulong)mem + layout.handshakes_used_off;
  uchar * used_handshakes = (uchar *)(used_handshakes_laddr);
  self->used_handshakes = used_handshakes;

  // set all to free
  fd_memset( used_handshakes, 0, (ulong)self->max_concur_handshakes );

  /* Initialize fd_tls */
  fd_quic_tls_init( &self->tls );

  return self;
}

/* fd_quic_tls_init is called as part of fd_quic_tls_new.  It sets up
   the embedded fd_tls instance. */

static void
fd_quic_tls_init( fd_tls_t * tls ) {
  tls = fd_tls_new( tls );

  *tls = (fd_tls_t) {
    .quic = 1,
    .rand = {
      .ctx     = NULL,
      .rand_fn = fd_quic_tls_rand
    },
    .secrets_fn = fd_quic_tls_secrets,
    .sendmsg_fn = fd_quic_tls_sendmsg,

    .quic_tp_self_fn = fd_quic_tls_tp_self,
    .quic_tp_peer_fn = fd_quic_tls_tp_peer,
  };

  /* Generate X25519 key */
  if( FD_UNLIKELY( 32L!=getrandom( tls->kex_private_key, 32UL, 0 ) ) )
    FD_LOG_ERR(( "getrandom failed: %s", fd_io_strerror( errno ) ));
  fd_x25519_public( tls->kex_public_key, tls->kex_private_key );

  /* Set Ed25519 key */
  fd_sha512_t sha[1];  /* does this need a join? */
  fd_memcpy( tls->cert_private_key, tls->kex_private_key, 32UL );
  fd_ed25519_public_from_private( tls->cert_public_key, tls->cert_private_key, sha );

  /* Generate X.509 cert */
  ulong cert_serial;
  if( FD_UNLIKELY( 8L!=getrandom( &cert_serial, 8UL, 0 ) ) )
    FD_LOG_ERR(( "getrandom failed: %s", fd_io_strerror( errno ) ));
  fd_x509_mock_cert( tls->cert_x509, tls->cert_private_key, cert_serial, sha );
  tls->cert_x509_sz = FD_X509_MOCK_CERT_SZ;

  /* Set ALPN protocol ID
     (Technically, don't need to copy the length prefix but we'll do
      so anyways.) */
  tls->alpn[ 0 ] = 0x0a;
  memcpy( tls->alpn+1, "solana-tpu", 11UL );
  tls->alpn_sz = 11UL;
}

void *
fd_quic_tls_delete( fd_quic_tls_t * self ) {
  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL self" ));
    return NULL;
  }

  // free up all used handshakes
  ulong              hs_sz   = (ulong)self->max_concur_handshakes;
  fd_quic_tls_hs_t * hs      = self->handshakes;
  uchar *            hs_used = self->used_handshakes;
  for( ulong j = 0; j < hs_sz; ++j ) {
    if( hs_used[j] ) fd_quic_tls_hs_delete( hs + j );
  }

  /* Clear secret data */
  fd_memset( &self->tls, 0, sizeof(fd_tls_t) );

  return self;
}

fd_quic_tls_hs_t *
fd_quic_tls_hs_new( fd_quic_tls_t * quic_tls,
                    void *          context,
                    int             is_server,
                    char const *    hostname,
                    uchar const *   transport_params_raw,
                    ulong           transport_params_raw_sz ) {
  // find a free handshake
  ulong hs_idx = 0;
  ulong hs_sz  = (ulong)quic_tls->max_concur_handshakes;
  uchar * hs_used = quic_tls->used_handshakes;
  while( hs_idx < hs_sz && hs_used[hs_idx] ) hs_idx++;

  // no room
  if( hs_idx == hs_sz ) {
    FD_DEBUG( FD_LOG_DEBUG(( "tls_hs alloc fail" )) );
    return NULL;
  }

  FD_DEBUG( FD_LOG_DEBUG(( "tls_hs alloc %lu", hs_idx )) );

  // self is the handshake at hs_idx
  fd_quic_tls_hs_t * self = quic_tls->handshakes + hs_idx;
  FD_TEST( fd_ulong_is_aligned( (ulong)self, alignof(fd_quic_tls_hs_t) ) );

  // clear the handshake bits
  fd_memset( self, 0, sizeof(fd_quic_tls_hs_t) );

  // set properties on self
  self->quic_tls  = quic_tls;
  self->is_server = is_server;
  self->is_flush  = 0;
  self->context   = context;
  self->state     = is_server ? FD_QUIC_TLS_HS_STATE_NEED_INPUT : FD_QUIC_TLS_HS_STATE_NEED_SERVICE;

  /* initialize handshake data */

  /* init free list */
  self->hs_data_free_idx = 0u; /* head points at first */
  for( ushort j = 0u; j < FD_QUIC_TLS_HS_DATA_CNT; ++j ) {
    if( j < FD_QUIC_TLS_HS_DATA_CNT-1u ) {
      self->hs_data[j].next_idx = (ushort)(j+1u); /* each point to next */
    } else {
      self->hs_data[j].next_idx = FD_QUIC_TLS_HS_DATA_UNUSED ;
    }
  }

  /* no data pending */
  for( unsigned j = 0; j < 4; ++j ) {
    self->hs_data_pend_idx[j]     = FD_QUIC_TLS_HS_DATA_UNUSED;
    self->hs_data_pend_end_idx[j] = FD_QUIC_TLS_HS_DATA_UNUSED;
  }

  /* set head and tail of used hs_data */
  self->hs_data_buf_head = 0;
  self->hs_data_buf_tail = 0;

  /* all handshake offsets start at zero */
  fd_memset( self->hs_data_offset, 0, sizeof( self->hs_data_offset ) );

  if( is_server ) {
    fd_tls_estate_srv_new( &self->hs.srv );
  } else {
    fd_tls_estate_cli_new( &self->hs.cli );
  }

  /* TODO set TLS hostname if client */
  (void)hostname;

  /* Set QUIC transport params */
  FD_TEST( transport_params_raw_sz <= sizeof(self->self_transport_params) );
  self->self_transport_params_sz = (uchar)transport_params_raw_sz;
  fd_memcpy( self->self_transport_params, transport_params_raw, transport_params_raw_sz );

  /* Mark handshake as used */
  hs_used[hs_idx] = 1;
  return self;
}

void
fd_quic_tls_hs_delete( fd_quic_tls_hs_t * self ) {
  if( !self ) return;

  self->state = FD_QUIC_TLS_HS_STATE_DEAD;

  fd_quic_tls_t * quic_tls = self->quic_tls;

  // find index into array
  ulong hs_idx = (ulong)( self - quic_tls->handshakes );
  FD_DEBUG( FD_LOG_DEBUG(( "tls_hs free %lu", hs_idx )) );
  if( quic_tls->used_handshakes[hs_idx] != 1 ) {
    return;
  }

  if( self->is_server )
    fd_tls_estate_srv_delete( &self->hs.srv );
  else
    fd_tls_estate_cli_delete( &self->hs.cli );

  // set used at the given index to zero to free
  quic_tls->used_handshakes[hs_idx] = 0;
}

int
fd_quic_tls_provide_data( fd_quic_tls_hs_t * self,
                          uint               enc_level,
                          uchar const *      data,
                          ulong              data_sz ) {

  switch( self->state ) {
    case FD_QUIC_TLS_HS_STATE_DEAD:
    case FD_QUIC_TLS_HS_STATE_COMPLETE:
      return FD_QUIC_TLS_SUCCESS;
    default:
      break;
  }

  /* TODO ugly: the handshake functions mutate data in place for
          endianness conversion.  Since we get a const pointer, we need
          to make a copy here.  (However, there is no reason for the
          incoming pointer to be const) */
  uchar copy[ 4096 ];
  if( FD_UNLIKELY( data_sz > sizeof(copy) ) )
    return FD_QUIC_TLS_FAILED;
  fd_memcpy( copy, data, data_sz );

  long res = fd_tls_handshake( &self->quic_tls->tls, &self->hs, copy, data_sz, enc_level );

  if( FD_UNLIKELY( res<0L ) ) {
    int alert = (int)-res;
    self->alert = (uint)alert;
    self->quic_tls->alert_cb( self, self->context, alert );
    return FD_QUIC_TLS_FAILED;
  }

  /* needs a call to fd_quic_tls_process */
  self->state = FD_QUIC_TLS_HS_STATE_NEED_SERVICE;

  return FD_QUIC_TLS_SUCCESS;
}

int
fd_quic_tls_process( fd_quic_tls_hs_t * self ) {
  if( self->state != FD_QUIC_TLS_HS_STATE_NEED_SERVICE ) return FD_QUIC_TLS_SUCCESS;

  uchar hs_state = self->hs.base.state;

  switch( hs_state ) {
  case FD_TLS_HS_CONNECTED:
    /* handshake completed */
    self->is_hs_complete = 1;
    self->quic_tls->handshake_complete_cb( self, self->context );
    self->state = FD_QUIC_TLS_HS_STATE_COMPLETE;
    return FD_QUIC_TLS_SUCCESS;
  case FD_TLS_HS_FAIL:
    /* handshake permanently failed */
    self->state = FD_QUIC_TLS_HS_STATE_DEAD;
    return FD_QUIC_TLS_FAILED;
  case FD_TLS_HS_START:
    /* special case: Client needs to initiate the handshake */
    if( !self->is_server ) {
      long res = fd_tls_client_handshake( &self->quic_tls->tls, &self->hs.cli, NULL, 0UL, 0 );
      if( FD_UNLIKELY( res<0L ) ) {
        self->alert = (uint)-res;
        return FD_QUIC_TLS_FAILED;
      }
      return FD_QUIC_TLS_SUCCESS;
    } else {
      /* server has no such special case */
      __attribute__((fallthrough));
    }
  default:
    /* fd_quic_tls_provide_data will perform as much handshaking as
       possible.  Thus, we know that we are blocked on needing more data
       when we reach fd_quic_tls_process without having completed the
       handshake. */
    self->state = FD_QUIC_TLS_HS_STATE_NEED_INPUT;
    return FD_QUIC_TLS_SUCCESS;
  }
}

/* internal callbacks */

int
fd_quic_tls_sendmsg( void const * handshake,
                     void const * data,
                     ulong        data_sz,
                     uint         enc_level,
                     int          flush ) {

  uint buf_sz = FD_QUIC_TLS_HS_DATA_SZ;
  if( data_sz > buf_sz ) {
    return 0;
  }

  /* Safe because the fd_tls_estate_{srv,cli}_t object is the first
     element of fd_quic_tls_hs_t */
  fd_quic_tls_hs_t * hs = (fd_quic_tls_hs_t *)handshake;
  hs->is_flush |= flush;

  /* add handshake data to handshake for retrieval by user */

  /* find free handshake data */
  ushort hs_data_idx = hs->hs_data_free_idx;
  if( hs_data_idx == FD_QUIC_TLS_HS_DATA_UNUSED ) {
    /* no free structures left. fail */
    return 0;
  }

  /* allocate enough space from hs data buffer */
  uint head       = hs->hs_data_buf_head;
  uint tail       = hs->hs_data_buf_tail;
  uint alloc_head = 0; /* to be determined */

  uint alloc_data_sz = fd_uint_align_up( (uint)data_sz, FD_QUIC_TLS_HS_DATA_ALIGN );
  uint free_data_sz  = alloc_data_sz; /* the number of bytes to free */

  /* we need contiguous bytes
     head >= buf_sz implies wrap around */
  if( head >= buf_sz ) {
    /* wrap around implies entire unused block is contiguous */
    if( head - tail < alloc_data_sz ) {
      /* not enough free */
      return 0;
    } else {
      alloc_head = head;
    }
  } else {
    /* available data split */
    if( buf_sz - head >= alloc_data_sz ) {
      alloc_head = head;
    } else {
      /* not enough at head, try front */
      if( tail < alloc_data_sz ) {
        /* not enough here either */
        return 0;
      }

      /* since we're skipping some free space at end of buffer,
         we need to free that also, upon pop */
      alloc_head   = 0;
      free_data_sz = alloc_data_sz + buf_sz - head;
    }
  }

  /* success */

  uint                    buf_mask = (uint)( buf_sz - 1u );
  fd_quic_tls_hs_data_t * hs_data = &hs->hs_data[hs_data_idx];
  uchar *                 buf     = &hs->hs_data_buf[alloc_head & buf_mask];

  /* update free list */
  hs->hs_data_free_idx = hs_data->next_idx;

  /* update buffer pointers */
  hs->hs_data_buf_head = alloc_head + alloc_data_sz;

  /* copy data into buffer, and update metadata in hs_data */
  fd_memcpy( buf, data, data_sz );
  hs_data->enc_level    = enc_level;
  hs_data->data         = buf;
  hs_data->data_sz      = (uint)data_sz;
  hs_data->free_data_sz = free_data_sz;
  hs_data->offset       = hs->hs_data_offset[enc_level];

  /* offset adjusted ready for more data */
  hs->hs_data_offset[enc_level] += (uint)data_sz;

  /* add to end of pending list */
  hs_data->next_idx = FD_QUIC_TLS_HS_DATA_UNUSED;
  ulong pend_end_idx = hs->hs_data_pend_end_idx[enc_level];
  if( pend_end_idx == FD_QUIC_TLS_HS_DATA_UNUSED  ) {
    /* pending list is empty */
    hs->hs_data_pend_end_idx[enc_level] = hs->hs_data_pend_idx[enc_level] = hs_data_idx;
  } else {
    /* last element must point to next */
    hs->hs_data[pend_end_idx].next_idx  = hs_data_idx;
    hs->hs_data_pend_end_idx[enc_level] = hs_data_idx;
  }

  return 1;
}

void
fd_quic_tls_secrets( void const * handshake,
                     void const * recv_secret,
                     void const * send_secret,
                     uint         enc_level ) {

  fd_quic_tls_hs_t * hs = (fd_quic_tls_hs_t *)handshake;

  /* TODO: For now AES-128-GCM hardcoded */
  fd_quic_tls_secret_t secret = {
    .suite_id     = 0x1301,
    .enc_level    = enc_level,
    .secret_len   = 32 };
  fd_memcpy( secret.read_secret,  recv_secret, 32UL );
  fd_memcpy( secret.write_secret, send_secret, 32UL );

  hs->quic_tls->secret_cb( hs, hs->context, &secret );
}

fd_quic_tls_hs_data_t *
fd_quic_tls_get_hs_data( fd_quic_tls_hs_t * self,
                         uint               enc_level ) {
  if( !self ) return NULL;

  uint idx = self->hs_data_pend_idx[enc_level];
  if( idx == FD_QUIC_TLS_HS_DATA_UNUSED ) return NULL;

  return &self->hs_data[idx];
}

fd_quic_tls_hs_data_t *
fd_quic_tls_get_next_hs_data( fd_quic_tls_hs_t * self, fd_quic_tls_hs_data_t * hs ) {
  ushort idx = hs->next_idx;
  if( idx == (ushort)(~0u) ) return NULL;
  return self->hs_data + idx;
}

void
fd_quic_tls_pop_hs_data( fd_quic_tls_hs_t * self, uint enc_level ) {
  ushort idx = self->hs_data_pend_idx[enc_level];
  if( idx == FD_QUIC_TLS_HS_DATA_UNUSED ) return;

  fd_quic_tls_hs_data_t * hs_data = &self->hs_data[idx];

  uint buf_sz       = FD_QUIC_TLS_HS_DATA_SZ;
  uint free_data_sz = hs_data->free_data_sz; /* amount of data to free */

  /* move tail pointer */
  uint head = self->hs_data_buf_head;
  uint tail = self->hs_data_buf_tail;

  tail += free_data_sz;
  if( tail > head ) {
    /* logic error - tried to free more than was allocated */
    FD_LOG_ERR(( "fd_quic_tls_pop_hs_data: tried to free more than was allocated" ));
    return;
  }

  /* adjust to maintain invariants */
  if( tail >= buf_sz ) {
    tail -= buf_sz;
    head -= buf_sz;
  }

  /* write back head and tail */
  self->hs_data_buf_head = head;
  self->hs_data_buf_tail = tail;

  /* pop from pending list */
  self->hs_data_pend_idx[enc_level] = hs_data->next_idx;

  /* if idx is the last, update last */
  if( hs_data->next_idx == FD_QUIC_TLS_HS_DATA_UNUSED ) {
    self->hs_data_pend_end_idx[enc_level] = FD_QUIC_TLS_HS_DATA_UNUSED;
  }

}

void
fd_quic_tls_get_peer_transport_params( fd_quic_tls_hs_t * self,
                                       uchar const **     transport_params,
                                       ulong *            transport_params_sz ) {
  *transport_params     = self->peer_transport_params;
  *transport_params_sz  = self->peer_transport_params_sz;
}

void *
fd_quic_tls_rand( void * ctx,
                  void * buf,
                  ulong  bufsz ) {
  (void)ctx;
  FD_TEST( (long)bufsz==getrandom( buf, bufsz, 0U ) );
  return buf;
}

ulong
fd_quic_tls_tp_self( void *  const handshake,
                     uchar * const quic_tp,
                     ulong   const quic_tp_bufsz ) {
  fd_quic_tls_hs_t * hs = (fd_quic_tls_hs_t *)handshake;

  /* Copy fd_quic_tls's transport params to fd_tls buffer */
  ulong sz = fd_ulong_min( quic_tp_bufsz, hs->self_transport_params_sz );
  fd_memcpy( quic_tp, hs->self_transport_params, sz );

  /* fd_tls will gracefully fail handshake if return value exceeds bufsz */
  return hs->self_transport_params_sz;
}

void
fd_quic_tls_tp_peer( void *        handshake,
                     uchar const * quic_tp,
                     ulong         quic_tp_sz ) {
  fd_quic_tls_hs_t * hs = (fd_quic_tls_hs_t *)handshake;

  /* Copy peer's transport params to fd_quic_tls_hs buffer */
  if( FD_UNLIKELY( quic_tp_sz > sizeof(hs->peer_transport_params) ) ) {
    /* TODO mark handshake as dead or report an error to fd_tls via
            return value */
    quic_tp_sz = 0UL;
  }

  hs->peer_transport_params_sz = (uchar)quic_tp_sz;
  fd_memcpy( hs->peer_transport_params, quic_tp, quic_tp_sz );
}

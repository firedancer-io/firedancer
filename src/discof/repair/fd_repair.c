#include "fd_repair.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../disco/keyguard/fd_keyguard_client.h"

void *
fd_repair_new( void * shmem, ulong peer_max ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_repair_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  int lg_peer_max = fd_ulong_find_msb( fd_ulong_pow2_up( peer_max ) );

  ulong footprint = fd_repair_footprint( peer_max );
  fd_memset( shmem, 0, footprint );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_repair_t * repair   = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_align(),          sizeof(fd_repair_t)                         );
  void *        peer_map = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_peer_map_align(), fd_repair_peer_map_footprint( lg_peer_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_repair_align() ) == (ulong)shmem + footprint );

  repair->peer_map = fd_repair_peer_map_new( peer_map, lg_peer_max );

  return shmem;
}

fd_repair_t *
fd_repair_join( void * shrepair ) {
  fd_repair_t * repair = (fd_repair_t *)shrepair;

  if( FD_UNLIKELY( !repair ) ) {
    FD_LOG_WARNING(( "NULL repair" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)repair, fd_repair_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned repair" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( repair );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "repair must be part of a workspace" ));
    return NULL;
  }

  repair->peer_map = fd_repair_peer_map_join( repair->peer_map );

  return repair;
}

void *
fd_repair_leave( fd_repair_t const * repair ) {

  if( FD_UNLIKELY( !repair ) ) {
    FD_LOG_WARNING(( "NULL repair" ));
    return NULL;
  }

  return (void *)repair;
}

void *
fd_repair_delete( void * repair ) {

  if( FD_UNLIKELY( !repair ) ) {
    FD_LOG_WARNING(( "NULL repair" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned((ulong)repair, fd_repair_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned repair" ));
    return NULL;
  }

  return repair;
}

fd_repair_pong_t *
fd_repair_pong( fd_repair_t * repair ) {
  fd_repair_private_pong( &repair->identity_key, &repair->pong );
  return &repair->pong;
}

static ulong tsms( void ) {
  return (ulong)fd_log_wallclock() / (ulong)1000000UL; /* ms */
}

fd_repair_req_t *
fd_repair_shred_req( fd_repair_t * repair,
                     fd_pubkey_t * to,
                     ulong         slot,
                     ulong         shred_idx,
                     uint          nonce ) {
  fd_repair_private_shred_req( &repair->identity_key, to, tsms(), nonce, slot, shred_idx, &repair->req );
  return &repair->req;
}

fd_repair_req_t *
fd_repair_highest_shred_req( fd_repair_t * repair,
                             fd_pubkey_t * to,
                             ulong         slot,
                             ulong         shred_idx,
                             uint          nonce ) {
  fd_repair_private_highest_shred_req( &repair->identity_key, to, tsms(), nonce, slot, shred_idx, &repair->req );
  return &repair->req;
}

fd_repair_req_t *
fd_repair_orphan_req( fd_repair_t * repair,
                      fd_pubkey_t * to,
                      ulong slot,
                      uint nonce ) {
  fd_repair_private_orphan_req( &repair->identity_key, to, tsms(), nonce, slot, &repair->req );
  return &repair->req;
}

void
fd_repair_private_pong( fd_pubkey_t * from, fd_repair_pong_t * pong_out ) {
  pong_out->kind = FD_REPAIR_KIND_PONG;
  pong_out->from = *from;
}

uchar *
preimage_hash_pong( fd_hash_t * ping_token, uchar preimage[ static FD_REPAIR_PREIMAGE_SZ ], fd_repair_pong_t * pong ) {
  memcpy( preimage,                                FD_REPAIR_PREIMAGE_PREFIX, FD_REPAIR_PREIMAGE_PREFIX_SZ );
  memcpy( preimage + FD_REPAIR_PREIMAGE_PREFIX_SZ, ping_token->uc,            sizeof( fd_hash_t ) );
  fd_sha256_hash( preimage, FD_REPAIR_PREIMAGE_SZ, pong->hash.uc );
  return preimage;
}

fd_repair_pong_t *
fd_repair_keyguard_hash_sign_pong( fd_keyguard_client_t * client, fd_hash_t * ping_token, fd_repair_pong_t * pong ) {
  uchar buf[ FD_REPAIR_PREIMAGE_SZ ];
  fd_keyguard_client_sign( client, pong->sig, preimage_hash_pong( ping_token, buf, pong ), FD_REPAIR_PREIMAGE_SZ, FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519 ); /* due to keyguard_match API limitations this results in hashing twice */
  return pong;
}

fd_repair_pong_t *
fd_repair_ed25519_hash_sign_pong( uchar const public_key[ 32 ], uchar const private_key[ 32 ], fd_hash_t * ping_token, fd_repair_pong_t * pong ) {
  uchar buf[ FD_REPAIR_PREIMAGE_SZ ];
  preimage_hash_pong( ping_token, buf, pong );
  fd_sha512_t sha[1];
  fd_ed25519_sign( pong->sig, pong->hash.uc, sizeof(fd_hash_t), public_key, private_key, sha );
  return pong;
}

/* hdr populates the common header of {Shred,HighestShred,Orphan}
   requests. */

void hdr_req( fd_pubkey_t * from, fd_pubkey_t * to, ulong ts, uint nonce, fd_repair_req_t * req_out ) {
  req_out->from  = *from;
  req_out->to    = *to;
  req_out->ts    = ts;
  req_out->nonce = nonce;
}

void
fd_repair_private_shred_req( fd_pubkey_t *     from,
                             fd_pubkey_t *     to,
                             ulong             ts,
                             uint              nonce,
                             ulong             slot,
                             ulong             shred_idx,
                             fd_repair_req_t * req_out ) {
  hdr_req( from, to, ts, nonce, req_out );
  req_out->kind            = FD_REPAIR_KIND_SHRED_REQ;
  req_out->shred.slot      = slot;
  req_out->shred.shred_idx = shred_idx;
}

void
fd_repair_private_highest_shred_req( fd_pubkey_t *     from,
                                     fd_pubkey_t *     to,
                                     ulong             ts,
                                     uint              nonce,
                                     ulong             slot,
                                     ulong             shred_idx,
                                     fd_repair_req_t * req_out ) {
  hdr_req( from, to, ts, nonce, req_out );
  req_out->kind            = FD_REPAIR_KIND_HIGHEST_SHRED_REQ;
  req_out->shred.slot      = slot;
  req_out->shred.shred_idx = shred_idx;
}

void
fd_repair_private_orphan_req( fd_pubkey_t *     from,
                              fd_pubkey_t *     to,
                              ulong             ts,
                              uint              nonce,
                              ulong             slot,
                              fd_repair_req_t * req_out ) {
  hdr_req( from, to, ts, nonce, req_out );
  req_out->kind       = FD_REPAIR_KIND_ORPHAN_REQ;
  req_out->shred.slot = slot;
}

static ulong
preimage_req( uchar preimage[ static sizeof(fd_repair_req_t) - sizeof(fd_ed25519_sig_t) ], fd_repair_req_t * req ) {
  FD_STORE( uint, preimage, req->kind );
  ulong sz  = sizeof(fd_repair_req_t) - sizeof(fd_ed25519_sig_t);
  sz        = fd_ulong_if( req->kind == FD_REPAIR_KIND_ORPHAN_REQ, sz - sizeof(ulong), sz );
  ulong off = sizeof(uint) + FD_ED25519_SIG_SZ;
  memcpy( preimage + sizeof(uint), (uchar *)req + off, sz - sizeof(uint) );
  return sz;
}

fd_repair_req_t *
fd_repair_keyguard_sign_req( fd_keyguard_client_t * client, fd_repair_req_t * req ) {
  uchar preimage[ sizeof(fd_repair_req_t) - sizeof(fd_ed25519_sig_t) ];
  ulong sz = preimage_req( preimage, req );
  fd_keyguard_client_sign( client, req->sig, preimage, sz, FD_KEYGUARD_SIGN_TYPE_ED25519 );
  return req;
}

fd_repair_req_t *
fd_repair_ed25519_sign_req( uchar const public_key[ 32 ], uchar const private_key[ 32 ], fd_repair_req_t * req ) {
  fd_sha512_t sha[1];
  uchar msg[ sizeof(fd_repair_req_t) - sizeof(fd_ed25519_sig_t) ];
  FD_STORE( uint, msg, req->kind );
  ulong sz = fd_ulong_if( req->kind == FD_REPAIR_KIND_ORPHAN_REQ, sizeof(msg) - sizeof(ulong), sizeof(msg) );
  memcpy( msg + sizeof(uint), req->from.uc, sz - sizeof(uint) );
  fd_ed25519_sign( req->sig, msg, sz, public_key, private_key, sha );
  // uchar preimage[ sizeof(fd_repair_req_t) - sizeof(fd_ed25519_sig_t) ];
  // ulong sz = preimage_req( preimage, req );
  // fd_sha512_t _sha[1]; fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );
  // fd_ed25519_sign( req->sig, preimage, sz, public_key, private_key, sha );
  return req;
}

static ulong
serialize( uchar * ser, ulong sz, uchar * buf_out ) {
   fd_repair_protocol_t protocol;
   memcpy( &protocol, ser, sz );
   fd_bincode_encode_ctx_t ctx = { .data = buf_out, .dataend = buf_out + sz };
   fd_repair_protocol_encode( &protocol, &ctx );
   return sz;
}

ulong
fd_repair_serialize_pong( fd_repair_pong_t * pong, uchar buf_out[ static sizeof(fd_repair_pong_t) ] ) {
  return serialize( (uchar *)pong, sizeof(fd_repair_pong_t), buf_out );
}

ulong
fd_repair_serialize_req( fd_repair_req_t * req, uchar buf_out[ static sizeof(fd_repair_req_t) ] ) {
  serialize( (uchar *)req, sizeof(fd_repair_req_t), buf_out );
  switch( req->kind ) {
  case FD_REPAIR_KIND_SHRED_REQ:         return sizeof(fd_repair_req_t);
  case FD_REPAIR_KIND_HIGHEST_SHRED_REQ: return sizeof(fd_repair_req_t);
  case FD_REPAIR_KIND_ORPHAN_REQ:        return sizeof(fd_repair_req_t) - sizeof(ulong);
  default: break;
  }
  FD_LOG_ERR(( "%s: unhandled kind %u", __func__, req->kind ));
}

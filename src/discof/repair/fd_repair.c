#include "fd_repair.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../disco/keyguard/fd_keyguard_client.h"

void *
fd_repair_new( void * shmem ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_repair_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_repair_footprint();
  fd_memset( shmem, 0, footprint );

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

fd_repair_msg_t *
fd_repair_pong( fd_repair_t * repair, fd_hash_t * ping_token ) {
  repair->msg.kind      = FD_REPAIR_KIND_PONG;
  repair->msg.pong.from = repair->identity_key;
  repair->msg.pong.hash = *ping_token;
  repair->sign_fn( repair->sign_ctx, &repair->msg, repair->msg.pong.sig );
  return &repair->msg;
}

fd_repair_msg_t *
fd_repair_shred( fd_repair_t * repair,
                 fd_pubkey_t * to,
                 ulong         ts,
                 uint          nonce,
                 ulong         slot,
                 ulong         shred_idx ) {
  repair->msg.kind            = FD_REPAIR_KIND_SHRED;
  repair->msg.shred.from      = repair->identity_key;
  repair->msg.shred.to        = *to;
  repair->msg.shred.ts        = ts;
  repair->msg.shred.nonce     = nonce;
  repair->msg.shred.slot      = slot;
  repair->msg.shred.shred_idx = shred_idx;
  repair->sign_fn( repair->sign_ctx, &repair->msg, repair->msg.shred.sig );
  return &repair->msg;
}

fd_repair_msg_t *
fd_repair_highest_shred( fd_repair_t * repair,
                         fd_pubkey_t * to,
                         ulong         ts,
                         uint          nonce,
                         ulong         slot,
                         ulong         shred_idx ) {
  repair->msg.kind                    = FD_REPAIR_KIND_HIGHEST_SHRED;
  repair->msg.highest_shred.from      = repair->identity_key;
  repair->msg.highest_shred.to        = *to;
  repair->msg.highest_shred.ts        = ts;
  repair->msg.highest_shred.nonce     = nonce;
  repair->msg.highest_shred.slot      = slot;
  repair->msg.highest_shred.shred_idx = shred_idx;
  repair->sign_fn( repair->sign_ctx, &repair->msg, repair->msg.highest_shred.sig );
  return &repair->msg;
}

fd_repair_msg_t *
fd_repair_orphan( fd_repair_t * repair,
                  fd_pubkey_t * to,
                  ulong         ts,
                  uint          nonce,
                  ulong         slot ) {
  repair->msg.kind         = FD_REPAIR_KIND_ORPHAN;
  repair->msg.orphan.from  = repair->identity_key;
  repair->msg.orphan.to    = *to;
  repair->msg.orphan.ts    = ts;
  repair->msg.orphan.nonce = nonce;
  repair->msg.orphan.slot  = slot;
  repair->sign_fn( repair->sign_ctx, &repair->msg, repair->msg.highest_shred.sig );
  return &repair->msg;
}

static uchar *
preimage_pong( fd_repair_pong_t * pong, uchar * preimage ) {
  fd_hash_t const * ping_token = &pong->hash; /* assumes Ping token stored in Pong hash */
  ulong prefix_sz = sizeof(FD_REPAIR_PONG_PREIMAGE_PREFIX) - 1 /* subtract NUL */;
  memcpy( preimage,             FD_REPAIR_PONG_PREIMAGE_PREFIX, prefix_sz         );
  memcpy( preimage + prefix_sz, ping_token,                     sizeof(fd_hash_t) );
  return preimage;
}

static uchar *
preimage_req( fd_repair_msg_t * msg, uchar * preimage ) {
  ulong off = sizeof(uint) + sizeof(fd_ed25519_sig_t);
  FD_STORE( uint, preimage, msg->kind ); /* copy kind */
  ulong sz = fd_repair_sz( msg ) - sizeof(fd_ed25519_sig_t) - sizeof(uint);
  memcpy( preimage + sizeof( uint ), (uchar *)msg + off, sz ); /* copy remaining fields excl sig */
  return preimage;
}

void
fd_repair_sign_ed25519( void * ctx, fd_repair_msg_t * msg, uchar * sig_out ) {
  if( FD_UNLIKELY( !ctx || !msg || !sig_out ) ) { FD_LOG_WARNING(( "NULL ctx or msg or sig_out" )); return; }
  fd_sha512_t sha[1];
  uchar *     public_key  = (uchar *)ctx;
  uchar *     private_key = public_key + 32UL; /* [public key ... private key] */
  uchar preimage[ sizeof(fd_repair_msg_t) - sizeof(fd_ed25519_sig_t) ];
  switch( msg->kind ) {
  case FD_REPAIR_KIND_PONG: {
    preimage_pong( &msg->pong, preimage );
    fd_sha256_hash( preimage, sizeof(FD_REPAIR_PONG_PREIMAGE_PREFIX) - 1 + sizeof(fd_hash_t), msg->pong.hash.uc );
    fd_ed25519_sign( msg->pong.sig, msg->pong.hash.uc, sizeof(fd_hash_t), public_key, private_key, sha );
    return;
  }
  case FD_REPAIR_KIND_SHRED:
  case FD_REPAIR_KIND_HIGHEST_SHRED:
  case FD_REPAIR_KIND_ORPHAN: {
    fd_ed25519_sign( (uchar *)msg + sizeof(uint) /* sig */, preimage_req( msg, preimage ), fd_repair_sz( msg ) - sizeof(fd_ed25519_sig_t), public_key, private_key, sha );
    return;
  }
  }
}

void
fd_repair_sign_keyguard( void * ctx, fd_repair_msg_t * msg, uchar * sig_out ) {
  if( FD_UNLIKELY( !ctx || !msg || !sig_out ) ) { FD_LOG_WARNING(( "NULL ctx or msg or sig_out" )); return; }
  fd_keyguard_client_t * client = (fd_keyguard_client_t *)ctx;
  uchar preimage[ sizeof(fd_repair_msg_t) - sizeof(fd_ed25519_sig_t) ];
  switch( msg->kind ) {
  case FD_REPAIR_KIND_PONG: {
    preimage_pong( &msg->pong, preimage );
    fd_sha256_hash( preimage, sizeof(FD_REPAIR_PONG_PREIMAGE_PREFIX) - 1 + sizeof(fd_hash_t), msg->pong.hash.uc );
    fd_keyguard_client_sign( client, msg->pong.sig, preimage, fd_repair_sz( msg ) - sizeof(fd_ed25519_sig_t), FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519 );
    return;
  }
  case FD_REPAIR_KIND_SHRED:
  case FD_REPAIR_KIND_HIGHEST_SHRED:
  case FD_REPAIR_KIND_ORPHAN: {
    fd_keyguard_client_sign( client, (uchar *)msg + sizeof(uint) /* sig */, preimage_req( msg, preimage ), fd_repair_sz( msg ) - sizeof(fd_ed25519_sig_t), FD_KEYGUARD_SIGN_TYPE_ED25519 );
    return;
  }
  }
}

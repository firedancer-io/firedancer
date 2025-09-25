#include "fd_repair.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../disco/keyguard/fd_keyguard_client.h"

void *
fd_repair_new( void * shmem, fd_pubkey_t * identity_key ) {

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

  fd_repair_t * repair = (fd_repair_t *)shmem;
  repair->identity_key = *identity_key;

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
  uchar pre_image[FD_REPAIR_PONG_PREIMAGE_SZ];
  memcpy( pre_image, "SOLANA_PING_PONG", 16UL );
  memcpy( pre_image+16UL, ping_token->uc, 32UL);

  /* Generate response hash token */
  fd_sha256_hash( pre_image, FD_REPAIR_PONG_PREIMAGE_SZ, &repair->msg.pong.hash );

  repair->msg.kind      = FD_REPAIR_KIND_PONG;
  repair->msg.pong.from = repair->identity_key;
  return &repair->msg;
}

fd_repair_msg_t *
fd_repair_shred( fd_repair_t *     repair,
                 fd_pubkey_t const * to,
                 ulong             ts,
                 uint              nonce,
                 ulong             slot,
                 ulong             shred_idx ) {
  memset(&repair->msg, 0, sizeof(fd_repair_msg_t));
  repair->msg.kind            = FD_REPAIR_KIND_SHRED;
  repair->msg.shred.from      = repair->identity_key;
  repair->msg.shred.to        = *to;
  repair->msg.shred.ts        = ts;
  repair->msg.shred.nonce     = nonce;
  repair->msg.shred.slot      = slot;
  repair->msg.shred.shred_idx = shred_idx;
  return &repair->msg;
}

fd_repair_msg_t *
fd_repair_highest_shred( fd_repair_t *     repair,
                         fd_pubkey_t const * to,
                         ulong             ts,
                         uint              nonce,
                         ulong             slot,
                         ulong             shred_idx ) {
  memset(&repair->msg, 0, sizeof(fd_repair_msg_t));
  repair->msg.kind                    = FD_REPAIR_KIND_HIGHEST_SHRED;
  repair->msg.highest_shred.from      = repair->identity_key;
  repair->msg.highest_shred.to        = *to;
  repair->msg.highest_shred.ts        = ts;
  repair->msg.highest_shred.nonce     = nonce;
  repair->msg.highest_shred.slot      = slot;
  repair->msg.highest_shred.shred_idx = shred_idx;
  return &repair->msg;
}

fd_repair_msg_t *
fd_repair_orphan( fd_repair_t *     repair,
                  fd_pubkey_t const * to,
                  ulong             ts,
                  uint              nonce,
                  ulong             slot ) {
  memset(&repair->msg, 0, sizeof(fd_repair_msg_t));
  repair->msg.kind         = FD_REPAIR_KIND_ORPHAN;
  repair->msg.orphan.from  = repair->identity_key;
  repair->msg.orphan.to    = *to;
  repair->msg.orphan.ts    = ts;
  repair->msg.orphan.nonce = nonce;
  repair->msg.orphan.slot  = slot;
  return &repair->msg;
}

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
fd_repair_pong( fd_repair_t * repair, fd_hash_t * ping_token, fd_repair_msg_t * out_msg ) {
  uchar pre_image[FD_REPAIR_PONG_PREIMAGE_SZ];
  memcpy( pre_image, "SOLANA_PING_PONG", 16UL );
  memcpy( pre_image+16UL, ping_token->uc, 32UL);

  /* Generate response hash token */
  fd_sha256_hash( pre_image, FD_REPAIR_PONG_PREIMAGE_SZ, &out_msg->pong.hash );

  out_msg->kind      = FD_REPAIR_KIND_PONG;
  out_msg->pong.from = repair->identity_key;
  return out_msg;
}

fd_repair_msg_t *
fd_repair_shred( fd_repair_t *     repair,
                 fd_pubkey_t const * to,
                 ulong             ts,
                 uint              nonce,
                 ulong             slot,
                 ulong             shred_idx,
                 fd_repair_msg_t * out_msg ) {
  memset(out_msg, 0, sizeof(fd_repair_msg_t));
  out_msg->kind            = FD_REPAIR_KIND_SHRED;
  out_msg->shred.from      = repair->identity_key;
  out_msg->shred.to        = *to;
  out_msg->shred.ts        = ts;
  out_msg->shred.nonce     = nonce;
  out_msg->shred.slot      = slot;
  out_msg->shred.shred_idx = shred_idx;
  return out_msg;
}

fd_repair_msg_t *
fd_repair_highest_shred( fd_repair_t *     repair,
                         fd_pubkey_t const * to,
                         ulong             ts,
                         uint              nonce,
                         ulong             slot,
                         ulong             shred_idx,
                         fd_repair_msg_t * out_msg ) {
  memset(out_msg, 0, sizeof(fd_repair_msg_t));
  out_msg->kind                    = FD_REPAIR_KIND_HIGHEST_SHRED;
  out_msg->highest_shred.from      = repair->identity_key;
  out_msg->highest_shred.to        = *to;
  out_msg->highest_shred.ts        = ts;
  out_msg->highest_shred.nonce     = nonce;
  out_msg->highest_shred.slot      = slot;
  out_msg->highest_shred.shred_idx = shred_idx;
  return out_msg;
}

fd_repair_msg_t *
fd_repair_orphan( fd_repair_t *     repair,
                  fd_pubkey_t const * to,
                  ulong             ts,
                  uint              nonce,
                  ulong             slot,
                  fd_repair_msg_t * out_msg ) {
  memset(out_msg, 0, sizeof(fd_repair_msg_t));
  out_msg->kind         = FD_REPAIR_KIND_ORPHAN;
  out_msg->orphan.from  = repair->identity_key;
  out_msg->orphan.to    = *to;
  out_msg->orphan.ts    = ts;
  out_msg->orphan.nonce = nonce;
  out_msg->orphan.slot  = slot;
  return out_msg;
}

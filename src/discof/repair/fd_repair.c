#include "fd_repair.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/bmtree/fd_bmtree.h"

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
  memcpy( pre_image,      "SOLANA_PING_PONG", 16UL );
  memcpy( pre_image+16UL, ping_token->uc,     32UL );

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

fd_repair_msg_t *
ag_repair_parent_and_fec_set_count( fd_repair_t *       repair,
                                    fd_pubkey_t const * to,
                                    ulong               ts,
                                    uint                nonce,
                                    ulong               slot,
                                    fd_hash_t const *   block_id ) {
  memset(&repair->msg, 0, sizeof(fd_repair_msg_t));
  repair->msg.kind = AG_REPAIR_KIND_PARENT_FEC_COUNT;
  repair->msg.parent_fec_set_count.from = repair->identity_key;
  repair->msg.parent_fec_set_count.to = *to;
  repair->msg.parent_fec_set_count.ts = ts;
  repair->msg.parent_fec_set_count.nonce = nonce;
  repair->msg.parent_fec_set_count.slot = slot;
  repair->msg.parent_fec_set_count.block_id = *block_id;
  return &repair->msg;
}

fd_repair_msg_t *
ag_repair_fec_set_root( fd_repair_t *       repair,
                        fd_pubkey_t const * to,
                        ulong               ts,
                        uint                nonce,
                        ulong               slot,
                        fd_hash_t const *   block_id,
                        uint                fec_set_idx ) {
  memset(&repair->msg, 0, sizeof(fd_repair_msg_t));
  repair->msg.kind = AG_REPAIR_KIND_FEC_ROOT;
  repair->msg.fec_set_root.from = repair->identity_key;
  repair->msg.fec_set_root.to = *to;
  repair->msg.fec_set_root.ts = ts;
  repair->msg.fec_set_root.nonce = nonce;
  repair->msg.fec_set_root.slot = slot;
  repair->msg.fec_set_root.block_id = *block_id;
  repair->msg.fec_set_root.fec_set_idx = fec_set_idx;
  return &repair->msg;
}

fd_repair_msg_t *
ag_repair_shred_block_id( fd_repair_t *       repair,
                          fd_pubkey_t const * to,
                          ulong               ts,
                          uint                nonce,
                          ulong               slot,
                          fd_hash_t const *   block_id,
                          uint                shred_idx ) {
  memset(&repair->msg, 0, sizeof(fd_repair_msg_t));
  repair->msg.kind = AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID;
  repair->msg.shred_block_id.from = repair->identity_key;
  repair->msg.shred_block_id.to = *to;
  repair->msg.shred_block_id.ts = ts;
  repair->msg.shred_block_id.nonce = nonce;
  repair->msg.shred_block_id.slot = slot;
  repair->msg.shred_block_id.shred_idx = shred_idx;
  repair->msg.shred_block_id.block_id = *block_id;
  return &repair->msg;
}

int
ag_repair_response_de( ag_repair_response_t * response,
                       uchar const *          buf,
                       ulong                  buf_sz ) {
  uchar const * cur = buf;
  ulong         rem = buf_sz;

  if( FD_UNLIKELY( rem<sizeof(uint) ) ) return -1;
  response->kind = fd_uint_load_4_fast( cur );
  cur += sizeof(uint); rem -= sizeof(uint);

  ulong   proof_sz; /* total bytes proof */
  uchar * proof;

  switch( response->kind ) {
    case AG_REPAIR_RESPONSE_PARENT_FEC_SET_COUNT: {
      ag_parent_fec_count_res_t * res = &response->parent_fec_set_res;

      if( FD_UNLIKELY( rem < sizeof(uint) ) ) return -1;
      res->fec_set_count = fd_uint_load_4_fast( cur );
      cur += sizeof(uint); rem -= sizeof(uint);
      if( FD_UNLIKELY( res->fec_set_count>FD_FEC_BLK_MAX ) ) return -1;

      if( FD_UNLIKELY( rem < sizeof(ulong) ) ) return -1;
      res->parent_slot = fd_ulong_load_8_fast( cur );
      cur += sizeof(ulong); rem -= sizeof(ulong);

      if( FD_UNLIKELY( rem < sizeof(fd_hash_t) ) ) return -1;
      memcpy( res->parent_block_id.uc, cur, sizeof(fd_hash_t) );
      cur += sizeof(fd_hash_t); rem -= sizeof(fd_hash_t);

      if( FD_UNLIKELY( rem < sizeof(ulong) ) ) return -1;
      proof_sz = fd_ulong_load_8_fast( cur );
      cur += sizeof(ulong); rem -= sizeof(ulong);

      res->proof_len = proof_sz / FD_SHRED_MERKLE_NODE_SZ;
      proof          = res->parent_proof[0];
      break;
    }

    case AG_REPAIR_RESPONSE_FEC_SET_ROOT: {
      ag_fec_root_res_t * res = &response->fec_set_root;

      if( FD_UNLIKELY( rem < FD_SHRED_MERKLE_NODE_SZ ) ) return -1;
      memcpy( res->root, cur, FD_SHRED_MERKLE_NODE_SZ );
      cur += FD_SHRED_MERKLE_NODE_SZ; rem -= FD_SHRED_MERKLE_NODE_SZ;

      if( FD_UNLIKELY( rem < sizeof(ulong) ) ) return -1;
      proof_sz = fd_ulong_load_8_fast( cur );
      cur += sizeof(ulong); rem -= sizeof(ulong);

      res->proof_len = proof_sz / FD_SHRED_MERKLE_NODE_SZ;
      proof          = res->fec_proof[0];
      break;
    }
    default: return -1;
  }

  if( FD_UNLIKELY( proof_sz % FD_SHRED_MERKLE_NODE_SZ                           ) ) return -1;
  if( FD_UNLIKELY( proof_sz > AG_MAX_FEC_PROOF_NODE_CNT*FD_SHRED_MERKLE_NODE_SZ ) ) return -1;
  if( FD_UNLIKELY( rem != proof_sz+sizeof(uint)                                 ) ) return -1; /* proof + trailing nonce, nothing more */

  memcpy( proof, cur, proof_sz );
  cur += proof_sz;

  response->nonce = fd_uint_load_4_fast( cur );
  return 0;
}

/* verify_merkle_proof reconstructs the double-merkle root from leaf at
   leaf_idx + proof and checks it equals block_id.  0 on match, -1 else. */

static int
verify_merkle_proof( fd_bmtree_node_t * leaf,
                     ulong              leaf_idx,
                     uchar const *      proof,
                     ulong              proof_len,
                     fd_hash_t const *  block_id ) {
  fd_bmtree_node_t root[1];
  if( FD_UNLIKELY( !fd_bmtree_from_proof( leaf, leaf_idx, root, proof, proof_len, FD_SHRED_MERKLE_NODE_SZ, FD_BMTREE_LONG_PREFIX_SZ ) ) ) return -1;
  if( FD_UNLIKELY( 0!=memcmp( root->hash, block_id->uc, sizeof(fd_hash_t) ) ) ) return -1;
  return 0;
}

int
ag_repair_parent_fec_count_verify( ag_parent_fec_count_res_t const * res,
                                   fd_hash_t const *                 block_id ) {
  /* The parent-info leaf is the last of the tree's fec_set_count+1
     leaves, so the proof must be exactly as deep as that tree. */
  if( FD_UNLIKELY( res->proof_len != fd_bmtree_depth( res->fec_set_count+1UL )-1UL ) ) return -1;

  fd_bmtree_node_t leaf[1];
  fd_sha256_t sha[1];
  fd_sha256_init  ( sha );
  fd_sha256_append( sha, &res->parent_slot,       sizeof(ulong)     );
  fd_sha256_append( sha, res->parent_block_id.uc, sizeof(fd_hash_t) );
  fd_sha256_append( sha, &res->fec_set_count,     sizeof(uint)      );
  fd_sha256_fini  ( sha, leaf->hash );

  return verify_merkle_proof( leaf, res->fec_set_count, res->parent_proof[0], res->proof_len, block_id );
}

int
ag_repair_fec_set_root_verify( ag_fec_root_res_t const * res,
                               fd_hash_t const *         block_id,
                               uint                      fec_set_idx ) {
  fd_bmtree_node_t leaf[1] = {0};
  memcpy( leaf->hash, res->root, FD_SHRED_MERKLE_NODE_SZ );

  return verify_merkle_proof( leaf, fec_set_idx / FD_FEC_SHRED_CNT, res->fec_proof[0], res->proof_len, block_id );
}

int
fd_repair_ping_de( fd_repair_ping_t * ping,
                   uchar      const * buf,
                   ulong              buf_sz ) {
  if( FD_UNLIKELY( buf_sz!=sizeof(fd_repair_ping_t) )) return -1;

  ping->kind = fd_uint_load_4_fast( buf );
  buf       += sizeof(uint);

  if( FD_UNLIKELY( ping->kind != FD_REPAIR_KIND_PING && ping->kind != AG_REPAIR_KIND_PING )) return -1;

  /* pong section */

  memcpy( &ping->ping.from, buf, sizeof(fd_pubkey_t) );
  buf += sizeof(fd_pubkey_t);

  memcpy( &ping->ping.hash, buf, sizeof(fd_hash_t) );
  buf += sizeof(fd_hash_t);

  memcpy( ping->ping.sig, buf, sizeof(fd_ed25519_sig_t) );
  buf += sizeof(fd_ed25519_sig_t);
  return 0;
}

int
fd_repair_ping_ser( fd_repair_ping_t const * ping,
                    uchar                    buf[static sizeof(fd_repair_ping_t)],
                    ulong                    buf_sz ) {
  ulong off = 0;
  if( FD_UNLIKELY( buf_sz!=sizeof(fd_repair_ping_t) )) return -1;

  FD_STORE( uint, buf+off, ping->kind );
  off += sizeof(uint);

  FD_STORE( fd_pubkey_t, buf+off, ping->ping.from );
  off += sizeof(fd_pubkey_t);

  FD_STORE( fd_hash_t, buf+off, ping->ping.hash );
  off += sizeof(fd_hash_t);

  memcpy( buf+off, ping->ping.sig, sizeof(fd_ed25519_sig_t) );
  off += sizeof(fd_ed25519_sig_t);

  return 0;
}

#include "fd_rotor_serde.h"
#include "../../ballet/bmtree/fd_bmtree.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../disco/shred/fd_fec_set.h"

ulong
fd_rotor_pong_ser( fd_rotor_pong_t const * self,
                   fd_ed25519_sig_t const  signature,
                   fd_pubkey_t const *     from,
                   uchar                   buf[ static FD_ROTOR_PONG_SER_SZ ] ) {
  ulong off = 0UL;
  FD_STORE( uint, buf+off, FD_ROTOR_SERDE_TAG_PONG );    off += sizeof(uint);
  memcpy( buf+off, from->uc,      sizeof(fd_pubkey_t) ); off += sizeof(fd_pubkey_t);
  memcpy( buf+off, self->hash.uc, sizeof(fd_hash_t)   ); off += sizeof(fd_hash_t);
  memcpy( buf+off, signature,     FD_ED25519_SIG_SZ   ); off += FD_ED25519_SIG_SZ;
  return off;
}

ulong
fd_rotor_req_sig_ser( uchar const * buf,
                      ulong         buf_sz,
                      uchar         out[ static FD_ROTOR_SIG_SER_MAX ] ) {
  memcpy( out,              buf,                                sizeof(uint)                          );
  memcpy( out+sizeof(uint), buf+sizeof(uint)+FD_ED25519_SIG_SZ, buf_sz-sizeof(uint)-FD_ED25519_SIG_SZ );
  return buf_sz-FD_ED25519_SIG_SZ;
}

ulong
fd_rotor_req_window_index_ser( fd_rotor_shred_t const * self,
                               fd_ed25519_sig_t const   signature,
                               fd_pubkey_t const *      sender,
                               fd_pubkey_t const *      recipient,
                               ulong                    timestamp,
                               uint                     nonce,
                               uchar                    buf[ static FD_ROTOR_WINDOW_INDEX_SER_SZ ] ) {
  ulong off = 0UL;
  FD_STORE( uint,  buf+off, FD_ROTOR_SERDE_TAG_WINDOW_INDEX ); off += sizeof(uint);
  memcpy( buf+off, signature,     FD_ED25519_SIG_SZ   );       off += FD_ED25519_SIG_SZ;
  memcpy( buf+off, sender->uc,    sizeof(fd_pubkey_t) );       off += sizeof(fd_pubkey_t);
  memcpy( buf+off, recipient->uc, sizeof(fd_pubkey_t) );       off += sizeof(fd_pubkey_t);
  FD_STORE( ulong, buf+off, timestamp );                       off += sizeof(ulong);
  FD_STORE( uint,  buf+off, nonce     );                       off += sizeof(uint);
  FD_STORE( ulong, buf+off, self->slot );                      off += sizeof(ulong);
  FD_STORE( ulong, buf+off, self->shred_idx );                 off += sizeof(ulong);
  return off;
}

ulong
fd_rotor_req_highest_window_index_ser( fd_rotor_highest_shred_t const * self,
                                       fd_ed25519_sig_t const           signature,
                                       fd_pubkey_t const *              sender,
                                       fd_pubkey_t const *              recipient,
                                       ulong                            timestamp,
                                       uint                             nonce,
                                       uchar                            buf[ static FD_ROTOR_HIGHEST_WINDOW_INDEX_SER_SZ ] ) {
  ulong off = 0UL;
  FD_STORE( uint,  buf+off, FD_ROTOR_SERDE_TAG_HIGHEST_WINDOW_INDEX ); off += sizeof(uint);
  memcpy( buf+off, signature,     FD_ED25519_SIG_SZ   );               off += FD_ED25519_SIG_SZ;
  memcpy( buf+off, sender->uc,    sizeof(fd_pubkey_t) );               off += sizeof(fd_pubkey_t);
  memcpy( buf+off, recipient->uc, sizeof(fd_pubkey_t) );               off += sizeof(fd_pubkey_t);
  FD_STORE( ulong, buf+off, timestamp );                               off += sizeof(ulong);
  FD_STORE( uint,  buf+off, nonce     );                               off += sizeof(uint);
  FD_STORE( ulong, buf+off, self->slot );                              off += sizeof(ulong);
  FD_STORE( ulong, buf+off, self->shred_idx );                         off += sizeof(ulong);
  return off;
}

ulong
fd_rotor_req_orphan_ser( fd_rotor_orphan_t const * self,
                         fd_ed25519_sig_t const    signature,
                         fd_pubkey_t const *       sender,
                         fd_pubkey_t const *       recipient,
                         ulong                     timestamp,
                         uint                      nonce,
                         uchar                     buf[ static FD_ROTOR_ORPHAN_SER_SZ ] ) {
  ulong off = 0UL;
  FD_STORE( uint,  buf+off, FD_ROTOR_SERDE_TAG_ORPHAN ); off += sizeof(uint);
  memcpy( buf+off, signature,     FD_ED25519_SIG_SZ   ); off += FD_ED25519_SIG_SZ;
  memcpy( buf+off, sender->uc,    sizeof(fd_pubkey_t) ); off += sizeof(fd_pubkey_t);
  memcpy( buf+off, recipient->uc, sizeof(fd_pubkey_t) ); off += sizeof(fd_pubkey_t);
  FD_STORE( ulong, buf+off, timestamp );                 off += sizeof(ulong);
  FD_STORE( uint,  buf+off, nonce     );                 off += sizeof(uint);
  FD_STORE( ulong, buf+off, self->slot );                off += sizeof(ulong);
  return off;
}

ulong
fd_rotor_req_parent_and_fec_set_count_ser( fd_rotor_parent_fec_set_count_t const * self,
                                           fd_ed25519_sig_t const                  signature,
                                           fd_pubkey_t const *                     sender,
                                           fd_pubkey_t const *                     recipient,
                                           ulong                                   timestamp,
                                           uint                                    nonce,
                                           uchar                                   buf[ static FD_ROTOR_PARENT_AND_FEC_SET_COUNT_SER_SZ ] ) {
  ulong off = 0UL;
  FD_STORE( uint,  buf+off, FD_ROTOR_SERDE_TAG_PARENT_AND_FEC_SET_COUNT ); off += sizeof(uint);
  memcpy( buf+off, signature,     FD_ED25519_SIG_SZ   );                   off += FD_ED25519_SIG_SZ;
  memcpy( buf+off, sender->uc,    sizeof(fd_pubkey_t) );                   off += sizeof(fd_pubkey_t);
  memcpy( buf+off, recipient->uc, sizeof(fd_pubkey_t) );                   off += sizeof(fd_pubkey_t);
  FD_STORE( ulong, buf+off, timestamp );                                   off += sizeof(ulong);
  FD_STORE( uint,  buf+off, nonce     );                                   off += sizeof(uint);
  FD_STORE( ulong, buf+off, self->slot );                                  off += sizeof(ulong);
  memcpy( buf+off, self->block_id.uc, sizeof(fd_hash_t) );                 off += sizeof(fd_hash_t);
  return off;
}

ulong
fd_rotor_req_fec_set_root_ser( fd_rotor_fec_set_root_t const * self,
                               fd_ed25519_sig_t const          signature,
                               fd_pubkey_t const *             sender,
                               fd_pubkey_t const *             recipient,
                               ulong                           timestamp,
                               uint                            nonce,
                               uchar                           buf[ static FD_ROTOR_FEC_SET_ROOT_SER_SZ ] ) {
  ulong off = 0UL;
  FD_STORE( uint,  buf+off, FD_ROTOR_SERDE_TAG_FEC_SET_ROOT ); off += sizeof(uint);
  memcpy( buf+off, signature,     FD_ED25519_SIG_SZ   );       off += FD_ED25519_SIG_SZ;
  memcpy( buf+off, sender->uc,    sizeof(fd_pubkey_t) );       off += sizeof(fd_pubkey_t);
  memcpy( buf+off, recipient->uc, sizeof(fd_pubkey_t) );       off += sizeof(fd_pubkey_t);
  FD_STORE( ulong, buf+off, timestamp );                       off += sizeof(ulong);
  FD_STORE( uint,  buf+off, nonce     );                       off += sizeof(uint);
  FD_STORE( ulong, buf+off, self->slot );                      off += sizeof(ulong);
  memcpy( buf+off, self->block_id.uc, sizeof(fd_hash_t) );     off += sizeof(fd_hash_t);
  FD_STORE( uint,  buf+off, self->fec_set_idx );               off += sizeof(uint);
  return off;
}

ulong
fd_rotor_req_window_index_for_block_id_ser( fd_rotor_shred_for_block_id_t const * self,
                                            fd_ed25519_sig_t const                signature,
                                            fd_pubkey_t const *                   sender,
                                            fd_pubkey_t const *                   recipient,
                                            ulong                                 timestamp,
                                            uint                                  nonce,
                                            uchar                                 buf[ static FD_ROTOR_WINDOW_INDEX_FOR_BLOCK_ID_SER_SZ ] ) {
  ulong off = 0UL;
  FD_STORE( uint,  buf+off, FD_ROTOR_SERDE_TAG_WINDOW_INDEX_FOR_BLOCK_ID ); off += sizeof(uint);
  memcpy( buf+off, signature,     FD_ED25519_SIG_SZ   );                    off += FD_ED25519_SIG_SZ;
  memcpy( buf+off, sender->uc,    sizeof(fd_pubkey_t) );                    off += sizeof(fd_pubkey_t);
  memcpy( buf+off, recipient->uc, sizeof(fd_pubkey_t) );                    off += sizeof(fd_pubkey_t);
  FD_STORE( ulong, buf+off, timestamp );                                    off += sizeof(ulong);
  FD_STORE( uint,  buf+off, nonce     );                                    off += sizeof(uint);
  FD_STORE( ulong, buf+off, self->slot );                                   off += sizeof(ulong);
  FD_STORE( uint,  buf+off, self->shred_idx );                              off += sizeof(uint);
  memcpy( buf+off, self->block_id.uc, sizeof(fd_hash_t) );                  off += sizeof(fd_hash_t);
  return off;
}

ulong
fd_rotor_ping_de( uchar const *    buf,
                  ulong            buf_sz,
                  fd_pubkey_t *    from,
                  fd_hash_t *      token,
                  fd_ed25519_sig_t signature ) {
  if( FD_UNLIKELY( buf_sz<FD_ROTOR_PING_DE_SZ || FD_LOAD( uint, buf )!=FD_ROTOR_SERDE_TAG_PING ) ) return 0UL;
  ulong off = sizeof(uint);
  memcpy( from->uc,  buf+off, sizeof(fd_pubkey_t) ); off += sizeof(fd_pubkey_t);
  memcpy( token->uc, buf+off, sizeof(fd_hash_t)   ); off += sizeof(fd_hash_t);
  memcpy( signature, buf+off, FD_ED25519_SIG_SZ   ); off += FD_ED25519_SIG_SZ;
  return off;
}

ulong
fd_rotor_block_id_ping_de( uchar const *    buf,
                           ulong            buf_sz,
                           fd_pubkey_t *    from,
                           fd_hash_t *      token,
                           fd_ed25519_sig_t signature ) {
  if( FD_UNLIKELY( buf_sz<FD_ROTOR_PING_DE_SZ || FD_LOAD( uint, buf )!=FD_ROTOR_SERDE_TAG_BLOCK_ID_PING ) ) return 0UL;
  ulong off = sizeof(uint);
  memcpy( from->uc,  buf+off, sizeof(fd_pubkey_t) ); off += sizeof(fd_pubkey_t);
  memcpy( token->uc, buf+off, sizeof(fd_hash_t)   ); off += sizeof(fd_hash_t);
  memcpy( signature, buf+off, FD_ED25519_SIG_SZ   ); off += FD_ED25519_SIG_SZ;
  return off;
}

ulong
fd_rotor_res_parent_fec_set_count_de( uchar const * buf,
                                      ulong         buf_sz,
                                      uint *        fec_set_cnt,
                                      ulong *       parent_slot,
                                      fd_hash_t *   parent_block_id,
                                      uchar         proof[ static FD_ROTOR_PROOF_MAX ],
                                      ulong *       proof_sz,
                                      uint *        nonce ) {
  if( FD_UNLIKELY( buf_sz<sizeof(uint)+sizeof(uint)+sizeof(ulong)+sizeof(fd_hash_t)+sizeof(ulong) ) ) return 0UL;
  if( FD_UNLIKELY( FD_LOAD( uint, buf )!=FD_ROTOR_SERDE_TAG_PARENT_FEC_SET_COUNT_RES              ) ) return 0UL;
  ulong off = sizeof(uint);
  *fec_set_cnt = FD_LOAD( uint,  buf+off );                  off += sizeof(uint);
  *parent_slot = FD_LOAD( ulong, buf+off );                  off += sizeof(ulong);
  memcpy( parent_block_id->uc, buf+off, sizeof(fd_hash_t) ); off += sizeof(fd_hash_t);
  *proof_sz    = FD_LOAD( ulong, buf+off );                  off += sizeof(ulong);
  if( FD_UNLIKELY( *proof_sz>FD_ROTOR_PROOF_MAX || *proof_sz+sizeof(uint)>buf_sz-off ) ) return 0UL;
  memcpy( proof, buf+off, *proof_sz );                       off += *proof_sz;
  *nonce       = FD_LOAD( uint, buf+off );                   off += sizeof(uint);
  return off;
}

ulong
fd_rotor_res_fec_set_root_de( uchar const * buf,
                              ulong         buf_sz,
                              uchar         fec_set_root[ static FD_SHRED_MERKLE_NODE_SZ ],
                              uchar         proof[ static FD_ROTOR_PROOF_MAX ],
                              ulong *       proof_sz,
                              uint *        nonce ) {
  if( FD_UNLIKELY( buf_sz<sizeof(uint)+FD_SHRED_MERKLE_NODE_SZ+sizeof(ulong) ) ) return 0UL;
  if( FD_UNLIKELY( FD_LOAD( uint, buf )!=FD_ROTOR_SERDE_TAG_FEC_SET_ROOT_RES   ) ) return 0UL;
  ulong off = sizeof(uint);
  memcpy( fec_set_root, buf+off, FD_SHRED_MERKLE_NODE_SZ ); off += FD_SHRED_MERKLE_NODE_SZ;
  *proof_sz = FD_LOAD( ulong, buf+off );                     off += sizeof(ulong);
  if( FD_UNLIKELY( *proof_sz>FD_ROTOR_PROOF_MAX || *proof_sz+sizeof(uint)>buf_sz-off ) ) return 0UL;
  memcpy( proof, buf+off, *proof_sz );                       off += *proof_sz;
  *nonce    = FD_LOAD( uint, buf+off );                      off += sizeof(uint);
  return off;
}

int
fd_rotor_res_parent_fec_set_count_verify( uint              fec_set_cnt,
                                          ulong             parent_slot,
                                          fd_hash_t const * parent_block_id,
                                          uchar const *     proof,
                                          ulong             proof_sz,
                                          fd_hash_t const * block_id ) {
  if( FD_UNLIKELY( !fec_set_cnt || fec_set_cnt>FD_FEC_BLK_MAX                                     ) ) return -1;
  if( FD_UNLIKELY( proof_sz!=( fd_bmtree_depth( fec_set_cnt+1UL )-1UL )*FD_SHRED_MERKLE_NODE_SZ ) ) return -1;

  fd_bmtree_node_t leaf[1];
  fd_sha256_t      sha[1];
  fd_sha256_init  ( sha );
  fd_sha256_append( sha, &parent_slot,        sizeof(ulong)     );
  fd_sha256_append( sha, parent_block_id->uc, sizeof(fd_hash_t) );
  fd_sha256_append( sha, &fec_set_cnt,        sizeof(uint)      );
  fd_sha256_fini  ( sha, leaf->hash );

  fd_bmtree_node_t root[1];
  if( FD_UNLIKELY( !fd_bmtree_from_proof( leaf, fec_set_cnt, root, proof, proof_sz/FD_SHRED_MERKLE_NODE_SZ, FD_SHRED_MERKLE_NODE_SZ, FD_BMTREE_LONG_PREFIX_SZ ) ) ) return -1;
  if( FD_UNLIKELY( memcmp( root->hash, block_id->uc, sizeof(fd_hash_t) )                                                                                   ) ) return -1;
  return 0;
}

int
fd_rotor_res_fec_set_root_verify( uchar const       fec_set_root[ static FD_SHRED_MERKLE_NODE_SZ ],
                                  uchar const *     proof,
                                  ulong             proof_sz,
                                  fd_hash_t const * block_id,
                                  uint              fec_set_idx,
                                  uint              fec_set_cnt ) {
  if( FD_UNLIKELY( !fec_set_cnt || fec_set_cnt>FD_FEC_BLK_MAX                                     ) ) return -1;
  if( FD_UNLIKELY( fec_set_idx%FD_FEC_SHRED_CNT || fec_set_idx/FD_FEC_SHRED_CNT>=fec_set_cnt      ) ) return -1;
  if( FD_UNLIKELY( proof_sz!=( fd_bmtree_depth( fec_set_cnt+1UL )-1UL )*FD_SHRED_MERKLE_NODE_SZ ) ) return -1;

  fd_bmtree_node_t leaf[1] = {0};
  memcpy( leaf->hash, fec_set_root, FD_SHRED_MERKLE_NODE_SZ );

  fd_bmtree_node_t root[1];
  if( FD_UNLIKELY( !fd_bmtree_from_proof( leaf, fec_set_idx/FD_FEC_SHRED_CNT, root, proof, proof_sz/FD_SHRED_MERKLE_NODE_SZ, FD_SHRED_MERKLE_NODE_SZ, FD_BMTREE_LONG_PREFIX_SZ ) ) ) return -1;
  if( FD_UNLIKELY( memcmp( root->hash, block_id->uc, sizeof(fd_hash_t) )                                                                                                       ) ) return -1;
  return 0;
}

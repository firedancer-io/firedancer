#ifndef HEADER_fd_src_choreo_rotor_fd_rotor_serde_h
#define HEADER_fd_src_choreo_rotor_fd_rotor_serde_h

#include "../fd_choreo_base.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/shred/fd_shred.h"

/* FD_ROTOR_PROOF_MAX bounds a merkle proof in a response: 63 entries,
   enough for u64::MAX FEC sets. */

#define FD_ROTOR_PROOF_MAX (63UL*FD_SHRED_MERKLE_NODE_SZ)

struct fd_rotor_pong {
  fd_hash_t hash;
};
typedef struct fd_rotor_pong fd_rotor_pong_t;

struct fd_rotor_shred {
  ulong slot;
  ulong shred_idx;
};
typedef struct fd_rotor_shred fd_rotor_shred_t;

struct fd_rotor_highest_shred {
  ulong slot;
  ulong shred_idx;
};
typedef struct fd_rotor_highest_shred fd_rotor_highest_shred_t;

struct fd_rotor_orphan {
  ulong slot;
};
typedef struct fd_rotor_orphan fd_rotor_orphan_t;

struct fd_rotor_parent_fec_set_count {
  ulong     slot;
  fd_hash_t block_id;
};
typedef struct fd_rotor_parent_fec_set_count fd_rotor_parent_fec_set_count_t;

struct fd_rotor_fec_set_root {
  ulong     slot;
  fd_hash_t block_id;
  uint      fec_set_idx;
};
typedef struct fd_rotor_fec_set_root fd_rotor_fec_set_root_t;

struct fd_rotor_shred_for_block_id {
  ulong     slot;
  uint      shred_idx;
  fd_hash_t block_id;
};
typedef struct fd_rotor_shred_for_block_id fd_rotor_shred_for_block_id_t;

#define FD_ROTOR_SERDE_TAG_PONG                      (7U)
#define FD_ROTOR_SERDE_TAG_WINDOW_INDEX              (8U)
#define FD_ROTOR_SERDE_TAG_HIGHEST_WINDOW_INDEX      (9U)
#define FD_ROTOR_SERDE_TAG_ORPHAN                    (10U)
#define FD_ROTOR_SERDE_TAG_PARENT_AND_FEC_SET_COUNT  (12U)
#define FD_ROTOR_SERDE_TAG_FEC_SET_ROOT              (13U)
#define FD_ROTOR_SERDE_TAG_WINDOW_INDEX_FOR_BLOCK_ID (14U)

/* RepairResponse, and BlockIdRepairResponse */

#define FD_ROTOR_SERDE_TAG_PING                      (0U)
#define FD_ROTOR_SERDE_TAG_PARENT_FEC_SET_COUNT_RES  (0U)
#define FD_ROTOR_SERDE_TAG_FEC_SET_ROOT_RES          (1U)
#define FD_ROTOR_SERDE_TAG_BLOCK_ID_PING             (2U)

#define FD_ROTOR_PONG_SER_SZ ( sizeof(uint)        /* tag       */ + \
                               sizeof(fd_pubkey_t) /* from      */ + \
                               sizeof(fd_hash_t)   /* hash      */ + \
                               FD_ED25519_SIG_SZ   /* signature */ )

#define FD_ROTOR_HEADER_SER_SZ ( sizeof(uint)        /* tag       */ + \
                                 FD_ED25519_SIG_SZ   /* signature */ + \
                                 sizeof(fd_pubkey_t) /* sender    */ + \
                                 sizeof(fd_pubkey_t) /* recipient */ + \
                                 sizeof(ulong)       /* timestamp */ + \
                                 sizeof(uint)        /* nonce     */ )

#define FD_ROTOR_WINDOW_INDEX_SER_SZ              ( FD_ROTOR_HEADER_SER_SZ + sizeof(ulong) /* slot */ + sizeof(ulong)     /* shred_index */ )
#define FD_ROTOR_HIGHEST_WINDOW_INDEX_SER_SZ      ( FD_ROTOR_HEADER_SER_SZ + sizeof(ulong) /* slot */ + sizeof(ulong)     /* shred_index */ )
#define FD_ROTOR_ORPHAN_SER_SZ                    ( FD_ROTOR_HEADER_SER_SZ + sizeof(ulong) /* slot */ )
#define FD_ROTOR_PARENT_AND_FEC_SET_COUNT_SER_SZ  ( FD_ROTOR_HEADER_SER_SZ + sizeof(ulong) /* slot */ + sizeof(fd_hash_t) /* block_id    */ )
#define FD_ROTOR_FEC_SET_ROOT_SER_SZ              ( FD_ROTOR_HEADER_SER_SZ + sizeof(ulong) /* slot */ + sizeof(fd_hash_t) /* block_id    */ + sizeof(uint)      /* fec_set_index */ )
#define FD_ROTOR_WINDOW_INDEX_FOR_BLOCK_ID_SER_SZ ( FD_ROTOR_HEADER_SER_SZ + sizeof(ulong) /* slot */ + sizeof(uint)      /* shred_index */ + sizeof(fd_hash_t) /* block_id      */ )

#define FD_ROTOR_SER_MAX FD_ROTOR_WINDOW_INDEX_FOR_BLOCK_ID_SER_SZ

#define FD_ROTOR_PING_DE_SZ ( sizeof(uint)        /* tag       */ + \
                              sizeof(fd_pubkey_t) /* from      */ + \
                              sizeof(fd_hash_t)   /* token     */ + \
                              FD_ED25519_SIG_SZ   /* signature */ )

#define FD_ROTOR_SIG_SER_MAX ( FD_ROTOR_SER_MAX - FD_ED25519_SIG_SZ )

FD_PROTOTYPES_BEGIN

/* signature, sender, recipient, timestamp and nonce (signature and
   from for a pong) are attached at send time and are not part of the
   request structs.  Each ser returns the bytes written. */

ulong
fd_rotor_pong_ser( fd_rotor_pong_t const * self,
                   fd_ed25519_sig_t const  signature,
                   fd_pubkey_t const *     from,
                   uchar                   buf[ static FD_ROTOR_PONG_SER_SZ ] );

/* fd_rotor_req_sig_ser writes the signing preimage of the serialized
   request in buf to out and returns its size.  Not for a pong, whose
   preimage is "SOLANA_PING_PONG" and the ping's token. */

ulong
fd_rotor_req_sig_ser( uchar const * buf,
                      ulong         buf_sz,
                      uchar         out[ static FD_ROTOR_SIG_SER_MAX ] );

ulong
fd_rotor_req_window_index_ser( fd_rotor_shred_t const * self,
                               fd_ed25519_sig_t const   signature,
                               fd_pubkey_t const *      sender,
                               fd_pubkey_t const *      recipient,
                               ulong                    timestamp,
                               uint                     nonce,
                               uchar                    buf[ static FD_ROTOR_WINDOW_INDEX_SER_SZ ] );

ulong
fd_rotor_req_highest_window_index_ser( fd_rotor_highest_shred_t const * self,
                                       fd_ed25519_sig_t const           signature,
                                       fd_pubkey_t const *              sender,
                                       fd_pubkey_t const *              recipient,
                                       ulong                            timestamp,
                                       uint                             nonce,
                                       uchar                            buf[ static FD_ROTOR_HIGHEST_WINDOW_INDEX_SER_SZ ] );

ulong
fd_rotor_req_orphan_ser( fd_rotor_orphan_t const * self,
                         fd_ed25519_sig_t const    signature,
                         fd_pubkey_t const *       sender,
                         fd_pubkey_t const *       recipient,
                         ulong                     timestamp,
                         uint                      nonce,
                         uchar                     buf[ static FD_ROTOR_ORPHAN_SER_SZ ] );

ulong
fd_rotor_req_parent_and_fec_set_count_ser( fd_rotor_parent_fec_set_count_t const * self,
                                           fd_ed25519_sig_t const                  signature,
                                           fd_pubkey_t const *                     sender,
                                           fd_pubkey_t const *                     recipient,
                                           ulong                                   timestamp,
                                           uint                                    nonce,
                                           uchar                                   buf[ static FD_ROTOR_PARENT_AND_FEC_SET_COUNT_SER_SZ ] );

ulong
fd_rotor_req_fec_set_root_ser( fd_rotor_fec_set_root_t const * self,
                               fd_ed25519_sig_t const          signature,
                               fd_pubkey_t const *             sender,
                               fd_pubkey_t const *             recipient,
                               ulong                           timestamp,
                               uint                            nonce,
                               uchar                           buf[ static FD_ROTOR_FEC_SET_ROOT_SER_SZ ] );

ulong
fd_rotor_req_window_index_for_block_id_ser( fd_rotor_shred_for_block_id_t const * self,
                                            fd_ed25519_sig_t const                signature,
                                            fd_pubkey_t const *                   sender,
                                            fd_pubkey_t const *                   recipient,
                                            ulong                                 timestamp,
                                            uint                                  nonce,
                                            uchar                                 buf[ static FD_ROTOR_WINDOW_INDEX_FOR_BLOCK_ID_SER_SZ ] );

ulong
fd_rotor_ping_de( uchar const *    buf,
                  ulong            buf_sz,
                  fd_pubkey_t *    from,
                  fd_hash_t *      token,
                  fd_ed25519_sig_t signature );

ulong
fd_rotor_block_id_ping_de( uchar const *    buf,
                           ulong            buf_sz,
                           fd_pubkey_t *    from,
                           fd_hash_t *      token,
                           fd_ed25519_sig_t signature );

ulong
fd_rotor_res_parent_fec_set_count_de( uchar const * buf,
                                      ulong         buf_sz,
                                      uint *        fec_set_cnt,
                                      ulong *       parent_slot,
                                      fd_hash_t *   parent_block_id,
                                      uchar         proof[ static FD_ROTOR_PROOF_MAX ],
                                      ulong *       proof_sz,
                                      uint *        nonce );

ulong
fd_rotor_res_fec_set_root_de( uchar const * buf,
                              ulong         buf_sz,
                              uchar         fec_set_root[ static FD_SHRED_MERKLE_NODE_SZ ],
                              uchar         proof[ static FD_ROTOR_PROOF_MAX ],
                              ulong *       proof_sz,
                              uint *        nonce );

/* fd_rotor_res_parent_fec_set_count_verify and
   fd_rotor_res_fec_set_root_verify check a decoded response's proof
   against block_id, the block the request named.  fec_set_idx and
   fec_set_cnt are the requested FEC set index and the block's FEC set
   count.  Return 0 if it verifies, -1 otherwise. */

int
fd_rotor_res_parent_fec_set_count_verify( uint              fec_set_cnt,
                                          ulong             parent_slot,
                                          fd_hash_t const * parent_block_id,
                                          uchar const *     proof,
                                          ulong             proof_sz,
                                          fd_hash_t const * block_id );

int
fd_rotor_res_fec_set_root_verify( uchar const       fec_set_root[ static FD_SHRED_MERKLE_NODE_SZ ],
                                  uchar const *     proof,
                                  ulong             proof_sz,
                                  fd_hash_t const * block_id,
                                  uint              fec_set_idx,
                                  uint              fec_set_cnt );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_rotor_fd_rotor_serde_h */

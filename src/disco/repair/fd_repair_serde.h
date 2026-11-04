#ifndef HEADER_fd_src_disco_repair_fd_repair_serde_h
#define HEADER_fd_src_disco_repair_fd_repair_serde_h

#include "../../flamenco/fd_flamenco_base.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../disco/shred/fd_fec_set.h"

/* FD_REPAIR_PROOF_MAX bounds a merkle proof in a response: 63 entries,
   enough for u64::MAX FEC sets. */

#define FD_REPAIR_PROOF_MAX (63UL*FD_SHRED_MERKLE_NODE_SZ)

struct fd_repair_pong {
  fd_hash_t hash;
};
typedef struct fd_repair_pong fd_repair_pong_t;

struct fd_repair_shred {
  ulong slot;
  ulong shred_idx;
};
typedef struct fd_repair_shred fd_repair_shred_t;

struct fd_repair_highest_shred {
  ulong slot;
  ulong shred_idx;
};
typedef struct fd_repair_highest_shred fd_repair_highest_shred_t;

struct fd_repair_orphan {
  ulong slot;
};
typedef struct fd_repair_orphan fd_repair_orphan_t;

struct fd_repair_parent_fec_set_count {
  ulong     slot;
  fd_hash_t block_id;
};
typedef struct fd_repair_parent_fec_set_count fd_repair_parent_fec_set_count_t;

struct fd_repair_fec_set_root {
  ulong     slot;
  fd_hash_t block_id;
  uint      fec_set_idx;
};
typedef struct fd_repair_fec_set_root fd_repair_fec_set_root_t;

struct fd_repair_shred_for_block_id {
  ulong     slot;
  uint      shred_idx;
  fd_hash_t block_id;
};
typedef struct fd_repair_shred_for_block_id fd_repair_shred_for_block_id_t;

#define FD_REPAIR_SERDE_TAG_PONG                      (7U)
#define FD_REPAIR_SERDE_TAG_WINDOW_INDEX              (8U)
#define FD_REPAIR_SERDE_TAG_HIGHEST_WINDOW_INDEX      (9U)
#define FD_REPAIR_SERDE_TAG_ORPHAN                    (10U)
#define FD_REPAIR_SERDE_TAG_ANCESTOR_HASHES           (11U)
#define FD_REPAIR_SERDE_TAG_PARENT_AND_FEC_SET_COUNT  (12U)
#define FD_REPAIR_SERDE_TAG_FEC_SET_ROOT              (13U)
#define FD_REPAIR_SERDE_TAG_WINDOW_INDEX_FOR_BLOCK_ID (14U)

/* RepairResponse, and BlockIdRepairResponse */

#define FD_REPAIR_SERDE_TAG_PING                      (0U)
#define FD_REPAIR_SERDE_TAG_PARENT_FEC_SET_COUNT_RES  (0U)
#define FD_REPAIR_SERDE_TAG_FEC_SET_ROOT_RES          (1U)
#define FD_REPAIR_SERDE_TAG_BLOCK_ID_PING             (2U)

#define FD_REPAIR_PONG_SER_SZ ( sizeof(uint)        /* tag       */ + \
                                sizeof(fd_pubkey_t) /* from      */ + \
                                sizeof(fd_hash_t)   /* hash      */ + \
                                FD_ED25519_SIG_SZ   /* signature */ )

#define FD_REPAIR_HEADER_SER_SZ ( sizeof(uint)        /* tag       */ + \
                                  FD_ED25519_SIG_SZ   /* signature */ + \
                                  sizeof(fd_pubkey_t) /* sender    */ + \
                                  sizeof(fd_pubkey_t) /* recipient */ + \
                                  sizeof(ulong)       /* timestamp */ + \
                                  sizeof(uint)        /* nonce     */ )

#define FD_REPAIR_WINDOW_INDEX_SER_SZ              ( FD_REPAIR_HEADER_SER_SZ + sizeof(ulong) /* slot */ + sizeof(ulong)     /* shred_index */ )
#define FD_REPAIR_HIGHEST_WINDOW_INDEX_SER_SZ      ( FD_REPAIR_HEADER_SER_SZ + sizeof(ulong) /* slot */ + sizeof(ulong)     /* shred_index */ )
#define FD_REPAIR_ORPHAN_SER_SZ                    ( FD_REPAIR_HEADER_SER_SZ + sizeof(ulong) /* slot */ )
#define FD_REPAIR_PARENT_AND_FEC_SET_COUNT_SER_SZ  ( FD_REPAIR_HEADER_SER_SZ + sizeof(ulong) /* slot */ + sizeof(fd_hash_t) /* block_id    */ )
#define FD_REPAIR_FEC_SET_ROOT_SER_SZ              ( FD_REPAIR_HEADER_SER_SZ + sizeof(ulong) /* slot */ + sizeof(fd_hash_t) /* block_id    */ + sizeof(uint)      /* fec_set_index */ )
#define FD_REPAIR_WINDOW_INDEX_FOR_BLOCK_ID_SER_SZ ( FD_REPAIR_HEADER_SER_SZ + sizeof(ulong) /* slot */ + sizeof(uint)      /* shred_index */ + sizeof(fd_hash_t) /* block_id      */ )

#define FD_REPAIR_SER_MAX FD_REPAIR_WINDOW_INDEX_FOR_BLOCK_ID_SER_SZ

#define FD_REPAIR_PING_DE_SZ ( sizeof(uint)        /* tag       */ + \
                               sizeof(fd_pubkey_t) /* from      */ + \
                               sizeof(fd_hash_t)   /* token     */ + \
                               FD_ED25519_SIG_SZ   /* signature */ )

#define FD_REPAIR_SIG_SER_MAX ( FD_REPAIR_SER_MAX - FD_ED25519_SIG_SZ )

/* FD_REPAIR_RES_DE_MAX bounds the size of a block id metadata response
   the shred tiles forward to repair and rserve serializes into: a parent
   and FEC set count response whose proof has a node for each layer of
   the largest block any configuration allows.  Shred responses are
   always larger. */

#define FD_REPAIR_RES_DE_MAX ( sizeof(uint)      /* tag             */ + \
                               sizeof(uint)      /* fec_set_count   */ + \
                               sizeof(ulong)     /* parent_slot     */ + \
                               sizeof(fd_hash_t) /* parent_block_id */ + \
                               sizeof(ulong)     /* proof_sz        */ + \
                               (1UL+(63UL-(ulong)__builtin_clzl( FD_SHRED_BLK_MAX_RAISED/FD_FEC_SHRED_CNT )))*FD_SHRED_MERKLE_NODE_SZ /* proof */ + \
                               sizeof(uint)      /* nonce           */ )

FD_STATIC_ASSERT( FD_REPAIR_RES_DE_MAX<FD_SHRED_MIN_SZ, repair_res_de_max );

/* FD_REPAIR_NET_FRAME_MAX bounds a forwarded repair frame: the largest
   Ethernet, IP and UDP header a netmux sig encodes, plus the payload. */

#define FD_REPAIR_NET_FRAME_MAX (42UL+4UL*15UL+FD_REPAIR_RES_DE_MAX)

FD_PROTOTYPES_BEGIN

/* signature, sender, recipient, timestamp and nonce (signature and
   from for a pong) are attached at send time and are not part of the
   request structs.  Each ser returns the bytes written. */

ulong
fd_repair_pong_ser( fd_repair_pong_t const * self,
                    fd_ed25519_sig_t const   signature,
                    fd_pubkey_t const *      from,
                    uchar                    buf[ static FD_REPAIR_PONG_SER_SZ ] );

/* fd_repair_req_sig_ser writes the signing preimage of the serialized
   request in buf to out and returns its size.  Not for a pong, whose
   preimage is "SOLANA_PING_PONG" and the ping's token. */

ulong
fd_repair_req_sig_ser( uchar const * buf,
                       ulong         buf_sz,
                       uchar         out[ static FD_REPAIR_SIG_SER_MAX ] );

ulong
fd_repair_req_window_index_ser( fd_repair_shred_t const * self,
                                fd_ed25519_sig_t const    signature,
                                fd_pubkey_t const *       sender,
                                fd_pubkey_t const *       recipient,
                                ulong                     timestamp,
                                uint                      nonce,
                                uchar                     buf[ static FD_REPAIR_WINDOW_INDEX_SER_SZ ] );

ulong
fd_repair_req_highest_window_index_ser( fd_repair_highest_shred_t const * self,
                                        fd_ed25519_sig_t const            signature,
                                        fd_pubkey_t const *               sender,
                                        fd_pubkey_t const *               recipient,
                                        ulong                             timestamp,
                                        uint                              nonce,
                                        uchar                             buf[ static FD_REPAIR_HIGHEST_WINDOW_INDEX_SER_SZ ] );

ulong
fd_repair_req_orphan_ser( fd_repair_orphan_t const * self,
                          fd_ed25519_sig_t const     signature,
                          fd_pubkey_t const *        sender,
                          fd_pubkey_t const *        recipient,
                          ulong                      timestamp,
                          uint                       nonce,
                          uchar                      buf[ static FD_REPAIR_ORPHAN_SER_SZ ] );

ulong
fd_repair_req_parent_and_fec_set_count_ser( fd_repair_parent_fec_set_count_t const * self,
                                            fd_ed25519_sig_t const                   signature,
                                            fd_pubkey_t const *                      sender,
                                            fd_pubkey_t const *                      recipient,
                                            ulong                                    timestamp,
                                            uint                                     nonce,
                                            uchar                                    buf[ static FD_REPAIR_PARENT_AND_FEC_SET_COUNT_SER_SZ ] );

ulong
fd_repair_req_fec_set_root_ser( fd_repair_fec_set_root_t const * self,
                                fd_ed25519_sig_t const           signature,
                                fd_pubkey_t const *              sender,
                                fd_pubkey_t const *              recipient,
                                ulong                            timestamp,
                                uint                             nonce,
                                uchar                            buf[ static FD_REPAIR_FEC_SET_ROOT_SER_SZ ] );

ulong
fd_repair_req_window_index_for_block_id_ser( fd_repair_shred_for_block_id_t const * self,
                                             fd_ed25519_sig_t const                 signature,
                                             fd_pubkey_t const *                    sender,
                                             fd_pubkey_t const *                    recipient,
                                             ulong                                  timestamp,
                                             uint                                   nonce,
                                             uchar                                  buf[ static FD_REPAIR_WINDOW_INDEX_FOR_BLOCK_ID_SER_SZ ] );

/* Each request de reads a request of its kind from buf and returns
   the bytes read, 0 if buf does not start with one.  Does not verify
   the signature. */

ulong
fd_repair_req_window_index_de( uchar const *       buf,
                               ulong               buf_sz,
                               fd_repair_shred_t * self,
                               fd_ed25519_sig_t    signature,
                               fd_pubkey_t *       sender,
                               fd_pubkey_t *       recipient,
                               ulong *             timestamp,
                               uint *              nonce );

ulong
fd_repair_req_highest_window_index_de( uchar const *               buf,
                                       ulong                       buf_sz,
                                       fd_repair_highest_shred_t * self,
                                       fd_ed25519_sig_t            signature,
                                       fd_pubkey_t *               sender,
                                       fd_pubkey_t *               recipient,
                                       ulong *                     timestamp,
                                       uint *                      nonce );

ulong
fd_repair_req_orphan_de( uchar const *        buf,
                         ulong                buf_sz,
                         fd_repair_orphan_t * self,
                         fd_ed25519_sig_t     signature,
                         fd_pubkey_t *        sender,
                         fd_pubkey_t *        recipient,
                         ulong *              timestamp,
                         uint *               nonce );

ulong
fd_repair_req_parent_and_fec_set_count_de( uchar const *                      buf,
                                           ulong                              buf_sz,
                                           fd_repair_parent_fec_set_count_t * self,
                                           fd_ed25519_sig_t                   signature,
                                           fd_pubkey_t *                      sender,
                                           fd_pubkey_t *                      recipient,
                                           ulong *                            timestamp,
                                           uint *                             nonce );

ulong
fd_repair_req_fec_set_root_de( uchar const *              buf,
                               ulong                      buf_sz,
                               fd_repair_fec_set_root_t * self,
                               fd_ed25519_sig_t           signature,
                               fd_pubkey_t *              sender,
                               fd_pubkey_t *              recipient,
                               ulong *                    timestamp,
                               uint *                     nonce );

ulong
fd_repair_req_window_index_for_block_id_de( uchar const *                    buf,
                                            ulong                            buf_sz,
                                            fd_repair_shred_for_block_id_t * self,
                                            fd_ed25519_sig_t                 signature,
                                            fd_pubkey_t *                    sender,
                                            fd_pubkey_t *                    recipient,
                                            ulong *                          timestamp,
                                            uint *                           nonce );

ulong
fd_repair_pong_de( uchar const *      buf,
                   ulong              buf_sz,
                   fd_repair_pong_t * self,
                   fd_ed25519_sig_t   signature,
                   fd_pubkey_t *      from );

ulong
fd_repair_ping_ser( fd_pubkey_t const *    from,
                    fd_hash_t const *      token,
                    fd_ed25519_sig_t const signature,
                    uchar                  buf[ static FD_REPAIR_PING_DE_SZ ] );

ulong
fd_repair_block_id_ping_ser( fd_pubkey_t const *    from,
                             fd_hash_t const *      token,
                             fd_ed25519_sig_t const signature,
                             uchar                  buf[ static FD_REPAIR_PING_DE_SZ ] );

/* fd_repair_res_parent_fec_set_count_ser and fd_repair_res_fec_set_root_ser
   write a response, proof_sz bytes of proof included, and return the
   bytes written, 0 if it does not fit in buf_sz. */

ulong
fd_repair_res_parent_fec_set_count_ser( uint              fec_set_cnt,
                                        ulong             parent_slot,
                                        fd_hash_t const * parent_block_id,
                                        uchar const *     proof,
                                        ulong             proof_sz,
                                        uint              nonce,
                                        uchar *           buf,
                                        ulong             buf_sz );

ulong
fd_repair_res_fec_set_root_ser( uchar const   fec_set_root[ static FD_SHRED_MERKLE_NODE_SZ ],
                                uchar const * proof,
                                ulong         proof_sz,
                                uint          nonce,
                                uchar *       buf,
                                ulong         buf_sz );

ulong
fd_repair_ping_de( uchar const *    buf,
                   ulong            buf_sz,
                   fd_pubkey_t *    from,
                   fd_hash_t *      token,
                   fd_ed25519_sig_t signature );

ulong
fd_repair_block_id_ping_de( uchar const *    buf,
                            ulong            buf_sz,
                            fd_pubkey_t *    from,
                            fd_hash_t *      token,
                            fd_ed25519_sig_t signature );

ulong
fd_repair_res_parent_fec_set_count_de( uchar const * buf,
                                       ulong         buf_sz,
                                       uint *        fec_set_cnt,
                                       ulong *       parent_slot,
                                       fd_hash_t *   parent_block_id,
                                       uchar         proof[ static FD_REPAIR_PROOF_MAX ],
                                       ulong *       proof_sz,
                                       uint *        nonce );

ulong
fd_repair_res_fec_set_root_de( uchar const * buf,
                               ulong         buf_sz,
                               uchar         fec_set_root[ static FD_SHRED_MERKLE_NODE_SZ ],
                               uchar         proof[ static FD_REPAIR_PROOF_MAX ],
                               ulong *       proof_sz,
                               uint *        nonce );

/* fd_repair_res_parent_fec_set_count_verify and
   fd_repair_res_fec_set_root_verify check a decoded response's proof
   against block_id, the block the request named.  fec_set_idx and
   fec_set_cnt are the requested FEC set index and the block's FEC set
   count.  Return 0 if it verifies, -1 otherwise. */

int
fd_repair_res_parent_fec_set_count_verify( uint              fec_set_cnt,
                                           ulong             parent_slot,
                                           fd_hash_t const * parent_block_id,
                                           uchar const *     proof,
                                           ulong             proof_sz,
                                           fd_hash_t const * block_id );

int
fd_repair_res_fec_set_root_verify( uchar const       fec_set_root[ static FD_SHRED_MERKLE_NODE_SZ ],
                                   uchar const *     proof,
                                   ulong             proof_sz,
                                   fd_hash_t const * block_id,
                                   uint              fec_set_idx,
                                   uint              fec_set_cnt );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_repair_fd_repair_serde_h */

#ifndef HEADER_fd_src_choreo_votor_ag_vote_serde_h
#define HEADER_fd_src_choreo_votor_ag_vote_serde_h

#include "ag_vote.h"

#define AG_VOTE_DE_SUCCESS           ( 0)
#define AG_VOTE_DE_ERR_TRUNCATED     (-1)
#define AG_VOTE_DE_ERR_MALFORMED     (-2)
#define AG_VOTE_DE_ERR_UNSUPPORTED   (-3)
#define AG_VOTE_DE_ERR_SHRED_VERSION (-4)

struct __attribute__((packed)) ag_vote_signature_serde {
  ag_bls_sig_t signature;     /* WireVoteSignature::signature          (BLSSignature) */
  ushort       shred_version; /* WireConsensusMessageV1::shred_version (u16)          */
};
typedef struct ag_vote_signature_serde ag_vote_signature_serde_t;

struct __attribute__((packed)) ag_vote_serde {
  uchar version;                             /* VersionedWireConsensusMessage::V1 (u8 tag)            */
  uchar kind;                                /* WireConsensusMessageKind          (u8 tag)            */
  ulong slot;                                /* WireSlotVoteMessage::slot         (Slot)              */
  union __attribute__((packed)) {
    struct __attribute__((packed)) {
      ag_vote_signature_serde_t signature;   /* WireSlotVoteMessage::signature    (WireVoteSignature) */
    } slot_vote;
    struct __attribute__((packed)) {
      ag_block_hash_t           block_id;    /* Block::block_id                   (Hash)              */
      ag_vote_signature_serde_t signature;   /* WireBlockVoteMessage::signature   (WireVoteSignature) */
    } block_vote;
  };
};
typedef struct ag_vote_serde ag_vote_serde_t;

FD_PROTOTYPES_BEGIN

int
ag_vote_ser( ag_vote_t const * self,
             ushort            shred_version,
             uchar *           buf,
             ulong             buf_max,
             ulong *           buf_sz );

int
ag_vote_de( ag_vote_t *   out,
            ushort        shred_version,
            uchar const * buf,
            ulong         buf_max,
            ulong *       buf_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_votor_ag_vote_serde_h */

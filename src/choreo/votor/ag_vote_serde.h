#ifndef HEADER_fd_src_choreo_votor_ag_vote_serde_h
#define HEADER_fd_src_choreo_votor_ag_vote_serde_h

#include "ag_vote.h"

/* Grouped from the wincode ReadError variants (agave error.rs) that are
   reachable for these fixed layout binary messages; the library's finer
   split is generic-serializer bookkeeping we cannot act on differently.
   Variants that cannot arise here are omitted: InvalidUtf8Encoding,
   InvalidUtf8Code, InvalidCharLead (no strings or chars),
   InvalidBoolEncoding (no bools), PointerSizedReadError,
   UnalignedPointerRead (no zero copy reads), TagEncodingOverflow (write side). */

#define AG_VOTE_DE_SUCCESS           (  0)
#define AG_VOTE_DE_ERR_SZ            ( -1) /* Io(ReadSizeLimit), TrailingBytes, PreallocationSizeLimit, LengthEncodingOverflow */
#define AG_VOTE_DE_ERR_INVAL         ( -2) /* InvalidTagEncoding, InvalidValue                                                 */
#define AG_VOTE_DE_ERR_SHRED_VERSION ( -3) /* Custom("shred version mismatch")                                                 */

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

/* buf must hold at least AG_VOTE_SER_MAX bytes; returns the number of
   bytes written. */

ulong
ag_vote_ser( ag_vote_t const * self,
             ushort            shred_version,
             uchar             buf[ static AG_VOTE_SER_MAX ] );

int
ag_vote_de( ag_vote_t *   self,
            ushort        shred_version,
            uchar const * buf,
            ulong         buf_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_votor_ag_vote_serde_h */

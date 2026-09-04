#ifndef HEADER_fd_src_choreo_votor_ag_vote_serde_h
#define HEADER_fd_src_choreo_votor_ag_vote_serde_h

#include "ag_vote.h"

#define AG_VOTE_DE_SUCCESS           ( 0)
#define AG_VOTE_DE_ERR_SZ            (-1) /* Io(ReadSizeLimit), TrailingBytes, PreallocationSizeLimit, LengthEncodingOverflow */
#define AG_VOTE_DE_ERR_INVAL         (-2) /* InvalidTagEncoding, InvalidValue                                                 */
#define AG_VOTE_DE_ERR_SHRED_VERSION (-3) /* Custom("shred version mismatch")                                                 */

/* WireConsensusMessageKind: https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/votor-messages/src/wire.rs#L164-L176 */

#define AG_VOTE_SERDE_TAG_NOTAR          (1)  /* WireConsensusMessageKind::NotarVote          #[wincode(tag = 1)] */
#define AG_VOTE_SERDE_TAG_FINAL          (2)  /* WireConsensusMessageKind::FinalizeVote       #[wincode(tag = 2)] */
#define AG_VOTE_SERDE_TAG_SKIP           (3)  /* WireConsensusMessageKind::SkipVote           #[wincode(tag = 3)] */
#define AG_VOTE_SERDE_TAG_NOTAR_FALLBACK (4)  /* WireConsensusMessageKind::NotarFallbackVote  #[wincode(tag = 4)] */
#define AG_VOTE_SERDE_TAG_SKIP_FALLBACK  (5)  /* WireConsensusMessageKind::SkipFallbackVote   #[wincode(tag = 5)] */

FD_STATIC_ASSERT( AG_VOTE_KIND_NOTAR         +1==AG_VOTE_SERDE_TAG_NOTAR,          ag_vote_serde );
FD_STATIC_ASSERT( AG_VOTE_KIND_FINAL         +1==AG_VOTE_SERDE_TAG_FINAL,          ag_vote_serde );
FD_STATIC_ASSERT( AG_VOTE_KIND_SKIP          +1==AG_VOTE_SERDE_TAG_SKIP,           ag_vote_serde );
FD_STATIC_ASSERT( AG_VOTE_KIND_NOTAR_FALLBACK+1==AG_VOTE_SERDE_TAG_NOTAR_FALLBACK, ag_vote_serde );
FD_STATIC_ASSERT( AG_VOTE_KIND_SKIP_FALLBACK +1==AG_VOTE_SERDE_TAG_SKIP_FALLBACK,  ag_vote_serde );

struct ag_vote_serde {
  uchar         version;       /* VersionedWireConsensusMessage::V1     (u8 tag)       */
  uchar         tag;           /* WireConsensusMessageKind              (u8 tag)       */
  ulong         slot;          /* WireSlotVoteMessage::slot             (Slot)         */
  uchar const * block_id;      /* Block::block_id                       (Hash)         */
  uchar const * signature;     /* WireVoteSignature::signature          (BLSSignature) */
  ushort        shred_version; /* WireConsensusMessageV1::shred_version (u16)          */
};
typedef struct ag_vote_serde ag_vote_serde_t;

#define AG_VOTE_SER_SZ( has_block_id ) ( sizeof(uchar)                                      /* version       */ + \
                                         sizeof(uchar)                                      /* kind          */ + \
                                         sizeof(ulong)                                      /* slot          */ + \
                                         ( (has_block_id) ? sizeof(ag_block_hash_t) : 0UL ) /* block_id      */ + \
                                         AG_BLS_SIG_SZ                                      /* signature     */ + \
                                         sizeof(ushort)                                     /* shred_version */ )

#define AG_VOTE_SIGNING_SER_MAX ( sizeof(uchar)           /* kind          */ + \
                                  sizeof(ulong)           /* slot          */ + \
                                  sizeof(ag_block_hash_t) /* block_id      */ + \
                                  sizeof(ushort)          /* shred_version */ )

FD_PROTOTYPES_BEGIN

ulong
ag_vote_ser( ag_vote_t const * self,
             ushort            shred_version,
             uchar             buf[ static AG_VOTE_SER_SZ( 1 ) ] );

int
ag_vote_de( ag_vote_t *   self,
            ushort        shred_version,
            uchar const * buf,
            ulong         buf_sz );

ulong
ag_vote_signing_ser( ag_vote_t const * self,
                     ushort            shred_version,
                     uchar             buf[ static AG_VOTE_SIGNING_SER_MAX ] );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_votor_ag_vote_serde_h */

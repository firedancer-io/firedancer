#ifndef HEADER_fd_src_flamenco_alpenglow_fd_block_marker_serde_h
#define HEADER_fd_src_flamenco_alpenglow_fd_block_marker_serde_h

#include "fd_block_marker.h"
#include "../../choreo/votor/ag_bls_serde.h"

#define FD_BLOCK_MARKER_DE_SUCCESS         ( 0)
#define FD_BLOCK_MARKER_DE_ERR_SZ          (-1) /* Io(ReadSizeLimit), PreallocationSizeLimit, Custom("LengthPrefixed: inner serialized size does not match length prefix") */
#define FD_BLOCK_MARKER_DE_ERR_INVAL       (-2) /* InvalidTagEncoding, InvalidValue                                                                                         */
#define FD_BLOCK_MARKER_DE_ERR_UNSUPPORTED (-3) /* no wincode error: BlockMarkerV1::GenesisCertificate decodes in agave but fd_block_marker_t cannot carry it              */

FD_STATIC_ASSERT( AG_BLS_DE_SUCCESS  ==FD_BLOCK_MARKER_DE_SUCCESS,   fd_block_marker_serde );
FD_STATIC_ASSERT( AG_BLS_DE_ERR_SZ   ==FD_BLOCK_MARKER_DE_ERR_SZ,    fd_block_marker_serde );
FD_STATIC_ASSERT( AG_BLS_DE_ERR_INVAL==FD_BLOCK_MARKER_DE_ERR_INVAL, fd_block_marker_serde );

/* BlockMarkerV1: https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/entry/src/block_component.rs#L380-L386 */

#define FD_BLOCK_MARKER_SERDE_TAG_FOOTER        (0) /* BlockMarkerV1::BlockFooter        (implicit tag 0) */
#define FD_BLOCK_MARKER_SERDE_TAG_HEADER        (1) /* BlockMarkerV1::BlockHeader        (implicit tag 1) */
#define FD_BLOCK_MARKER_SERDE_TAG_UPDATE_PARENT (2) /* BlockMarkerV1::UpdateParent       (implicit tag 2) */
#define FD_BLOCK_MARKER_SERDE_TAG_GENESIS_CERT  (3) /* BlockMarkerV1::GenesisCertificate (implicit tag 3) */

FD_STATIC_ASSERT( FD_BLOCK_MARKER_KIND_FOOTER       ==FD_BLOCK_MARKER_SERDE_TAG_FOOTER,        fd_block_marker_serde );
FD_STATIC_ASSERT( FD_BLOCK_MARKER_KIND_HEADER       ==FD_BLOCK_MARKER_SERDE_TAG_HEADER,        fd_block_marker_serde );
FD_STATIC_ASSERT( FD_BLOCK_MARKER_KIND_UPDATE_PARENT==FD_BLOCK_MARKER_SERDE_TAG_UPDATE_PARENT, fd_block_marker_serde );
FD_STATIC_ASSERT( FD_BLOCK_MARKER_KIND_GENESIS_CERT ==FD_BLOCK_MARKER_SERDE_TAG_GENESIS_CERT,  fd_block_marker_serde );

#define FD_BLOCK_MARKER_PREAMBLE_SZ ( sizeof(ulong)  /* entry_cnt */ + \
                                      sizeof(ushort) /* version   */ + \
                                      sizeof(uchar)  /* tag       */ + \
                                      sizeof(ushort) /* length    */ )

#define FD_BLOCK_HEADER_SER_SZ ( sizeof(uchar)     /* version         */ + \
                                 sizeof(ulong)     /* parent_slot     */ + \
                                 sizeof(fd_hash_t) /* parent_block_id */ )

#define FD_UPDATE_PARENT_SER_SZ ( sizeof(uchar)     /* version             */ + \
                                  sizeof(ulong)     /* new_parent_slot     */ + \
                                  sizeof(fd_hash_t) /* new_parent_block_id */ )

#define FD_BLOCK_VOTES_AGGREGATE_SER_HDR_SZ ( FD_BLS_SIG_COMPRESSED_SZ /* signature */ + \
                                              sizeof(ushort)           /* bitmap_sz */ )

#define FD_BLOCK_VOTES_AGGREGATE_SER_SZ( bit_cnt ) ( FD_BLOCK_VOTES_AGGREGATE_SER_HDR_SZ + \
                                                     AG_BLS_AGG_SER_SZ( bit_cnt ) /* bitmap */ )

#define FD_BLOCK_VOTES_AGGREGATE_SER_MAX ( FD_BLOCK_VOTES_AGGREGATE_SER_SZ( AG_VAT_MAX ) )

#define FD_BLOCK_FINAL_CERT_SER_HDR_SZ ( sizeof(ulong)     /* slot     */ + \
                                         sizeof(fd_hash_t) /* block_id */ )

#define FD_BLOCK_FINAL_CERT_SER_MAX ( FD_BLOCK_FINAL_CERT_SER_HDR_SZ   /* slot, block_id      */ + \
                                      FD_BLOCK_VOTES_AGGREGATE_SER_MAX /* final_aggregate     */ + \
                                      sizeof(uchar)                    /* has_notar_aggregate */ + \
                                      FD_BLOCK_VOTES_AGGREGATE_SER_MAX /* notar_aggregate     */ )

#define FD_BLOCK_REWARD_CERT_SER_CU16_MAX (3UL) /* a ShortU16 is at most three bytes */

#define FD_BLOCK_SKIP_REWARD_CERT_SER_HDR_SZ ( sizeof(ulong)            /* slot      */ + \
                                               FD_BLS_SIG_COMPRESSED_SZ /* signature */ )

#define FD_BLOCK_SKIP_REWARD_CERT_SER_MAX ( FD_BLOCK_SKIP_REWARD_CERT_SER_HDR_SZ /* slot, signature */ + \
                                            FD_BLOCK_REWARD_CERT_SER_CU16_MAX    /* bitmap_sz       */ + \
                                            AG_BLS_AGG_SER_SZ( AG_VAT_MAX )      /* bitmap          */ )

#define FD_BLOCK_NOTAR_REWARD_CERT_SER_HDR_SZ ( sizeof(ulong)            /* slot      */ + \
                                                sizeof(fd_hash_t)        /* block_id  */ + \
                                                FD_BLS_SIG_COMPRESSED_SZ /* signature */ )

#define FD_BLOCK_NOTAR_REWARD_CERT_SER_MAX ( FD_BLOCK_NOTAR_REWARD_CERT_SER_HDR_SZ /* slot, block_id, signature */ + \
                                             FD_BLOCK_REWARD_CERT_SER_CU16_MAX     /* bitmap_sz                 */ + \
                                             AG_BLS_AGG_SER_SZ( AG_VAT_MAX )       /* bitmap                    */ )

#define FD_BLOCK_FOOTER_SER_HDR_SZ ( sizeof(uchar)     /* version                   */ + \
                                     sizeof(fd_hash_t) /* bank_hash                 */ + \
                                     sizeof(ulong)     /* block_producer_time_nanos */ + \
                                     sizeof(uchar)     /* user_agent_len            */ )

#define FD_BLOCK_FOOTER_SER_MAX ( FD_BLOCK_MARKER_PREAMBLE_SZ    /* preamble              */ + \
                                  FD_BLOCK_FOOTER_SER_HDR_SZ     /* fixed fields          */ + \
                                  FD_BLOCK_FOOTER_USER_AGENT_MAX /* user_agent            */ + \
                                  sizeof(uchar)                  /* has_block_final_cert  */ + \
                                  FD_BLOCK_FINAL_CERT_SER_MAX    /* block_final_cert      */ + \
                                  sizeof(uchar)                      /* has_skip_reward_cert  */ + \
                                  FD_BLOCK_SKIP_REWARD_CERT_SER_MAX  /* skip_reward_cert      */ + \
                                  sizeof(uchar)                      /* has_notar_reward_cert */ + \
                                  FD_BLOCK_NOTAR_REWARD_CERT_SER_MAX /* notar_reward_cert     */ )

#define FD_BLOCK_MARKER_SER_MAX ( FD_BLOCK_FOOTER_SER_MAX ) /* the footer is the widest marker */

FD_STATIC_ASSERT( FD_BLOCK_MARKER_PREAMBLE_SZ          ==  13UL, fd_block_marker_serde );
FD_STATIC_ASSERT( FD_BLOCK_HEADER_SER_SZ               ==  41UL, fd_block_marker_serde );
FD_STATIC_ASSERT( FD_UPDATE_PARENT_SER_SZ              ==  41UL, fd_block_marker_serde );
FD_STATIC_ASSERT( FD_BLOCK_VOTES_AGGREGATE_SER_HDR_SZ  ==  98UL, fd_block_marker_serde );
FD_STATIC_ASSERT( FD_BLOCK_VOTES_AGGREGATE_SER_MAX     == 351UL, fd_block_marker_serde );
FD_STATIC_ASSERT( FD_BLOCK_FINAL_CERT_SER_HDR_SZ       ==  40UL, fd_block_marker_serde );
FD_STATIC_ASSERT( FD_BLOCK_FINAL_CERT_SER_MAX          == 743UL, fd_block_marker_serde );
FD_STATIC_ASSERT( FD_BLOCK_SKIP_REWARD_CERT_SER_HDR_SZ  == 104UL, fd_block_marker_serde );
FD_STATIC_ASSERT( FD_BLOCK_SKIP_REWARD_CERT_SER_MAX     == 360UL, fd_block_marker_serde );
FD_STATIC_ASSERT( FD_BLOCK_NOTAR_REWARD_CERT_SER_HDR_SZ == 136UL, fd_block_marker_serde );
FD_STATIC_ASSERT( FD_BLOCK_NOTAR_REWARD_CERT_SER_MAX    == 392UL, fd_block_marker_serde );
FD_STATIC_ASSERT( FD_BLOCK_FOOTER_SER_HDR_SZ            ==  42UL, fd_block_marker_serde );
FD_STATIC_ASSERT( FD_BLOCK_FOOTER_SER_MAX               ==1808UL, fd_block_marker_serde );
FD_STATIC_ASSERT( FD_BLOCK_FOOTER_SER_MAX-FD_BLOCK_MARKER_PREAMBLE_SZ<=(ulong)USHORT_MAX, fd_block_marker_serde ); /* LengthPrefixed::len is a u16 */

FD_PROTOTYPES_BEGIN

ulong
fd_block_marker_ser( fd_block_marker_t const * self,
                     uchar                     buf[ static FD_BLOCK_MARKER_SER_MAX ] );

int
fd_block_marker_de( fd_block_marker_t * self,
                    uchar const *       buf,
                    ulong               buf_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_alpenglow_fd_block_marker_serde_h */

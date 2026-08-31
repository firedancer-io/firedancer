/* TODO move out of replay to somewhere more reasonable... */

#ifndef HEADER_fd_src_discof_replay_fd_block_marker_h
#define HEADER_fd_src_discof_replay_fd_block_marker_h
/* fd_block_marker serializes and deserializes block markers */

#include "../../flamenco/fd_flamenco_base.h"
#include "../../flamenco/rewards/fd_reward_cert.h"
#include "../../choreo/votor/ag_cert.h"

#define FD_BLOCK_MARKER_DE_SUCCESS         ( 0)
#define FD_BLOCK_MARKER_DE_ERR_TRUNCATED   (-1) /* input ended short of the encoding */
#define FD_BLOCK_MARKER_DE_ERR_MALFORMED   (-2) /* not a valid encoding */
#define FD_BLOCK_MARKER_DE_ERR_UNSUPPORTED (-3) /* valid, but a version/variant we don't handle */

#define FD_BLOCK_MARKER_SER_SUCCESS         ( 0)
#define FD_BLOCK_MARKER_SER_ERR_NOSPACE     (-1) /* output buffer too small */
#define FD_BLOCK_MARKER_SER_ERR_UNSUPPORTED (-2) /* a variant or field we don't emit */

/* Size of the fixed marker preamble: marker_flag (8) + version (2) +
   variant (1) + length (2). */
#define FD_BLOCK_MARKER_PREAMBLE_SZ (13UL)

/* https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/entry/src/block_component.rs#L381 */
enum fd_block_marker_variant {
   FOOTER = 0,
   HEADER = 1,
   UPDATE_PARENT = 2,
   GENESIS_CERTIFICATE = 3,
};
struct fd_block_header {
   ulong     parent_slot;
   fd_hash_t parent_block_id;
};
typedef struct fd_block_header fd_block_header_t;

/* https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/entry/src/block_component.rs#L436 */
struct fd_update_parent {
   ulong     new_parent_slot;
   fd_hash_t new_parent_block_id;
};
typedef struct fd_update_parent fd_update_parent_t;

#define FD_BLOCK_FOOTER_USER_AGENT_MAX (255UL)

/* FD_BLOCK_FOOTER_SER_MAX bounds a serialized footer marker: the marker
   preamble, the fixed footer fields, a full length user agent, and all
   three optional certificates.  Every certificate carries a compressed
   BLS signature and a signer bitmap over at most AG_VAT_MAX validators,
   which is what dominates the bound. */

#define FD_BLOCK_MARKER_BITMAP_MAX (3UL+(AG_VAT_MAX+7UL)/8UL)                                     /* version, bit_cnt, payload    */
#define FD_BLOCK_MARKER_AGG_MAX    (AG_BLS_SIG_COMPRESSED_SZ+2UL+FD_BLOCK_MARKER_BITMAP_MAX)      /* VotesAggregate               */
#define FD_BLOCK_MARKER_REWARD_MAX (8UL+32UL+AG_BLS_SIG_COMPRESSED_SZ+3UL+FD_BLOCK_MARKER_BITMAP_MAX) /* slot, block_id, sig, cu16 */

#define FD_BLOCK_FOOTER_SER_MAX    ( FD_BLOCK_MARKER_PREAMBLE_SZ        + /* marker preamble           */ \
                                     1UL+32UL+8UL+1UL                   + /* version, hash, time, ualen*/ \
                                     FD_BLOCK_FOOTER_USER_AGENT_MAX     +                                 \
                                     3UL                                + /* three option bytes        */ \
                                     8UL+32UL+1UL                       + /* block_final slot, id, opt */ \
                                     2UL*FD_BLOCK_MARKER_AGG_MAX        + /* final + notar aggregates  */ \
                                     2UL*FD_BLOCK_MARKER_REWARD_MAX )     /* skip + notar reward certs */

struct fd_block_footer {
   fd_hash_t bank_hash;
   ulong     block_producer_time_nanos;
   ulong     user_agent_len;
   uchar     user_agent[ FD_BLOCK_FOOTER_USER_AGENT_MAX ];

   /* Optional finalization certa, shape validated and agg
      signatures decompressed, but not verified. A fast finalization
      cert fills fast_final_cert; a slow one fills final_cert +
      notar_cert. */
   int                  has_fast_final_cert;
   int                  has_final_cert;
   ag_cert_fast_final_t fast_final_cert;
   ag_cert_final_t      final_cert;
   ag_cert_notar_t      notar_cert;

   /* Optional reward certs. Shapes are validated but signatures are
      not verified. */
   int              has_skip_reward_cert;
   fd_reward_cert_t skip_reward_cert;
   int              has_notar_reward_cert;
   fd_reward_cert_t notar_reward_cert;
};
typedef struct fd_block_footer fd_block_footer_t;

struct fd_block_marker {
   uchar variant; /* enum fd_block_marker_variant */
   union {
    fd_block_header_t  header;
    fd_block_footer_t  footer;
    fd_update_parent_t update_parent;
   };
};
typedef struct fd_block_marker fd_block_marker_t;

struct __attribute__((packed)) fd_block_marker_serde {
  ulong  entry_cnt; /* BlockComponent::BlockMarker                 (u64, always 0) */
  ushort version;   /* VersionedBlockMarker::V1                    (u16 tag)       */
  uchar  variant;   /* BlockMarkerV1                               (u8 tag)        */
  ushort length;    /* LengthPrefixed<VersionedBlockMarkerV1>::len (u16)           */
/*uchar  payload[];*/
};
typedef struct fd_block_marker_serde fd_block_marker_serde_t;

struct __attribute__((packed)) fd_block_header_serde {
  uchar version;               /* VersionedBlockHeader::V1       (u8 tag) */
  ulong parent_slot;           /* BlockHeaderV1::parent_slot     (Slot)   */
  uchar parent_block_id[ 32 ]; /* BlockHeaderV1::parent_block_id (Hash)   */
};
typedef struct fd_block_header_serde fd_block_header_serde_t;

struct __attribute__((packed)) fd_block_footer_serde {
  uchar version;                   /* VersionedBlockFooter::V1                 (u8 tag)                          */
  uchar bank_hash[ 32 ];           /* BlockFooterV1::bank_hash                 (Hash)                            */
  ulong block_producer_time_nanos; /* BlockFooterV1::block_producer_time_nanos (u64)                             */
  uchar user_agent_len;            /* BlockFooterV1::block_user_agent          (WincodeVec<u8, FixIntLen<u8>>)   */
/*uchar user_agent[];*/            /* BlockFooterV1::block_user_agent          (WincodeVec<u8, FixIntLen<u8>>)   */
  /* Each Option is a one byte tag immediately followed by its own
     payload when present, so a cert's length shifts the next tag. */
/*uchar has_block_final_cert;*/    /* BlockFooterV1::block_final_cert          (Option<BlockFinalizationCert>)   */
/*uchar block_final_cert[];*/      /* BlockFinalizationCert                                                     */
/*uchar has_skip_reward_cert;*/    /* BlockFooterV1::skip_reward_cert          (Option<SkipRewardCertificate>)   */
/*uchar skip_reward_cert[];*/      /* SkipRewardCertificate                                                     */
/*uchar has_notar_reward_cert;*/   /* BlockFooterV1::notar_reward_cert         (Option<NotarRewardCertificate>)  */
/*uchar notar_reward_cert[];*/     /* NotarRewardCertificate                                                    */
};
typedef struct fd_block_footer_serde fd_block_footer_serde_t;

/* The footer framing of a certificate is not the wire framing in
   ag_cert_serde.h: the aggregate signature is compressed and the bitmap
   carries a u16 length prefix rather than a u64.  The bitmap payload
   itself (ag_cert_bitmap_serde_t) is common to both. */

struct __attribute__((packed)) fd_block_votes_aggregate_serde {
  uchar  signature[ AG_BLS_SIG_COMPRESSED_SZ ]; /* VotesAggregate::signature (BLSSignatureCompressed)         */
  ushort bitmap_cnt;                            /* VotesAggregate::bitmap    (WincodeVec<u8, FixIntLen<u16>>) */
/*uchar  bitmap[];*/                            /* VotesAggregate::bitmap    (WincodeVec<u8, FixIntLen<u16>>) */
};
typedef struct fd_block_votes_aggregate_serde fd_block_votes_aggregate_serde_t;

struct __attribute__((packed)) fd_block_final_cert_serde {
  ulong           slot;                                    /* BlockFinalizationCert::slot            (Slot)                   */
  ag_block_hash_t block_id;                                /* BlockFinalizationCert::block_id        (Hash)                   */
/*fd_block_votes_aggregate_serde_t final_aggregate;    */   /* BlockFinalizationCert::final_aggregate (VotesAggregate)         */
/*uchar                            has_notar_aggregate;*/   /* BlockFinalizationCert::notar_aggregate (Option<VotesAggregate>) */
/*fd_block_votes_aggregate_serde_t notar_aggregate;    */   /* BlockFinalizationCert::notar_aggregate (Option<VotesAggregate>) */
};
typedef struct fd_block_final_cert_serde fd_block_final_cert_serde_t;

FD_PROTOTYPES_BEGIN

/* fd_block_final_cert_de deserializes the BlockFinalizationCert at buf,
   which a block footer carries inline.  Agg signatures are decompressed
   but not verified.  Returns 1 when the cert is a fast finalization, in
   which case only fast_final is written, 0 when it is a slow one, in
   which case only final and notar are written, and -1 on failure.  On
   success buf_sz (if non-NULL) receives the number of bytes consumed. */

int
fd_block_final_cert_de( ag_cert_fast_final_t * fast_final,
                        ag_cert_final_t *      final,
                        ag_cert_notar_t *      notar,
                        uchar const *          buf,
                        ulong                  buf_max,
                        ulong *                buf_sz );

/* The deserializers below decode a versioned block marker payload,
   with buf pointing at the payload byte (FD_BLOCK_MARKER_PREAMBLE_SZ
   into the marker). returns FD_BLOCK_MARKER_DE_SUCCESS and write
   the number of bytes consumed to buf_sz (if non-NULL) on success, and
   return FD_BLOCK_MARKER_DE_ERR_* on failure. */

int
fd_block_header_de( fd_block_header_t * header,
                    uchar const *       buf,
                    ulong               buf_max,
                    ulong *             buf_sz );

int
fd_block_footer_de( fd_block_footer_t * footer,
                    uchar const *       buf,
                    ulong               buf_max,
                    ulong *             buf_sz );

int
fd_update_parent_de( fd_update_parent_t * update_parent,
                     uchar const *        buf,
                     ulong                buf_max,
                     ulong *              buf_sz );

/* fd_block_marker_de deserializes a whole block marker, with buf
   pointing at the marker flag (the start of the entry batch). Trailing
   bytes past buf_max are not consumed.  buf_sz set to
   FD_BLOCK_MARKER_PREAMBLE_SZ + length on success, and returns
   FD_BLOCK_MARKER_DE_SUCCESS or FD_BLOCK_MARKER_DE_ERR_* on failure */
int
fd_block_marker_de( fd_block_marker_t * marker,
                    uchar const *       buf,
                    ulong               buf_max,
                    ulong *             buf_sz );

/* fd_block_marker_ser serializes a whole block marker, with buf pointing
   at the marker flag (the start of the entry batch).  Only HEADER and
   FOOTER are emitted, and a footer must have all certificates absent.
   buf_sz is set to FD_BLOCK_MARKER_PREAMBLE_SZ + length on success.
   Returns FD_BLOCK_MARKER_SER_SUCCESS or FD_BLOCK_MARKER_SER_ERR_* on
   failure; a failed call may have written a prefix. */

int
fd_block_marker_ser( fd_block_marker_t const * marker,
                     uchar *                   buf,
                     ulong                     buf_max,
                     ulong *                   buf_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_replay_fd_block_marker_h */

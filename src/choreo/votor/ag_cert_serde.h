#ifndef HEADER_fd_src_choreo_votor_ag_cert_serde_h
#define HEADER_fd_src_choreo_votor_ag_cert_serde_h

#include "ag_cert.h"

#define AG_CERT_DE_SUCCESS           (  0)
#define AG_CERT_DE_ERR_SZ            ( -1) /* Io(ReadSizeLimit), TrailingBytes, PreallocationSizeLimit, LengthEncodingOverflow */
#define AG_CERT_DE_ERR_INVAL         ( -2) /* InvalidTagEncoding, InvalidValue                                                 */
#define AG_CERT_DE_ERR_SHRED_VERSION ( -3) /* Custom("shred version mismatch")                                                 */

struct __attribute__((packed)) ag_cert_signature_serde {
  ag_bls_sig_t signature;  /* WireCertSignature::signature (BLSSignature) */
  ulong        bitmap_cnt; /* WireCertSignature::bitmap    (Vec<u8>)      */
/*uchar        bitmap[];*/ /* WireCertSignature::bitmap    (Vec<u8>)      */
};
typedef struct ag_cert_signature_serde ag_cert_signature_serde_t;

struct __attribute__((packed)) ag_cert_serde {
  uchar version;                           /* VersionedWireConsensusMessage::V1     (u8 tag)            */
  uchar kind;                              /* WireConsensusMessageKind              (u8 tag)            */
  ulong slot;                              /* WireSlotCertMessage::slot             (Slot)              */
  union __attribute__((packed)) {
    struct __attribute__((packed)) {
      ag_cert_signature_serde_t signature; /* WireSlotCertMessage::signature        (WireCertSignature) */
    } slot_cert;
    struct __attribute__((packed)) {
      ag_block_hash_t           block_id;  /* Block::block_id                       (Hash)              */
      ag_cert_signature_serde_t signature; /* WireBlockCertMessage::signature       (WireCertSignature) */
    } block_cert;
  };
/*ushort shred_version;*/                  /* WireConsensusMessageV1::shred_version (u16)               */
};
typedef struct ag_cert_serde ag_cert_serde_t;

struct __attribute__((packed)) ag_cert_bitmap_serde {
  uchar  version;     /* solana_signer_store::Version    (u8 tag) */
  ushort bit_cnt;     /* solana_signer_store::num_bits   (u16)    */
/*uchar  payload[];*/ /* solana_signer_store::data_bytes          */
};
typedef struct ag_cert_bitmap_serde ag_cert_bitmap_serde_t;

struct __attribute__((packed)) ag_cert_votes_aggregate_serde {
  uchar  signature[ AG_BLS_SIG_COMPRESSED_SZ ]; /* VotesAggregate::signature (BLSSignatureCompressed)         */
  ushort bitmap_cnt;                            /* VotesAggregate::bitmap    (WincodeVec<u8, FixIntLen<u16>>) */
/*uchar  bitmap[];*/                            /* VotesAggregate::bitmap    (WincodeVec<u8, FixIntLen<u16>>) */
};
typedef struct ag_cert_votes_aggregate_serde ag_cert_votes_aggregate_serde_t;

struct __attribute__((packed)) ag_cert_block_final_serde {
  ulong           slot;                                  /* BlockFinalizationCert::slot            (Slot)                   */
  ag_block_hash_t block_id;                              /* BlockFinalizationCert::block_id        (Hash)                   */
/*ag_cert_votes_aggregate_serde_t final_aggregate;    */ /* BlockFinalizationCert::final_aggregate (VotesAggregate)         */
/*uchar                           has_notar_aggregate;*/ /* BlockFinalizationCert::notar_aggregate (Option<VotesAggregate>) */
/*ag_cert_votes_aggregate_serde_t notar_aggregate;    */ /* BlockFinalizationCert::notar_aggregate (Option<VotesAggregate>) */
};
typedef struct ag_cert_block_final_serde ag_cert_block_final_serde_t;

#define AG_CERT_SER_MAX (sizeof(ag_cert_serde_t) + sizeof(ag_cert_bitmap_serde_t) + (AG_BLS_SIGNERS_MAX+4UL)/5UL + 2UL) /* max serialized sz of ag_cert_serde */

FD_PROTOTYPES_BEGIN

/* buf must hold at least AG_CERT_SER_MAX bytes; returns the number of
   bytes written. */

ulong
ag_cert_ser( ag_cert_t const * self,
             ushort            shred_version,
             uchar             buf[ static AG_CERT_SER_MAX ] );

int
ag_cert_de( ag_cert_t *   cert,
            ushort        shred_version,
            uchar const * buf,
            ulong         buf_sz );

int
ag_cert_block_final_de( ag_cert_fast_final_t * fast_final,
                        ag_cert_final_t *      final,
                        ag_cert_notar_t *      notar,
                        uchar const *          buf,
                        ulong                  buf_max,
                        ulong *                buf_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_votor_ag_cert_serde_h */

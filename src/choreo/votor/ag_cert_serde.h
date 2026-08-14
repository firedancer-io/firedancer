#ifndef HEADER_fd_src_choreo_votor_ag_cert_serde_h
#define HEADER_fd_src_choreo_votor_ag_cert_serde_h

#include "ag_cert.h"

#define AG_CERT_DE_SUCCESS           ( 0)
#define AG_CERT_DE_ERR_TRUNCATED     (-1)
#define AG_CERT_DE_ERR_MALFORMED     (-2)
#define AG_CERT_DE_ERR_UNSUPPORTED   (-3)
#define AG_CERT_DE_ERR_SHRED_VERSION (-4)

struct __attribute__((packed)) ag_cert_signature_serde {
  ag_aggsig_sig_t signature;  /* WireCertSignature::signature (BLSSignature) */
  ulong           bitmap_cnt; /* WireCertSignature::bitmap    (Vec<u8>)      */
/*uchar           bitmap[];*/ /* WireCertSignature::bitmap    (Vec<u8>)      */
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
      fd_hash_t                 block_id;  /* Block::block_id                       (Hash)              */
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
  uchar  signature[ AG_AGGSIG_SIG_COMPRESSED_SZ ]; /* VotesAggregate::signature (BLSSignatureCompressed)         */
  ushort bitmap_cnt;                               /* VotesAggregate::bitmap    (WincodeVec<u8, FixIntLen<u16>>) */
/*uchar  bitmap[];*/                               /* VotesAggregate::bitmap    (WincodeVec<u8, FixIntLen<u16>>) */
};
typedef struct ag_cert_votes_aggregate_serde ag_cert_votes_aggregate_serde_t;

struct __attribute__((packed)) ag_cert_block_final_serde {
  ulong     slot;                                        /* BlockFinalizationCert::slot            (Slot)                   */
  fd_hash_t block_id;                                    /* BlockFinalizationCert::block_id        (Hash)                   */
/*ag_cert_votes_aggregate_serde_t final_aggregate;    */ /* BlockFinalizationCert::final_aggregate (VotesAggregate)         */
/*uchar                           has_notar_aggregate;*/ /* BlockFinalizationCert::notar_aggregate (Option<VotesAggregate>) */
/*ag_cert_votes_aggregate_serde_t notar_aggregate;    */ /* BlockFinalizationCert::notar_aggregate (Option<VotesAggregate>) */
};
typedef struct ag_cert_block_final_serde ag_cert_block_final_serde_t;

FD_PROTOTYPES_BEGIN

int
ag_cert_ser( ag_cert_t const * self,
             ushort            shred_version,
             uchar *           buf,
             ulong             buf_max,
             ulong *           buf_sz );

int
ag_cert_de( ag_cert_t *   cert,
            ushort        shred_version,
            uchar const * buf,
            ulong         buf_max,
            ulong *       buf_sz );

int
ag_cert_block_final_de( ag_fast_final_cert_t * fast_final,
                        ag_final_cert_t *      final,
                        ag_notar_cert_t *      notar,
                        uchar const *          buf,
                        ulong                  buf_max,
                        ulong *                buf_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_votor_ag_cert_serde_h */

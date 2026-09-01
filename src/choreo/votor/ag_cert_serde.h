#ifndef HEADER_fd_src_choreo_votor_ag_cert_serde_h
#define HEADER_fd_src_choreo_votor_ag_cert_serde_h

#include "ag_cert.h"
#include "ag_bls_serde.h"

#define AG_CERT_DE_SUCCESS           (  0)
#define AG_CERT_DE_ERR_SZ            ( -1) /* Io(ReadSizeLimit), TrailingBytes, PreallocationSizeLimit, LengthEncodingOverflow */
#define AG_CERT_DE_ERR_INVAL         ( -2) /* InvalidTagEncoding, InvalidValue                                                 */
#define AG_CERT_DE_ERR_SHRED_VERSION ( -3) /* Custom("shred version mismatch")                                                 */

FD_STATIC_ASSERT( AG_BLS_DE_SUCCESS  ==AG_CERT_DE_SUCCESS,   ag_cert_serde );
FD_STATIC_ASSERT( AG_BLS_DE_ERR_SZ   ==AG_CERT_DE_ERR_SZ,    ag_cert_serde );
FD_STATIC_ASSERT( AG_BLS_DE_ERR_INVAL==AG_CERT_DE_ERR_INVAL, ag_cert_serde );

/* WireConsensusMessageKind: https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/votor-messages/src/wire.rs#L178-L189 */

#define AG_CERT_SERDE_TAG_FINAL          ( 7)  /* WireConsensusMessageKind::FinalizeCert       #[wincode(tag = 7)]  */
#define AG_CERT_SERDE_TAG_FAST_FINAL     ( 8)  /* WireConsensusMessageKind::FastFinalizeCert   #[wincode(tag = 8)]  */
#define AG_CERT_SERDE_TAG_NOTAR          ( 9)  /* WireConsensusMessageKind::NotarCert          #[wincode(tag = 9)]  */
#define AG_CERT_SERDE_TAG_NOTAR_FALLBACK (10)  /* WireConsensusMessageKind::NotarFallbackCert  #[wincode(tag = 10)] */
#define AG_CERT_SERDE_TAG_SKIP           (11)  /* WireConsensusMessageKind::SkipCert           #[wincode(tag = 11)] */
#define AG_CERT_SERDE_TAG_GENESIS        (12)  /* WireConsensusMessageKind::GenesisCert        #[wincode(tag = 12)] */

FD_STATIC_ASSERT( AG_CERT_KIND_FINAL         +7==AG_CERT_SERDE_TAG_FINAL,          ag_cert_serde );
FD_STATIC_ASSERT( AG_CERT_KIND_FAST_FINAL    +7==AG_CERT_SERDE_TAG_FAST_FINAL,     ag_cert_serde );
FD_STATIC_ASSERT( AG_CERT_KIND_NOTAR         +7==AG_CERT_SERDE_TAG_NOTAR,          ag_cert_serde );
FD_STATIC_ASSERT( AG_CERT_KIND_NOTAR_FALLBACK+7==AG_CERT_SERDE_TAG_NOTAR_FALLBACK, ag_cert_serde );
FD_STATIC_ASSERT( AG_CERT_KIND_SKIP          +7==AG_CERT_SERDE_TAG_SKIP,           ag_cert_serde );
FD_STATIC_ASSERT( AG_CERT_KIND_GENESIS       +7==AG_CERT_SERDE_TAG_GENESIS,        ag_cert_serde );

struct ag_cert_serde {
  uchar         version;       /* VersionedWireConsensusMessage::V1     (u8 tag)       */
  uchar         tag;           /* WireConsensusMessageKind              (u8 tag)       */
  ulong         slot;          /* WireSlotCertMessage::slot             (Slot)         */
  uchar const * block_id;      /* Block::block_id                       (Hash)         */
  uchar const * signature;     /* WireCertSignature::signature          (BLSSignature) */
  ulong         bitmap_sz;     /* WireCertSignature::bitmap len         (u64)          */
  uchar const * bitmap;        /* WireCertSignature::bitmap             (Vec<u8>)      */
  ushort        shred_version; /* WireConsensusMessageV1::shred_version (u16)          */
};
typedef struct ag_cert_serde ag_cert_serde_t;

#define AG_CERT_SER_HDR_SZ( has_block_id ) ( sizeof(uchar)                              /* version   */ + \
                                             sizeof(uchar)                              /* kind      */ + \
                                             sizeof(ulong)                              /* slot      */ + \
                                             ( (has_block_id) ? sizeof(ag_block_hash_t) /* block_id  */   \
                                                              : 0UL )                                   + \
                                             AG_BLS_SIG_SZ                              /* signature */ + \
                                             sizeof(ulong)                              /* bitmap_sz */ )


#define AG_CERT_SER_MIN ( AG_CERT_SER_HDR_SZ( 0 ) + \
                          AG_BLS_AGG_HDR_SZ       + \
                          sizeof(ushort) /* shred_version */ )

#define AG_CERT_SER_MAX ( AG_CERT_SER_HDR_SZ( 1 ) + \
                          AG_BLS_AGG_PAIR_SER_MAX + \
                          sizeof(ushort) /* shred_version */ )

FD_STATIC_ASSERT( AG_CERT_SER_MAX==657UL, ag_cert_serde );

FD_PROTOTYPES_BEGIN

ulong
ag_cert_ser( ag_cert_t const * self,
             ushort            shred_version,
             uchar             buf[ static AG_CERT_SER_MAX ] );

int
ag_cert_de( ag_cert_t *   cert,
            ushort        shred_version,
            uchar const * buf,
            ulong         buf_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_votor_ag_cert_serde_h */

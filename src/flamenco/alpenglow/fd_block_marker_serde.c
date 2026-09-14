#include "fd_block_marker_serde.h"

#include "../../ballet/txn/fd_compact_u16.h"

#define FAIL( cond, err ) do { if( FD_UNLIKELY( cond ) ) return FD_BLOCK_MARKER_DE_ERR_##err; } while( 0 )

/* BlockComponent:       https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/entry/src/block_component.rs#L486-L488
   VersionedBlockMarker: https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/entry/src/block_component.rs#L435-L438
   LengthPrefixed:       https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/entry/src/block_component.rs#L172-L175 */

struct marker_serde {
  ulong         entry_cnt; /* BlockComponent::BlockMarker            (u64, always 0) */
  ushort        version;   /* VersionedBlockMarker::V1               (u16 tag)       */
  uchar         tag;       /* BlockMarkerV1                          (u8 tag)        */
  ushort        length;    /* LengthPrefixed<VersionedBlock*>::len   (u16)           */
  uchar const * payload;   /* LengthPrefixed<VersionedBlock*>::inner (length bytes)  */
};
typedef struct marker_serde marker_serde_t;

/* VersionedBlockHeader: https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/entry/src/block_component.rs#L364-L367
   BlockHeaderV1:        https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/entry/src/block_component.rs#L251-L254 */

struct header_serde {
  uchar         version;         /* VersionedBlockHeader::V1       (u8 tag, #[wincode(tag = 1)]) */
  ulong         parent_slot;     /* BlockHeaderV1::parent_slot     (Slot)                        */
  uchar const * parent_block_id; /* BlockHeaderV1::parent_block_id (Hash)                        */
};
typedef struct header_serde header_serde_t;

/* VersionedUpdateParent: https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/entry/src/block_component.rs#L371-L374
   UpdateParentV1:        https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/entry/src/block_component.rs#L257-L260 */

struct update_parent_serde {
  uchar         version;             /* VersionedUpdateParent::V1           (u8 tag, #[wincode(tag = 1)]) */
  ulong         new_parent_slot;     /* UpdateParentV1::new_parent_slot     (Slot)                        */
  uchar const * new_parent_block_id; /* UpdateParentV1::new_parent_block_id (Hash)                        */
};
typedef struct update_parent_serde update_parent_serde_t;

/* VotesAggregate: https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/entry/src/block_component.rs#L324-L328
   Not the wire framing in ag_cert_serde.h: the signature is compressed
   and the bitmap sits under a u16 byte count rather than a u64.  The
   bitmap itself is the solana_signer_store encoding ag_bls_serde
   handles. */

struct votes_aggregate_serde {
  uchar const * signature; /* VotesAggregate::signature  (BLSSignatureCompressed)         */
  ushort        bitmap_sz; /* VotesAggregate::bitmap len (FixIntLen<u16>)                 */
  uchar const * bitmap;    /* VotesAggregate::bitmap     (WincodeVec<u8, FixIntLen<u16>>) */
};
typedef struct votes_aggregate_serde votes_aggregate_serde_t;

/* BlockFinalizationCert: https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/entry/src/block_component.rs#L299-L304 */

struct final_cert_serde {
  ulong         slot;                /* BlockFinalizationCert::slot            (Slot)                             */
  uchar const * block_id;            /* BlockFinalizationCert::block_id        (Hash)                             */
  uchar const * final_aggregate;     /* BlockFinalizationCert::final_aggregate (VotesAggregate)                   */
  uchar         has_notar_aggregate; /* BlockFinalizationCert::notar_aggregate (Option<VotesAggregate> tag)       */
  uchar const * notar_aggregate;     /* BlockFinalizationCert::notar_aggregate (VotesAggregate, NULL when absent) */
};
typedef struct final_cert_serde final_cert_serde_t;

/* SkipRewardCertificate: https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/votor-messages/src/reward_certificate.rs#L34-L42
   The bitmap byte count is a ShortU16, not the aggregate's u16. */

struct skip_reward_cert_serde {
  ulong         slot;      /* SkipRewardCertificate::slot       (Slot)                     */
  uchar const * signature; /* SkipRewardCertificate::signature  (BLSSignatureCompressed)   */
  ushort        bitmap_sz; /* SkipRewardCertificate::bitmap len (ShortU16)                 */
  uchar const * bitmap;    /* SkipRewardCertificate::bitmap     (WincodeVec<u8, ShortU16>) */
};
typedef struct skip_reward_cert_serde skip_reward_cert_serde_t;

/* NotarRewardCertificate: https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/votor-messages/src/reward_certificate.rs#L75-L85 */

struct notar_reward_cert_serde {
  ulong         slot;      /* NotarRewardCertificate::slot       (Slot)                     */
  uchar const * block_id;  /* NotarRewardCertificate::block_id   (Hash)                     */
  uchar const * signature; /* NotarRewardCertificate::signature  (BLSSignatureCompressed)   */
  ushort        bitmap_sz; /* NotarRewardCertificate::bitmap len (ShortU16)                 */
  uchar const * bitmap;    /* NotarRewardCertificate::bitmap     (WincodeVec<u8, ShortU16>) */
};
typedef struct notar_reward_cert_serde notar_reward_cert_serde_t;

/* VersionedBlockFooter: https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/entry/src/block_component.rs#L357-L360
   BlockFooterV1:        https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/entry/src/block_component.rs#L240-L248
   Each Option is a one byte tag immediately followed by its own body
   when present, so a cert's length shifts the next tag. */

struct footer_serde {
  uchar         version;                   /* VersionedBlockFooter::V1                 (u8 tag, #[wincode(tag = 1)])        */
  uchar const * bank_hash;                 /* BlockFooterV1::bank_hash                 (Hash)                               */
  ulong         block_producer_time_nanos; /* BlockFooterV1::block_producer_time_nanos (u64)                                */
  uchar         user_agent_len;            /* BlockFooterV1::block_user_agent len      (FixIntLen<u8>)                      */
  uchar const * user_agent;                /* BlockFooterV1::block_user_agent          (WincodeVec<u8, FixIntLen<u8>>)      */
  uchar         has_block_final_cert;      /* BlockFooterV1::block_final_cert          (Option<BlockFinalizationCert> tag)  */
  uchar const * block_final_cert;          /* BlockFooterV1::block_final_cert          (BlockFinalizationCert)              */
  uchar         has_skip_reward_cert;      /* BlockFooterV1::skip_reward_cert          (Option<SkipRewardCertificate> tag)  */
  uchar const * skip_reward_cert;          /* BlockFooterV1::skip_reward_cert          (SkipRewardCertificate)              */
  uchar         has_notar_reward_cert;     /* BlockFooterV1::notar_reward_cert         (Option<NotarRewardCertificate> tag) */
  uchar const * notar_reward_cert;         /* BlockFooterV1::notar_reward_cert         (NotarRewardCertificate)             */
};
typedef struct footer_serde footer_serde_t;

static ulong
header_ser( fd_block_header_t const * header,
            uchar *                   buf ) {
  header_serde_t hdr;

  hdr.version         = (uchar)1;
  hdr.parent_slot     = header->parent_slot;
  hdr.parent_block_id = header->parent_block_id.uc;

  ulong off = 0UL;
  buf[ off ] = hdr.version;                                  off += sizeof(uchar);
  FD_STORE( ulong, buf+off, hdr.parent_slot );               off += sizeof(ulong);
  memcpy( buf+off, hdr.parent_block_id, sizeof(fd_hash_t) ); off += sizeof(fd_hash_t);

  return off;
}

/* bitmap_ser writes the base2 bitmap naming the ranks in signer_set,
   exactly nbits wide.  ag_bls_agg_ser packs the ranks but trims the
   width to one past the highest, as agave does when it builds a cert;
   a footer cert re-emits the width it carries, so one that came off the
   wire goes back out byte for byte.  Returns the bytes written, or 0UL
   if nbits passes AG_VAT_MAX (which sizes FD_BLOCK_FOOTER_SER_MAX) or a
   rank sits at or past nbits. */

static ulong
bitmap_ser( ulong                nbits,
            fd_bls_set_t const * signer_set,
            uchar *              buf ) {
  fd_bls_agg_t agg[1]; /* only the set is read */
  fd_bls_set_copy( agg->set, signer_set );
  ulong bits = fd_ulong_min( FD_BLS_SET_MAX, fd_bls_set_last( signer_set )+1UL ); /* one past the highest rank, 0 when empty */
  if( FD_UNLIKELY( nbits>AG_VAT_MAX || bits>nbits ) ) return 0UL;

  /* ag_bls_agg_ser packs bits<=nbits of them (none for an empty set);
     the rest of the nbits-wide payload is zero filled */
  uchar packed[ AG_BLS_AGG_SER_MAX ];
  ulong packed_sz = ag_bls_agg_ser( agg, packed )-AG_BLS_AGG_HDR_SZ;

  ag_bls_agg_serde_t bm;

  bm.version    = (uchar)0; /* base2 */
  bm.bit_cnt    = (ushort)nbits;
  bm.payload    = packed+AG_BLS_AGG_HDR_SZ;
  bm.payload_sz = AG_BLS_AGG_SER_SZ( nbits )-AG_BLS_AGG_HDR_SZ;

  ulong off = 0UL;
  buf[ off ] = bm.version;                                    off += sizeof(uchar);
  FD_STORE( ushort, buf+off, bm.bit_cnt );                    off += sizeof(ushort);
  memcpy( buf+off, bm.payload, packed_sz );
  fd_memset( buf+off+packed_sz, 0, bm.payload_sz-packed_sz ); off += bm.payload_sz; /* ranks past the packed width are unset */

  return off;
}

static ulong
votes_aggregate_ser( fd_block_footer_cert_t const * cert,
                     uchar *                        buf ) {
  votes_aggregate_serde_t aggregate;

  aggregate.signature = cert->sig; /* already compressed */
  aggregate.bitmap_sz = (ushort)AG_BLS_AGG_SER_SZ( cert->nbits );
  aggregate.bitmap    = NULL; /* written straight into buf by bitmap_ser below */

  ulong off = 0UL;
  ulong sz;
  memcpy( buf+off, aggregate.signature, FD_BLS_SIG_COMPRESSED_SZ );                     off += FD_BLS_SIG_COMPRESSED_SZ;
  FD_STORE( ushort, buf+off, aggregate.bitmap_sz );                                     off += sizeof(ushort);
  if( FD_UNLIKELY( !(sz=bitmap_ser( cert->nbits, cert->signer_set, buf+off )) ) ) return 0UL;
                                                                                        off += sz;
  return off;
}

static ulong
final_cert_ser( fd_block_footer_t const * footer,
                uchar *                   buf ) {
  int is_fast = footer->has_fast_final_cert;
  /* one block_id goes on the wire, so the two certs of a slow
     finalization must name one slot */
  if( FD_UNLIKELY( !is_fast && footer->final_cert.slot!=footer->notar_cert.slot ) ) return 0UL;

  final_cert_serde_t cert;

  cert.slot                = is_fast ? footer->fast_final_cert.slot        : footer->final_cert.slot;
  cert.block_id            = is_fast ? footer->fast_final_cert.block_id.uc : footer->notar_cert.block_id.uc;
  cert.final_aggregate     = NULL; /* written straight into buf by votes_aggregate_ser below */
  cert.has_notar_aggregate = (uchar)!is_fast;
  cert.notar_aggregate     = NULL;

  ulong off = 0UL;
  ulong sz;
  FD_STORE( ulong, buf+off, cert.slot );                                                                          off += sizeof(ulong);
  memcpy( buf+off, cert.block_id, sizeof(fd_hash_t) );                                                            off += sizeof(fd_hash_t);
  if( FD_UNLIKELY( !(sz=votes_aggregate_ser( is_fast ? &footer->fast_final_cert : &footer->final_cert, buf+off )) ) ) return 0UL;
                                                                                                                  off += sz;
  buf[ off ] = cert.has_notar_aggregate;                                                                          off += sizeof(uchar);
  if( cert.has_notar_aggregate ) {
    if( FD_UNLIKELY( !(sz=votes_aggregate_ser( &footer->notar_cert, buf+off )) ) ) return 0UL;
                                                                                                                  off += sz;
  }
  return off;
}

static ulong
skip_reward_cert_ser( fd_block_footer_cert_t const * cert,
                      uchar *                        buf ) {
  skip_reward_cert_serde_t reward;

  reward.slot      = cert->slot;
  reward.signature = cert->sig; /* already compressed */
  reward.bitmap_sz = (ushort)AG_BLS_AGG_SER_SZ( cert->nbits );
  reward.bitmap    = NULL; /* written straight into buf by bitmap_ser below */

  ulong off = 0UL;
  ulong sz;
  FD_STORE( ulong, buf+off, reward.slot );                                              off += sizeof(ulong);
  memcpy( buf+off, reward.signature, FD_BLS_SIG_COMPRESSED_SZ );                        off += FD_BLS_SIG_COMPRESSED_SZ;
                                                                                        off += fd_cu16_enc( reward.bitmap_sz, buf+off );
  if( FD_UNLIKELY( !(sz=bitmap_ser( cert->nbits, cert->signer_set, buf+off )) ) ) return 0UL;
                                                                                        off += sz;
  return off;
}

static ulong
notar_reward_cert_ser( fd_block_footer_cert_t const * cert,
                       uchar *                        buf ) {
  notar_reward_cert_serde_t reward;

  reward.slot      = cert->slot;
  reward.block_id  = cert->block_id.uc;
  reward.signature = cert->sig; /* already compressed */
  reward.bitmap_sz = (ushort)AG_BLS_AGG_SER_SZ( cert->nbits );
  reward.bitmap    = NULL; /* written straight into buf by bitmap_ser below */

  ulong off = 0UL;
  ulong sz;
  FD_STORE( ulong, buf+off, reward.slot );                                              off += sizeof(ulong);
  memcpy( buf+off, reward.block_id, sizeof(fd_hash_t) );                                off += sizeof(fd_hash_t);
  memcpy( buf+off, reward.signature, FD_BLS_SIG_COMPRESSED_SZ );                        off += FD_BLS_SIG_COMPRESSED_SZ;
                                                                                        off += fd_cu16_enc( reward.bitmap_sz, buf+off );
  if( FD_UNLIKELY( !(sz=bitmap_ser( cert->nbits, cert->signer_set, buf+off )) ) ) return 0UL;
                                                                                        off += sz;
  return off;
}

static ulong
footer_ser( fd_block_footer_t const * footer,
            uchar *                   buf ) {
  if( FD_UNLIKELY( footer->has_fast_final_cert && footer->has_final_cert ) ) return 0UL; /* one finalization shape or the other */
  if( FD_UNLIKELY( footer->user_agent_len>FD_BLOCK_FOOTER_USER_AGENT_MAX ) ) return 0UL;

  footer_serde_t ftr;

  ftr.version                   = (uchar)1;
  ftr.bank_hash                 = footer->bank_hash.uc;
  ftr.block_producer_time_nanos = footer->block_producer_time_nanos;
  ftr.user_agent_len            = (uchar)footer->user_agent_len;
  ftr.user_agent                = footer->user_agent;
  ftr.has_block_final_cert      = (uchar)( footer->has_fast_final_cert || footer->has_final_cert );
  ftr.block_final_cert          = NULL; /* the three cert bodies are written straight into buf below */
  ftr.has_skip_reward_cert      = (uchar)!!footer->has_skip_reward_cert;
  ftr.skip_reward_cert          = NULL;
  ftr.has_notar_reward_cert     = (uchar)!!footer->has_notar_reward_cert;
  ftr.notar_reward_cert         = NULL;

  ulong off = 0UL;
  ulong sz;
  buf[ off ] = ftr.version;                                                                          off += sizeof(uchar);
  memcpy( buf+off, ftr.bank_hash, sizeof(fd_hash_t) );                                               off += sizeof(fd_hash_t);
  FD_STORE( ulong, buf+off, ftr.block_producer_time_nanos );                                         off += sizeof(ulong);
  buf[ off ] = ftr.user_agent_len;                                                                   off += sizeof(uchar);
  memcpy( buf+off, ftr.user_agent, ftr.user_agent_len );                                             off += ftr.user_agent_len;
  buf[ off ] = ftr.has_block_final_cert;                                                             off += sizeof(uchar);
  if( ftr.has_block_final_cert ) {
    if( FD_UNLIKELY( !(sz=final_cert_ser( footer, buf+off )) ) ) return 0UL;
                                                                                                     off += sz;
  }
  buf[ off ] = ftr.has_skip_reward_cert;                                                             off += sizeof(uchar);
  if( ftr.has_skip_reward_cert ) {
    if( FD_UNLIKELY( !(sz=skip_reward_cert_ser( &footer->skip_reward_cert, buf+off )) ) ) return 0UL;
                                                                                                     off += sz;
  }
  buf[ off ] = ftr.has_notar_reward_cert;                                                            off += sizeof(uchar);
  if( ftr.has_notar_reward_cert ) {
    if( FD_UNLIKELY( !(sz=notar_reward_cert_ser( &footer->notar_reward_cert, buf+off )) ) ) return 0UL;
                                                                                                     off += sz;
  }

  return off;
}

ulong
fd_block_marker_ser( fd_block_marker_t const * self,
                     uchar                     buf[ static FD_BLOCK_MARKER_SER_MAX ] ) {
  uchar * payload = buf+FD_BLOCK_MARKER_PREAMBLE_SZ;
  ulong   payload_sz;
  switch( self->kind ) {
  case FD_BLOCK_MARKER_KIND_FOOTER: payload_sz = footer_ser( &self->footer, payload ); break;
  case FD_BLOCK_MARKER_KIND_HEADER: payload_sz = header_ser( &self->header, payload ); break;
  default:                          return 0UL; /* nothing we produce is an UpdateParent or GenesisCertificate */
  }
  if( FD_UNLIKELY( !payload_sz ) ) return 0UL;

  marker_serde_t marker;

  marker.entry_cnt = 0UL;
  marker.version   = (ushort)1;
  marker.tag       = (uchar)self->kind;
  marker.length    = (ushort)payload_sz;
  marker.payload   = payload; /* already in place */

  ulong off = 0UL;
  FD_STORE( ulong,  buf+off, marker.entry_cnt ); off += sizeof(ulong);
  FD_STORE( ushort, buf+off, marker.version );   off += sizeof(ushort);
  buf[ off ] = marker.tag;                       off += sizeof(uchar);
  FD_STORE( ushort, buf+off, marker.length );    off += sizeof(ushort);
                                                 off += payload_sz;

  return off;
}

static int
header_de( fd_block_header_t * header,
           uchar const *       buf,
           ulong               buf_sz,
           ulong *             sz ) {
  FAIL( buf_sz<FD_BLOCK_HEADER_SER_SZ, SZ );

  header_serde_t hdr; ulong off = 0UL;
  hdr.version         = buf[ off ];                off += sizeof(uchar);
  FAIL( hdr.version!=1, INVAL ); /* VersionedBlockHeader has only V1 */
  hdr.parent_slot     = FD_LOAD( ulong, buf+off ); off += sizeof(ulong);
  hdr.parent_block_id = buf+off;                   off += sizeof(fd_hash_t);

  header->parent_slot = hdr.parent_slot;
  memcpy( header->parent_block_id.uc, hdr.parent_block_id, sizeof(fd_hash_t) );

  *sz = off;
  return FD_BLOCK_MARKER_DE_SUCCESS;
}

static int
update_parent_de( fd_update_parent_t * update_parent,
                  uchar const *        buf,
                  ulong                buf_sz,
                  ulong *              sz ) {
  FAIL( buf_sz<FD_UPDATE_PARENT_SER_SZ, SZ );

  update_parent_serde_t upd; ulong off = 0UL;
  upd.version             = buf[ off ];                off += sizeof(uchar);
  FAIL( upd.version!=1, INVAL ); /* VersionedUpdateParent has only V1 */
  upd.new_parent_slot     = FD_LOAD( ulong, buf+off ); off += sizeof(ulong);
  upd.new_parent_block_id = buf+off;                   off += sizeof(fd_hash_t);

  update_parent->new_parent_slot = upd.new_parent_slot;
  memcpy( update_parent->new_parent_block_id.uc, upd.new_parent_block_id, sizeof(fd_hash_t) );

  *sz = off;
  return FD_BLOCK_MARKER_DE_SUCCESS;
}

/* bitmap_de decodes the base2 bitmap at b into nbits and signer_set
   through ag_bls_agg_de, which checks the version, the width against
   FD_BLS_SET_MAX and the payload length against the width.  The
   width is then kept verbatim, so a cert re-encodes at the width it came
   with. */

static int
bitmap_de( ushort *       nbits,
           fd_bls_set_t * signer_set,
           uchar const *  b,
           ulong          b_sz ) {
  fd_bls_agg_t agg[1];
  int err = ag_bls_agg_de( agg, b, b_sz ); /* base2 only; AG_BLS_DE_ERR_* are FD_BLOCK_MARKER_DE_ERR_* */
  if( FD_UNLIKELY( err ) ) return err;

  *nbits = FD_LOAD( ushort, b+sizeof(uchar) ); /* ag_bls_agg_de has sized and bounded this header */
  fd_bls_set_copy( signer_set, agg->set );
  return FD_BLOCK_MARKER_DE_SUCCESS;
}

static int
votes_aggregate_de( fd_block_footer_cert_t * cert,
                    uchar const *            buf,
                    ulong                    buf_sz,
                    ulong *                  sz ) {
  FAIL( buf_sz<FD_BLOCK_VOTES_AGGREGATE_SER_HDR_SZ, SZ );

  votes_aggregate_serde_t aggregate; ulong off = 0UL;
  aggregate.signature = buf+off;                    off += FD_BLS_SIG_COMPRESSED_SZ;
  aggregate.bitmap_sz = FD_LOAD( ushort, buf+off ); off += sizeof(ushort);
  FAIL( (ulong)aggregate.bitmap_sz>buf_sz-off, SZ );
  aggregate.bitmap    = buf+off;                    off += aggregate.bitmap_sz;

  int err = bitmap_de( &cert->nbits, cert->signer_set, aggregate.bitmap, aggregate.bitmap_sz );
  if( FD_UNLIKELY( err ) ) return err;
  memcpy( cert->sig, aggregate.signature, FD_BLS_SIG_COMPRESSED_SZ ); /* stays compressed for votor */

  *sz = off;
  return FD_BLOCK_MARKER_DE_SUCCESS;
}

static int
final_cert_de( fd_block_footer_t * footer,
               uchar const *       buf,
               ulong               buf_sz,
               ulong *             sz ) {
  FAIL( buf_sz<FD_BLOCK_FINAL_CERT_SER_HDR_SZ, SZ );

  final_cert_serde_t cert; ulong off = 0UL;
  cert.slot            = FD_LOAD( ulong, buf+off ); off += sizeof(ulong);
  cert.block_id        = buf+off;                   off += sizeof(fd_hash_t);
  cert.final_aggregate = buf+off;

  /* zeroed so final_cert.block_id stays zero on the slow path */
  fd_block_footer_cert_t final_agg[1]; fd_memset( final_agg, 0, sizeof(final_agg) );
  ulong agg_sz;
  int   err = votes_aggregate_de( final_agg, cert.final_aggregate, buf_sz-off, &agg_sz );
  if( FD_UNLIKELY( err ) ) return err;
  off += agg_sz;

  FAIL( buf_sz-off<sizeof(uchar), SZ );
  cert.has_notar_aggregate = buf[ off ];            off += sizeof(uchar);
  FAIL( cert.has_notar_aggregate>1, INVAL );
  cert.notar_aggregate     = cert.has_notar_aggregate ? buf+off : NULL;

  if( !cert.notar_aggregate ) {
    footer->has_fast_final_cert  = 1;
    footer->fast_final_cert      = *final_agg;
    footer->fast_final_cert.slot = cert.slot;
    memcpy( footer->fast_final_cert.block_id.uc, cert.block_id, sizeof(fd_hash_t) );
  } else {
    err = votes_aggregate_de( &footer->notar_cert, cert.notar_aggregate, buf_sz-off, &agg_sz );
    if( FD_UNLIKELY( err ) ) return err;
    off += agg_sz;
    footer->has_final_cert  = 1;
    footer->final_cert      = *final_agg;
    footer->final_cert.slot = cert.slot;
    footer->notar_cert.slot = cert.slot;
    memcpy( footer->notar_cert.block_id.uc, cert.block_id, sizeof(fd_hash_t) );
  }

  *sz = off;
  return FD_BLOCK_MARKER_DE_SUCCESS;
}

static int
skip_reward_cert_de( fd_block_footer_cert_t * cert,
                     uchar const *            buf,
                     ulong                    buf_sz,
                     ulong *                  sz ) {
  FAIL( buf_sz<FD_BLOCK_SKIP_REWARD_CERT_SER_HDR_SZ, SZ );

  skip_reward_cert_serde_t reward; ulong off = 0UL;
  reward.slot      = FD_LOAD( ulong, buf+off );             off += sizeof(ulong);
  reward.signature = buf+off;                               off += FD_BLS_SIG_COMPRESSED_SZ;
  FAIL( buf_sz==off, SZ ); /* no byte for the ShortU16 */
  ulong cu16_sz = fd_cu16_dec_sz( buf+off, buf_sz-off );
  FAIL( !cu16_sz, INVAL ); /* ShortU16 malformed (or a multi byte one cut short, which fd_cu16_dec_sz cannot tell apart) */
  reward.bitmap_sz = fd_cu16_dec_fixed( buf+off, cu16_sz ); off += cu16_sz;
  FAIL( (ulong)reward.bitmap_sz>buf_sz-off, SZ );
  reward.bitmap    = buf+off;                               off += reward.bitmap_sz;

  int err = bitmap_de( &cert->nbits, cert->signer_set, reward.bitmap, reward.bitmap_sz );
  if( FD_UNLIKELY( err ) ) return err;
  cert->slot = reward.slot; /* block_id stays zero */
  memcpy( cert->sig, reward.signature, FD_BLS_SIG_COMPRESSED_SZ );

  *sz = off;
  return FD_BLOCK_MARKER_DE_SUCCESS;
}

static int
notar_reward_cert_de( fd_block_footer_cert_t * cert,
                      uchar const *            buf,
                      ulong                    buf_sz,
                      ulong *                  sz ) {
  FAIL( buf_sz<FD_BLOCK_NOTAR_REWARD_CERT_SER_HDR_SZ, SZ );

  notar_reward_cert_serde_t reward; ulong off = 0UL;
  reward.slot      = FD_LOAD( ulong, buf+off );             off += sizeof(ulong);
  reward.block_id  = buf+off;                               off += sizeof(fd_hash_t);
  reward.signature = buf+off;                               off += FD_BLS_SIG_COMPRESSED_SZ;
  FAIL( buf_sz==off, SZ ); /* no byte for the ShortU16 */
  ulong cu16_sz = fd_cu16_dec_sz( buf+off, buf_sz-off );
  FAIL( !cu16_sz, INVAL ); /* ShortU16 malformed (or a multi byte one cut short, which fd_cu16_dec_sz cannot tell apart) */
  reward.bitmap_sz = fd_cu16_dec_fixed( buf+off, cu16_sz ); off += cu16_sz;
  FAIL( (ulong)reward.bitmap_sz>buf_sz-off, SZ );
  reward.bitmap    = buf+off;                               off += reward.bitmap_sz;

  int err = bitmap_de( &cert->nbits, cert->signer_set, reward.bitmap, reward.bitmap_sz );
  if( FD_UNLIKELY( err ) ) return err;
  cert->slot = reward.slot;
  memcpy( cert->block_id.uc, reward.block_id, sizeof(fd_hash_t) );
  memcpy( cert->sig, reward.signature, FD_BLS_SIG_COMPRESSED_SZ );

  *sz = off;
  return FD_BLOCK_MARKER_DE_SUCCESS;
}

static int
footer_de( fd_block_footer_t * footer,
           uchar const *       buf,
           ulong               buf_sz,
           ulong *             sz ) {
  FAIL( buf_sz<FD_BLOCK_FOOTER_SER_HDR_SZ, SZ );

  footer_serde_t ftr; ulong off = 0UL;
  ftr.version                   = buf[ off ];                off += sizeof(uchar);
  FAIL( ftr.version!=1, INVAL ); /* VersionedBlockFooter has only V1 */
  ftr.bank_hash                 = buf+off;                   off += sizeof(fd_hash_t);
  ftr.block_producer_time_nanos = FD_LOAD( ulong, buf+off ); off += sizeof(ulong);
  ftr.user_agent_len            = buf[ off ];                off += sizeof(uchar);
  FAIL( buf_sz-off<(ulong)ftr.user_agent_len, SZ );
  ftr.user_agent                = buf+off;                   off += ftr.user_agent_len;

  memcpy( footer->bank_hash.uc, ftr.bank_hash, sizeof(fd_hash_t) );
  footer->block_producer_time_nanos = ftr.block_producer_time_nanos;
  footer->user_agent_len            = (ulong)ftr.user_agent_len;
  memcpy( footer->user_agent, ftr.user_agent, ftr.user_agent_len );

  int   err;
  ulong part_sz;

  FAIL( buf_sz-off<sizeof(uchar), SZ );
  ftr.has_block_final_cert  = buf[ off ];                    off += sizeof(uchar);
  FAIL( ftr.has_block_final_cert>1, INVAL );
  ftr.block_final_cert      = ftr.has_block_final_cert ? buf+off : NULL;
  if( ftr.block_final_cert ) {
    err = final_cert_de( footer, ftr.block_final_cert, buf_sz-off, &part_sz ); /* sets has_fast_final_cert or has_final_cert itself */
    if( FD_UNLIKELY( err ) ) return err;
    off += part_sz;
  }

  FAIL( buf_sz-off<sizeof(uchar), SZ );
  ftr.has_skip_reward_cert  = buf[ off ];                    off += sizeof(uchar);
  FAIL( ftr.has_skip_reward_cert>1, INVAL );
  ftr.skip_reward_cert      = ftr.has_skip_reward_cert ? buf+off : NULL;
  if( ftr.skip_reward_cert ) {
    err = skip_reward_cert_de( &footer->skip_reward_cert, ftr.skip_reward_cert, buf_sz-off, &part_sz );
    if( FD_UNLIKELY( err ) ) return err;
    off += part_sz;
    footer->has_skip_reward_cert = 1;
  }

  FAIL( buf_sz-off<sizeof(uchar), SZ );
  ftr.has_notar_reward_cert = buf[ off ];                    off += sizeof(uchar);
  FAIL( ftr.has_notar_reward_cert>1, INVAL );
  ftr.notar_reward_cert     = ftr.has_notar_reward_cert ? buf+off : NULL;
  if( ftr.notar_reward_cert ) {
    err = notar_reward_cert_de( &footer->notar_reward_cert, ftr.notar_reward_cert, buf_sz-off, &part_sz );
    if( FD_UNLIKELY( err ) ) return err;
    off += part_sz;
    footer->has_notar_reward_cert = 1;
  }

  *sz = off;
  return FD_BLOCK_MARKER_DE_SUCCESS;
}

int
fd_block_marker_de( fd_block_marker_t * self,
                    uchar const *       buf,
                    ulong               buf_sz ) {
  FAIL( buf_sz<FD_BLOCK_MARKER_PREAMBLE_SZ, SZ );

  marker_serde_t marker; ulong off = 0UL;
  marker.entry_cnt = FD_LOAD( ulong,  buf+off ); off += sizeof(ulong);
  marker.version   = FD_LOAD( ushort, buf+off ); off += sizeof(ushort);
  marker.tag       = buf[ off ];                 off += sizeof(uchar);
  marker.length    = FD_LOAD( ushort, buf+off ); off += sizeof(ushort);
  FAIL( marker.entry_cnt!=0UL, INVAL ); /* an entry batch, not a marker */
  FAIL( marker.version!=1,     INVAL ); /* VersionedBlockMarker has only V1 */
  FAIL( (ulong)marker.length>buf_sz-off, SZ );
  marker.payload   = buf+off;

  fd_memset( self, 0, sizeof(fd_block_marker_t) );
  self->kind = (uint)marker.tag;

  int   err;
  ulong payload_sz;
  switch( self->kind ) {
  case FD_BLOCK_MARKER_KIND_FOOTER:        err = footer_de       ( &self->footer,        marker.payload, marker.length, &payload_sz ); break;
  case FD_BLOCK_MARKER_KIND_HEADER:        err = header_de       ( &self->header,        marker.payload, marker.length, &payload_sz ); break;
  case FD_BLOCK_MARKER_KIND_UPDATE_PARENT: err = update_parent_de( &self->update_parent, marker.payload, marker.length, &payload_sz ); break;
  case FD_BLOCK_MARKER_KIND_GENESIS_CERT:  return FD_BLOCK_MARKER_DE_ERR_UNSUPPORTED;
  default:                                 return FD_BLOCK_MARKER_DE_ERR_INVAL;
  }
  if( FD_UNLIKELY( err ) ) return err;
  FAIL( payload_sz!=(ulong)marker.length, SZ ); /* LengthPrefixed::len is exact */

  return FD_BLOCK_MARKER_DE_SUCCESS;
}

#include "ag_cert_serde.h"

#define FAIL( cond, err ) do { if( FD_UNLIKELY( cond ) ) return AG_CERT_DE_ERR_##err; } while( 0 )

ulong
ag_cert_ser( ag_cert_t const * self,
             ushort            shred_version,
             uchar             buf[ static AG_CERT_SER_MAX ] ) {
  ag_bls_agg_t const * agg;
  ag_bls_agg_t const * agg2 = NULL;
  uchar const *        hash = NULL;
  ulong                slot;
  switch( self->kind ) {
  case AG_CERT_KIND_FINAL:
    slot = self->final.slot;
    agg  = &self->final.agg;
    break;
  case AG_CERT_KIND_FAST_FINAL:
    slot = self->fast_final.slot;
    agg  = &self->fast_final.agg;
    hash = self->fast_final.block_hash;
    break;
  case AG_CERT_KIND_NOTAR:
    slot = self->notar.slot;
    agg  = &self->notar.agg;
    hash = self->notar.block_hash;
    break;
  case AG_CERT_KIND_NOTAR_FALLBACK:
    slot = self->notar_fallback.slot;
    agg  = &self->notar_fallback.agg_notar;
    agg2 = &self->notar_fallback.agg_notar_fallback;
    hash = self->notar_fallback.block_hash;
    break;
  case AG_CERT_KIND_SKIP:
    slot = self->skip.slot;
    agg  = &self->skip.agg_skip;
    agg2 = &self->skip.agg_skip_fallback;
    break;
  default:
    FD_LOG_ERR(( "unimplemented" ));
  }

  if( FD_UNLIKELY( agg2 && !ag_bls_agg_signer_cnt( agg2 ) ) ) agg2 = NULL; /* check empty */

  ag_cert_serde_t cert;

  cert.version       = (uchar)1;
  cert.tag           = (uchar)( self->kind+AG_CERT_SERDE_TAG_FINAL );
  cert.slot          = slot;
  cert.block_id      = hash;
  cert.signature     = agg->sig;
  cert.bitmap_sz     = agg2 ? ag_bls_agg_pair_ser_sz( agg, agg2 ) : ag_bls_agg_ser_sz( agg );
  cert.bitmap        = NULL; /* filled straight into buf by the bitmap encoder below */
  cert.shred_version = shred_version;

  ulong off = 0UL;
  buf[ off ] = cert.version;                                                       off += sizeof(uchar);
  buf[ off ] = cert.tag;                                                           off += sizeof(uchar);
  FD_STORE( ulong, buf+off, cert.slot );                                           off += sizeof(ulong);
  if( cert.block_id ) { memcpy( buf+off, cert.block_id, sizeof(ag_block_hash_t) ); off += sizeof(ag_block_hash_t); }
  memcpy( buf+off, cert.signature, AG_BLS_SIG_SZ );                                off += AG_BLS_SIG_SZ;
  FD_STORE( ulong, buf+off, cert.bitmap_sz );                                      off += sizeof(ulong);
                                                                                   off += agg2 ? ag_bls_agg_pair_ser( agg, agg2, buf+off ) : ag_bls_agg_ser( agg, buf+off );
  FD_STORE( ushort, buf+off, cert.shred_version );                                 off += sizeof(ushort);

  return off;
}

int
ag_cert_de( ag_cert_t *   self,
            ushort        shred_version,
            uchar const * buf,
            ulong         buf_sz ) {
  FAIL( buf_sz<AG_CERT_SER_MIN || buf_sz>AG_CERT_SER_MAX, SZ );

  ag_cert_serde_t cert; ulong off = 0UL;
  cert.version       = buf[ off ];                off += sizeof(uchar);
  cert.tag           = buf[ off ];                off += sizeof(uchar);
  FAIL( cert.version!=1, INVAL );

  fd_memset( self, 0, sizeof(ag_cert_t) );
  self->kind = (uint)cert.tag - AG_CERT_SERDE_TAG_FINAL;

  int   has_block_id = self->kind==AG_CERT_KIND_FAST_FINAL || self->kind==AG_CERT_KIND_NOTAR || self->kind==AG_CERT_KIND_NOTAR_FALLBACK;
  ulong hdr_sz      = AG_CERT_SER_HDR_SZ( has_block_id );
  FAIL( buf_sz<hdr_sz, SZ );

  cert.slot          = FD_LOAD( ulong, buf+off ); off += sizeof(ulong);
  cert.block_id      = NULL;
  if( has_block_id ) {
    cert.block_id    = buf+off;                   off += sizeof(ag_block_hash_t);
  }
  cert.signature     = buf+off;                   off += AG_BLS_SIG_SZ;
  cert.bitmap_sz     = FD_LOAD( ulong, buf+off ); off += sizeof(ulong);
  cert.bitmap        = buf+off;
  FD_TEST( off==hdr_sz );

  ulong rem = buf_sz - hdr_sz;
  FAIL( cert.bitmap_sz>rem || rem-cert.bitmap_sz!=sizeof(ushort), SZ ); /* too few, or trailing bytes */

  cert.shred_version = FD_LOAD( ushort, cert.bitmap+cert.bitmap_sz );
  FAIL( cert.shred_version!=shred_version, SHRED_VERSION );

  int err;
  switch( self->kind ) {
  case AG_CERT_KIND_FINAL:
    self->final.slot = cert.slot;
    if( FD_UNLIKELY( err = ag_bls_agg_de( &self->final.agg, cert.bitmap, cert.bitmap_sz ) ) ) return err;
    memcpy( self->final.agg.sig, cert.signature, AG_BLS_SIG_SZ );
    break;
  case AG_CERT_KIND_FAST_FINAL:
    self->fast_final.slot = cert.slot;
    memcpy( self->fast_final.block_hash, cert.block_id, sizeof(ag_block_hash_t) );
    if( FD_UNLIKELY( err = ag_bls_agg_de( &self->fast_final.agg, cert.bitmap, cert.bitmap_sz ) ) ) return err;
    memcpy( self->fast_final.agg.sig, cert.signature, AG_BLS_SIG_SZ );
    break;
  case AG_CERT_KIND_NOTAR:
    self->notar.slot = cert.slot;
    memcpy( self->notar.block_hash, cert.block_id, sizeof(ag_block_hash_t) );
    if( FD_UNLIKELY( err = ag_bls_agg_de( &self->notar.agg, cert.bitmap, cert.bitmap_sz ) ) ) return err;
    memcpy( self->notar.agg.sig, cert.signature, AG_BLS_SIG_SZ );
    break;
  case AG_CERT_KIND_NOTAR_FALLBACK: {
    ag_bls_agg_t * agg  = &self->notar_fallback.agg_notar;
    ag_bls_agg_t * agg2 = &self->notar_fallback.agg_notar_fallback;
    self->notar_fallback.slot = cert.slot;
    memcpy( self->notar_fallback.block_hash, cert.block_id, sizeof(ag_block_hash_t) );
    if( FD_UNLIKELY( err = ag_bls_agg_pair_de( agg, agg2, cert.bitmap, cert.bitmap_sz ) ) ) return err;
    memcpy( agg->sig, cert.signature, AG_BLS_SIG_SZ );
    break;
  }
  case AG_CERT_KIND_SKIP: {
    ag_bls_agg_t * agg  = &self->skip.agg_skip;
    ag_bls_agg_t * agg2 = &self->skip.agg_skip_fallback;
    self->skip.slot = cert.slot;
    if( FD_UNLIKELY( err = ag_bls_agg_pair_de( agg, agg2, cert.bitmap, cert.bitmap_sz ) ) ) return err;
    memcpy( agg->sig, cert.signature, AG_BLS_SIG_SZ );
    break;
  }
  default:
    return AG_CERT_DE_ERR_INVAL;
  }

  return AG_CERT_DE_SUCCESS;
}

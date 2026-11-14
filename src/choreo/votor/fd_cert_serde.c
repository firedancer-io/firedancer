#include "fd_cert_serde.h"

#define FAIL( cond, err ) do { if( FD_UNLIKELY( cond ) ) return FD_CERT_DE_ERR_##err; } while( 0 )

ulong
fd_cert_ser( fd_cert_t const * self,
             uchar             buf[ static FD_CERT_SER_MAX ] ) {
  fd_bls_agg_t const * agg;
  fd_bls_agg_t const * agg2 = NULL;
  uchar const *        hash = NULL;
  ulong                slot;
  switch( self->kind ) {
  case FD_CERT_KIND_FINAL:
    slot = self->final.slot;
    agg  = &self->final.agg;
    break;
  case FD_CERT_KIND_FAST_FINAL:
    slot = self->fast_final.slot;
    agg  = &self->fast_final.agg;
    hash = self->fast_final.block_hash.uc;
    break;
  case FD_CERT_KIND_NOTAR:
    slot = self->notar.slot;
    agg  = &self->notar.agg;
    hash = self->notar.block_hash.uc;
    break;
  case FD_CERT_KIND_NOTAR_FALLBACK:
    slot = self->notar_fallback.slot;
    agg  = &self->notar_fallback.agg_notar;
    agg2 = &self->notar_fallback.agg_notar_fallback;
    hash = self->notar_fallback.block_hash.uc;
    break;
  case FD_CERT_KIND_SKIP:
    slot = self->skip.slot;
    agg  = &self->skip.agg_skip;
    agg2 = &self->skip.agg_skip_fallback;
    break;
  default:
    FD_LOG_ERR(( "unimplemented" ));
  }

  if( FD_UNLIKELY( agg2 && !fd_bls_set_cnt( agg2->set ) ) ) agg2 = NULL; /* check empty */

  fd_bls_sig_t sig = agg->sig;
  if( FD_UNLIKELY( agg2 ) ) fd_bls_sig_add( &sig, &sig, &agg2->sig );

  fd_cert_serde_t cert = {
    .version       = (uchar)1,
    .tag           = (uchar)( self->kind+FD_CERT_SERDE_TAG_FINAL ),
    .slot          = slot,
    .block_id      = hash,
    .bitmap_sz     = agg2 ? fd_bls_agg_pair_ser_sz( agg, agg2 ) : fd_bls_agg_ser_sz( agg ),
    .shred_version = fd_cert_shred_version( self ),
  };

  ulong off = 0UL;
  buf[ off ] = cert.version;                                                                    off += sizeof(uchar);
  buf[ off ] = cert.tag;                                                                        off += sizeof(uchar);
  FD_STORE( ulong, buf+off, cert.slot );                                                        off += sizeof(ulong);
  if( FD_LIKELY( cert.block_id ) ) { memcpy( buf+off, cert.block_id, sizeof(fd_block_hash_t) ); off += sizeof(fd_block_hash_t); }
  fd_bls_sig_ser( &sig, buf+off );                                                              off += FD_BLS_SIG_SZ;
  FD_STORE( ulong, buf+off, cert.bitmap_sz );                                                   off += sizeof(ulong);
                                                                                                off += agg2 ? fd_bls_agg_pair_ser( agg, agg2, buf+off ) : fd_bls_agg_ser( agg, buf+off );
  FD_STORE( ushort, buf+off, cert.shred_version );                                              off += sizeof(ushort);

  return off;
}

/* cert_de_hdr parses the fixed size header (version through bitmap_sz)
   and cert_de_tail bounds checks the bitmap and reads shred_version.
   fd_cert_de decodes the signature between the two. */

static int
cert_de_hdr( fd_cert_serde_t * hdr,
             uchar const *     buf,
             ulong             buf_sz ) {
  FAIL( buf_sz<2 /* version + tag */, SZ );

  ulong off = 0UL;
  hdr->version   = buf[ off ];                off += sizeof(uchar);
  hdr->tag       = buf[ off ];                off += sizeof(uchar);
  FAIL( hdr->version!=1, INVAL );

  int   has_block_id = hdr->tag==FD_CERT_SERDE_TAG_FAST_FINAL || hdr->tag==FD_CERT_SERDE_TAG_NOTAR || hdr->tag==FD_CERT_SERDE_TAG_NOTAR_FALLBACK;
  ulong hdr_sz       = FD_CERT_SER_HDR_SZ( has_block_id );
  FAIL( buf_sz<hdr_sz, SZ );

  hdr->slot      = FD_LOAD( ulong, buf+off ); off += sizeof(ulong);
  hdr->block_id  = NULL;
  if( FD_LIKELY( has_block_id ) ) {
    hdr->block_id = buf+off;                  off += sizeof(fd_block_hash_t);
  }
  hdr->signature = buf+off;                   off += FD_BLS_SIG_SZ;
  hdr->bitmap_sz = FD_LOAD( ulong, buf+off ); off += sizeof(ulong);
  hdr->bitmap    = buf+off;
  FD_TEST( off==hdr_sz );

  return FD_CERT_DE_SUCCESS;
}

static int
cert_de_tail( fd_cert_serde_t * hdr,
              uchar const *     buf,
              ulong             buf_sz ) {
  ulong rem = buf_sz - (ulong)( hdr->bitmap - buf );
  FAIL( hdr->bitmap_sz>rem || rem-hdr->bitmap_sz<sizeof(ushort), SZ ); /* too few, trailing bytes are ignored */

  hdr->shred_version = FD_LOAD( ushort, hdr->bitmap+hdr->bitmap_sz );
  return FD_CERT_DE_SUCCESS;
}

int
fd_cert_de_peek( fd_cert_serde_t * hdr,
                 ulong *           bit_cnt,
              uchar const *     buf,
              ulong             buf_sz ) {
  int err = cert_de_hdr( hdr, buf, buf_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = cert_de_tail( hdr, buf, buf_sz );
  if( FD_UNLIKELY( err ) ) return err;

  switch( hdr->tag ) { /* the bitmap encodings fd_cert_de accepts */
  case FD_CERT_SERDE_TAG_FINAL:
  case FD_CERT_SERDE_TAG_FAST_FINAL:
  case FD_CERT_SERDE_TAG_NOTAR:          return fd_bls_agg_de_check( 0, bit_cnt, hdr->bitmap, hdr->bitmap_sz );
  case FD_CERT_SERDE_TAG_NOTAR_FALLBACK:
  case FD_CERT_SERDE_TAG_SKIP:           return fd_bls_agg_de_check( 1, bit_cnt, hdr->bitmap, hdr->bitmap_sz );
  default:                               return FD_CERT_DE_ERR_INVAL;
  }
}

int
fd_cert_de( fd_cert_t *   self,
            ulong *       bit_cnt,
            uchar const * buf,
            ulong         buf_sz ) {
  fd_cert_serde_t cert;
  int err = cert_de_hdr( &cert, buf, buf_sz );
  if( FD_UNLIKELY( err ) ) return err;

  fd_memset( self, 0, sizeof(fd_cert_t) );
  self->kind = (uint)cert.tag - FD_CERT_SERDE_TAG_FINAL;

  fd_bls_sig_t sig[1];
  FAIL( fd_bls_sig_de_unchecked( sig, cert.signature ), INVAL ); /* deserialize now, defer the g2 subgroup check to verify */

  err = cert_de_tail( &cert, buf, buf_sz );
  if( FD_UNLIKELY( err ) ) return err;

  switch( self->kind ) {
  case FD_CERT_KIND_FINAL:
    self->final.slot = cert.slot;
    self->final.shred_version = cert.shred_version;
    if( FD_UNLIKELY( err = fd_bls_agg_de( &self->final.agg, bit_cnt, cert.bitmap, cert.bitmap_sz ) ) ) return err;
    self->final.agg.sig = *sig;
    break;
  case FD_CERT_KIND_FAST_FINAL:
    self->fast_final.slot = cert.slot;
    self->fast_final.shred_version = cert.shred_version;
    memcpy( &self->fast_final.block_hash, cert.block_id, sizeof(fd_block_hash_t) );
    if( FD_UNLIKELY( err = fd_bls_agg_de( &self->fast_final.agg, bit_cnt, cert.bitmap, cert.bitmap_sz ) ) ) return err;
    self->fast_final.agg.sig = *sig;
    break;
  case FD_CERT_KIND_NOTAR:
    self->notar.slot = cert.slot;
    self->notar.shred_version = cert.shred_version;
    memcpy( &self->notar.block_hash, cert.block_id, sizeof(fd_block_hash_t) );
    if( FD_UNLIKELY( err = fd_bls_agg_de( &self->notar.agg, bit_cnt, cert.bitmap, cert.bitmap_sz ) ) ) return err;
    self->notar.agg.sig = *sig;
    break;
  case FD_CERT_KIND_NOTAR_FALLBACK: {
    fd_bls_agg_t * agg  = &self->notar_fallback.agg_notar;
    fd_bls_agg_t * agg2 = &self->notar_fallback.agg_notar_fallback;
    self->notar_fallback.slot = cert.slot;
    self->notar_fallback.shred_version = cert.shred_version;
    memcpy( &self->notar_fallback.block_hash, cert.block_id, sizeof(fd_block_hash_t) );
    if( FD_UNLIKELY( err = fd_bls_agg_pair_de( agg, agg2, bit_cnt, cert.bitmap, cert.bitmap_sz ) ) ) return err;
    agg->sig = *sig;
    break;
  }
  case FD_CERT_KIND_SKIP: {
    fd_bls_agg_t * agg  = &self->skip.agg_skip;
    fd_bls_agg_t * agg2 = &self->skip.agg_skip_fallback;
    self->skip.slot = cert.slot;
    self->skip.shred_version = cert.shred_version;
    if( FD_UNLIKELY( err = fd_bls_agg_pair_de( agg, agg2, bit_cnt, cert.bitmap, cert.bitmap_sz ) ) ) return err;
    agg->sig = *sig;
    break;
  }
  default:
    return FD_CERT_DE_ERR_INVAL;
  }

  return FD_CERT_DE_SUCCESS;
}

#include "ag_vote_serde.h"

#define FAIL( cond, err ) do { if( FD_UNLIKELY( cond ) ) return AG_VOTE_DE_ERR_##err; } while( 0 )

ulong
ag_vote_ser( ag_vote_t const * self,
             uchar             buf[ static AG_VOTE_SER_SZ( 1 ) ] ) {
  ag_vote_serde_t vote;

  vote.version       = (uchar)1;
  vote.tag           = (uchar)( self->kind+AG_VOTE_SERDE_TAG_NOTAR );
  vote.slot          = ag_vote_slot( self );
  vote.block_id      = ag_vote_block_hash( self );
  vote.shred_version = ag_vote_shred_version( self );

  ulong off = 0UL;
  buf[ off ] = vote.version;                                                                    off += sizeof(uchar);
  buf[ off ] = vote.tag;                                                                        off += sizeof(uchar);
  FD_STORE( ulong, buf+off, vote.slot );                                                        off += sizeof(ulong);
  if( FD_LIKELY( vote.block_id ) ) { memcpy( buf+off, vote.block_id, sizeof(ag_block_hash_t) ); off += sizeof(ag_block_hash_t); }
  blst_p2_affine sig_aff[1];
  blst_p2_to_affine( sig_aff, ag_vote_sig( self ) );
  blst_p2_affine_serialize( buf+off, sig_aff );                                                 off += FD_BLS_SIG_SZ;
  FD_STORE( ushort, buf+off, vote.shred_version );                                              off += sizeof(ushort);

  return off;
}

int
ag_vote_de( ag_vote_t *   self,
            uchar const * buf,
            ulong         buf_sz ) {
  FAIL( buf_sz<2 /* version + tag */, SZ );

  ag_vote_serde_t vote; ulong off = 0UL;
  vote.version       = buf[ off ];                 off += sizeof(uchar);
  vote.tag           = buf[ off ];                 off += sizeof(uchar);
  FAIL( vote.version!=1, INVAL );

  uint kind = (uint)vote.tag - AG_VOTE_SERDE_TAG_NOTAR;

  int has_block_id = kind==AG_VOTE_KIND_NOTAR || kind==AG_VOTE_KIND_NOTAR_FALLBACK;
  FAIL( buf_sz!=AG_VOTE_SER_SZ( has_block_id ), SZ ); /* too few, or trailing bytes */

  vote.slot          = FD_LOAD( ulong, buf+off );  off += sizeof(ulong);
  vote.block_id      = NULL;
  if( FD_LIKELY( has_block_id ) ) {
    vote.block_id    = buf+off;                    off += sizeof(ag_block_hash_t);
  }
  vote.signature     = buf+off;                    off += FD_BLS_SIG_SZ;

  fd_bls_sig_t   sig[1];
  blst_p2_affine sig_aff[1];
  FAIL( vote.signature[0]&0xA0U,                                      INVAL );
  FAIL( blst_p2_deserialize( sig_aff, vote.signature )!=BLST_SUCCESS, INVAL );
  FAIL( !blst_p2_affine_in_g2( sig_aff ),                             INVAL );
  blst_p2_from_affine( sig, sig_aff );
  vote.shred_version = FD_LOAD( ushort, buf+off ); off += sizeof(ushort);

  fd_memset( self, 0, sizeof(ag_vote_t) );
  self->kind = kind;

  ag_vote_set_rank( self, USHORT_MAX ); /* FIXME */

  switch( kind ) {
  case AG_VOTE_KIND_NOTAR:
    self->notar.slot = vote.slot;
    self->notar.shred_version = vote.shred_version;
    memcpy( self->notar.block_hash, vote.block_id, sizeof(ag_block_hash_t) );
    self->notar.sig = *sig;
    break;
  case AG_VOTE_KIND_FINAL:
    self->final.slot = vote.slot;
    self->final.shred_version = vote.shred_version;
    self->final.sig = *sig;
    break;
  case AG_VOTE_KIND_SKIP:
    self->skip.slot = vote.slot;
    self->skip.shred_version = vote.shred_version;
    self->skip.sig = *sig;
    break;
  case AG_VOTE_KIND_NOTAR_FALLBACK:
    self->notar_fallback.slot = vote.slot;
    self->notar_fallback.shred_version = vote.shred_version;
    memcpy( self->notar_fallback.block_hash, vote.block_id, sizeof(ag_block_hash_t) );
    self->notar_fallback.sig = *sig;
    break;
  case AG_VOTE_KIND_SKIP_FALLBACK:
    self->skip_fallback.slot = vote.slot;
    self->skip_fallback.shred_version = vote.shred_version;
    self->skip_fallback.sig = *sig;
    break;
  default:
    return AG_VOTE_DE_ERR_INVAL;
  }

  return AG_VOTE_DE_SUCCESS;
}

ulong
ag_vote_signing_ser( uint          kind,
                     ulong         slot,
                     uchar const * block_hash,
                     ushort        shred_version,
                     uchar         buf[ static AG_VOTE_SIGNING_SER_MAX ] ) {
  ulong off = 0UL;
  buf[ off ] = (uchar)( kind+AG_VOTE_SERDE_TAG_NOTAR );                                   off += sizeof(uchar);
  FD_STORE( ulong, buf+off, slot );                                                       off += sizeof(ulong);
  if( FD_LIKELY( block_hash ) ) { memcpy( buf+off, block_hash, sizeof(ag_block_hash_t) ); off += sizeof(ag_block_hash_t); }
  FD_STORE( ushort, buf+off, shred_version );                                             off += sizeof(ushort);
  return off;
}

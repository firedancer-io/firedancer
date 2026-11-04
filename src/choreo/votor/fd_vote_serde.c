#include "fd_vote_serde.h"

#define FAIL( cond, err ) do { if( FD_UNLIKELY( cond ) ) return FD_VOTE_DE_ERR_##err; } while( 0 )

ulong
fd_vote_ser( fd_vote_t const * self,
             uchar             buf[ static FD_VOTE_SER_MAX ] ) {
  fd_vote_serde_t vote = {
    .version       = (uchar)1,
    .tag           = (uchar)( self->kind+FD_VOTE_SERDE_TAG_NOTAR ),
    .slot          = fd_vote_slot( self ),
    .block_id      = (uchar const *)fd_vote_block_hash( self ),
    .shred_version = fd_vote_shred_version( self ),
  };

  ulong off = 0UL;
  buf[ off ] = vote.version;                                                                    off += sizeof(uchar);
  buf[ off ] = vote.tag;                                                                        off += sizeof(uchar);
  FD_STORE( ulong, buf+off, vote.slot );                                                        off += sizeof(ulong);
  if( FD_LIKELY( vote.block_id ) ) { memcpy( buf+off, vote.block_id, sizeof(fd_block_hash_t) ); off += sizeof(fd_block_hash_t); }
  fd_bls_sig_ser( fd_vote_sig( self ), buf+off );                                                 off += FD_BLS_SIG_SZ;
  FD_STORE( ushort, buf+off, vote.shred_version );                                              off += sizeof(ushort);

  return off;
}

int
fd_vote_de( fd_vote_t *   self,
            uchar const * buf,
            ulong         buf_sz ) {
  FAIL( buf_sz<2 /* version + tag */, SZ );

  ulong off = 0UL;
  fd_vote_serde_t vote;
  vote.version       = buf[ off ];                 off += sizeof(uchar);
  vote.tag           = buf[ off ];                 off += sizeof(uchar);
  FAIL( vote.version!=1, INVAL );

  uint kind = (uint)vote.tag - FD_VOTE_SERDE_TAG_NOTAR;

  int has_block_id = kind==FD_VOTE_KIND_NOTAR || kind==FD_VOTE_KIND_NOTAR_FALLBACK;
  FAIL( buf_sz<FD_VOTE_SER_SZ( has_block_id ), SZ ); /* too few, trailing bytes are ignored */

  vote.slot          = FD_LOAD( ulong, buf+off );  off += sizeof(ulong);
  vote.block_id      = NULL;
  if( FD_LIKELY( has_block_id ) ) {
    vote.block_id    = buf+off;                    off += sizeof(fd_block_hash_t);
  }
  vote.signature     = buf+off;                    off += FD_BLS_SIG_SZ;

  fd_bls_sig_t sig[1];
  FAIL( fd_bls_sig_de_unchecked( sig, vote.signature ), INVAL );
  FAIL( fd_bls_sig_is_inf( sig ), SIG );
  vote.shred_version = FD_LOAD( ushort, buf+off ); off += sizeof(ushort);

  fd_memset( self, 0, sizeof(fd_vote_t) );
  self->kind = kind;

  switch( kind ) {
  case FD_VOTE_KIND_NOTAR:
    self->notar.slot = vote.slot;
    self->notar.shred_version = vote.shred_version;
    memcpy( &self->notar.block_hash, vote.block_id, sizeof(fd_block_hash_t) );
    self->notar.sig = *sig;
    break;
  case FD_VOTE_KIND_FINAL:
    self->final.slot = vote.slot;
    self->final.shred_version = vote.shred_version;
    self->final.sig = *sig;
    break;
  case FD_VOTE_KIND_SKIP:
    self->skip.slot = vote.slot;
    self->skip.shred_version = vote.shred_version;
    self->skip.sig = *sig;
    break;
  case FD_VOTE_KIND_NOTAR_FALLBACK:
    self->notar_fallback.slot = vote.slot;
    self->notar_fallback.shred_version = vote.shred_version;
    memcpy( &self->notar_fallback.block_hash, vote.block_id, sizeof(fd_block_hash_t) );
    self->notar_fallback.sig = *sig;
    break;
  case FD_VOTE_KIND_SKIP_FALLBACK:
    self->skip_fallback.slot = vote.slot;
    self->skip_fallback.shred_version = vote.shred_version;
    self->skip_fallback.sig = *sig;
    break;
  default:
    return FD_VOTE_DE_ERR_INVAL;
  }

  return FD_VOTE_DE_SUCCESS;
}

ulong
fd_vote_signing_ser( uint                    kind,
                     ulong                   slot,
                     fd_block_hash_t const * block_hash,
                     ushort                  shred_version,
                     uchar                   buf[ static FD_VOTE_SIGNING_SER_MAX ] ) {
  ulong off = 0UL;
  buf[ off ] = (uchar)( kind+FD_VOTE_SERDE_TAG_NOTAR );                                   off += sizeof(uchar);
  FD_STORE( ulong, buf+off, slot );                                                       off += sizeof(ulong);
  if( FD_LIKELY( block_hash ) ) { memcpy( buf+off, block_hash, sizeof(fd_block_hash_t) ); off += sizeof(fd_block_hash_t); }
  FD_STORE( ushort, buf+off, shred_version );                                             off += sizeof(ushort);
  return off;
}

#include "ag_vote_serde.h"

#define FAIL( cond, err ) do { if( FD_UNLIKELY( cond ) ) return AG_VOTE_DE_ERR_##err; } while( 0 )

static uchar const *
sig( ag_vote_t const * self ) {
  switch( self->kind ) {
  case AG_VOTE_KIND_NOTAR:          return self->notar.sig;
  case AG_VOTE_KIND_FINAL:          return self->final.sig;
  case AG_VOTE_KIND_SKIP:           return self->skip.sig;
  case AG_VOTE_KIND_NOTAR_FALLBACK: return self->notar_fallback.sig;
  case AG_VOTE_KIND_SKIP_FALLBACK:  return self->skip_fallback.sig;
  default:                          __builtin_unreachable();
  }
}

static uchar const *
block_hash( ag_vote_t const * self ) {
  switch( self->kind ) {
  case AG_VOTE_KIND_NOTAR:          return ag_vote_notar_block_hash( &self->notar );
  case AG_VOTE_KIND_FINAL:          return NULL;
  case AG_VOTE_KIND_SKIP:           return NULL;
  case AG_VOTE_KIND_NOTAR_FALLBACK: return ag_vote_notar_fallback_block_hash( &self->notar_fallback );
  case AG_VOTE_KIND_SKIP_FALLBACK:  return NULL;
  default:                          __builtin_unreachable();
  }
}

ulong
ag_vote_ser( ag_vote_t const * self,
             ushort            shred_version,
             uchar             buf[ static AG_VOTE_SER_SZ( 1 ) ] ) {
  ag_vote_serde_t vote;

  vote.version       = (uchar)1;
  vote.tag           = (uchar)( self->kind+AG_VOTE_SERDE_TAG_NOTAR );
  vote.slot          = ag_vote_slot( self );
  vote.block_id      = block_hash( self );
  vote.signature     = sig( self );
  vote.shred_version = shred_version;

  ulong off = 0UL;
  buf[ off ] = vote.version;                                                       off += sizeof(uchar);
  buf[ off ] = vote.tag;                                                           off += sizeof(uchar);
  FD_STORE( ulong, buf+off, vote.slot );                                           off += sizeof(ulong);
  if( vote.block_id ) { memcpy( buf+off, vote.block_id, sizeof(ag_block_hash_t) ); off += sizeof(ag_block_hash_t); }
  memcpy( buf+off, vote.signature, AG_BLS_SIG_SZ );                                off += AG_BLS_SIG_SZ;
  FD_STORE( ushort, buf+off, vote.shred_version );                                 off += sizeof(ushort);

  return off;
}

int
ag_vote_de( ag_vote_t *   self,
            ushort        shred_version,
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
  if( has_block_id ) {
    vote.block_id    = buf+off;                    off += sizeof(ag_block_hash_t);
  }
  vote.signature     = buf+off;                    off += AG_BLS_SIG_SZ;
  vote.shred_version = FD_LOAD( ushort, buf+off ); off += sizeof(ushort);
  FAIL( vote.shred_version!=shred_version, SHRED_VERSION );

  fd_memset( self, 0, sizeof(ag_vote_t) );
  self->kind = kind;

  ag_vote_set_rank( self, USHORT_MAX ); /* FIXME */

  switch( kind ) {
  case AG_VOTE_KIND_NOTAR:
    self->notar.slot = vote.slot;
    memcpy( self->notar.block_hash, vote.block_id, sizeof(ag_block_hash_t) );
    memcpy( self->notar.sig, vote.signature, AG_BLS_SIG_SZ );
    break;
  case AG_VOTE_KIND_FINAL:
    self->final.slot = vote.slot;
    memcpy( self->final.sig, vote.signature, AG_BLS_SIG_SZ );
    break;
  case AG_VOTE_KIND_SKIP:
    self->skip.slot = vote.slot;
    memcpy( self->skip.sig, vote.signature, AG_BLS_SIG_SZ );
    break;
  case AG_VOTE_KIND_NOTAR_FALLBACK:
    self->notar_fallback.slot = vote.slot;
    memcpy( self->notar_fallback.block_hash, vote.block_id, sizeof(ag_block_hash_t) );
    memcpy( self->notar_fallback.sig, vote.signature, AG_BLS_SIG_SZ );
    break;
  case AG_VOTE_KIND_SKIP_FALLBACK:
    self->skip_fallback.slot = vote.slot;
    memcpy( self->skip_fallback.sig, vote.signature, AG_BLS_SIG_SZ );
    break;
  default:
    return AG_VOTE_DE_ERR_INVAL;
  }

  return AG_VOTE_DE_SUCCESS;
}

ulong
ag_vote_signing_ser( ag_vote_t const * self,
                     ushort            shred_version,
                     uchar             buf[ static AG_VOTE_SIGNING_SER_MAX ] ) {
  uchar const * hash = block_hash( self );

  ulong off = 0UL;
  buf[ off ] = (uchar)( self->kind+AG_VOTE_SERDE_TAG_NOTAR );    off += sizeof(uchar);
  FD_STORE( ulong, buf+off, ag_vote_slot( self ) );              off += sizeof(ulong);
  if( hash ) { memcpy( buf+off, hash, sizeof(ag_block_hash_t) ); off += sizeof(ag_block_hash_t); }
  FD_STORE( ushort, buf+off, shred_version );                    off += sizeof(ushort);
  return off;
}

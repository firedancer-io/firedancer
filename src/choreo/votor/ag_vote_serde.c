#include "ag_vote_serde.h"

FD_STATIC_ASSERT( sizeof(ag_vote_signature_serde_t)==AG_BLS_SIG_SZ+2UL,                                              ag_vote_serde );
FD_STATIC_ASSERT( sizeof(ag_vote_serde_t          )==10UL+sizeof(ag_block_hash_t)+sizeof(ag_vote_signature_serde_t), ag_vote_serde );

static uchar const *
sig( ag_vote_t const * self ) {
  switch( self->kind ) {
  case AG_VOTE_KIND_NOTAR:          return self->notar.sig;
  case AG_VOTE_KIND_NOTAR_FALLBACK: return self->notar_fallback.sig;
  case AG_VOTE_KIND_SKIP:           return self->skip.sig;
  case AG_VOTE_KIND_SKIP_FALLBACK:  return self->skip_fallback.sig;
  default:                          return self->final.sig;
  }
}

/* NULL for the kinds whose wire form carries no block id */

static uchar const *
block_hash( ag_vote_t const * self ) {
  switch( self->kind ) {
  case AG_VOTE_KIND_NOTAR:          return ag_vote_notar_block_hash( &self->notar );
  case AG_VOTE_KIND_NOTAR_FALLBACK: return ag_vote_notar_fallback_block_hash( &self->notar_fallback );
  default:                          return NULL;
  }
}

int
ag_vote_ser( ag_vote_t const * self,
             ushort            shred_version,
             uchar *           buf,
             ulong             buf_max,
             ulong *           buf_sz ) {
  uchar const * block_id = block_hash( self );
  ulong         sz       = sizeof(ag_vote_serde_t) - ( block_id ? 0UL : sizeof(ag_block_hash_t) );
  if( FD_UNLIKELY( buf_max<sz ) ) return -1;

  ag_vote_serde_t *           out       = (ag_vote_serde_t *)buf;
  ag_vote_signature_serde_t * signature = block_id ? &out->block_vote.signature : &out->slot_vote.signature;

  out->version = (uchar)1;
  out->kind    = (uchar)( self->kind+1U );
  out->slot    = ag_vote_slot( self );
  if( block_id ) memcpy( out->block_vote.block_id, block_id, sizeof(ag_block_hash_t) );
  fd_memcpy( signature->signature, sig( self ), AG_BLS_SIG_SZ );
  signature->shred_version = shred_version;

  if( buf_sz ) *buf_sz = sz;
  return 0;
}

int
ag_vote_de( ag_vote_t *   self,
            ushort        shred_version,
            uchar const * buf,
            ulong         buf_max,
            ulong *       buf_sz ) {
  if( FD_UNLIKELY( buf_max<2UL ) ) return AG_VOTE_DE_ERR_TRUNCATED;

  ag_vote_serde_t const * vote = (ag_vote_serde_t const *)buf;
  if( FD_UNLIKELY( vote->version!=1 ) ) return AG_VOTE_DE_ERR_UNSUPPORTED;

  uint kind;
  switch( vote->kind ) {
  case 1: kind = AG_VOTE_KIND_NOTAR;          break;
  case 2: kind = AG_VOTE_KIND_FINAL;          break;
  case 3: kind = AG_VOTE_KIND_SKIP;           break;
  case 4: kind = AG_VOTE_KIND_NOTAR_FALLBACK; break;
  case 5: kind = AG_VOTE_KIND_SKIP_FALLBACK;  break;
  case 6: return AG_VOTE_DE_ERR_UNSUPPORTED;
  default: return AG_VOTE_DE_ERR_MALFORMED;
  }

  int   has_block_id = kind==AG_VOTE_KIND_NOTAR || kind==AG_VOTE_KIND_NOTAR_FALLBACK;
  ulong sz           = sizeof(ag_vote_serde_t) - ( has_block_id ? 0UL : sizeof(ag_block_hash_t) );
  if( FD_UNLIKELY( buf_max<sz ) ) return AG_VOTE_DE_ERR_TRUNCATED;

  ag_vote_signature_serde_t const * signature = has_block_id ? &vote->block_vote.signature : &vote->slot_vote.signature;
  if( FD_UNLIKELY( signature->shred_version!=shred_version ) ) return AG_VOTE_DE_ERR_SHRED_VERSION;

  fd_memset( self, 0, sizeof(ag_vote_t) );
  self->kind = kind;

  ag_vote_set_rank( self, USHORT_MAX ); /* FIXME */

  switch( kind ) {
  case AG_VOTE_KIND_NOTAR:
    self->notar.slot = vote->slot;
    memcpy( self->notar.block_hash, vote->block_vote.block_id, sizeof(ag_block_hash_t) );
    fd_memcpy( self->notar.sig, signature->signature, AG_BLS_SIG_SZ );
    break;
  case AG_VOTE_KIND_NOTAR_FALLBACK:
    self->notar_fallback.slot = vote->slot;
    memcpy( self->notar_fallback.block_hash, vote->block_vote.block_id, sizeof(ag_block_hash_t) );
    fd_memcpy( self->notar_fallback.sig, signature->signature, AG_BLS_SIG_SZ );
    break;
  case AG_VOTE_KIND_SKIP:
    self->skip.slot = vote->slot;
    fd_memcpy( self->skip.sig, signature->signature, AG_BLS_SIG_SZ );
    break;
  case AG_VOTE_KIND_SKIP_FALLBACK:
    self->skip_fallback.slot = vote->slot;
    fd_memcpy( self->skip_fallback.sig, signature->signature, AG_BLS_SIG_SZ );
    break;
  default:
    self->final.slot = vote->slot;
    fd_memcpy( self->final.sig, signature->signature, AG_BLS_SIG_SZ );
    break;
  }

  if( buf_sz ) *buf_sz = sz;
  return AG_VOTE_DE_SUCCESS;
}

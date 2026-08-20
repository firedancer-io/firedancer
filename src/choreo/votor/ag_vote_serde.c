#include "ag_vote_serde.h"

FD_STATIC_ASSERT( sizeof(ag_vote_signature_serde_t)==AG_BLS_SIG_SZ+2UL,                                     ag_vote_serde );
FD_STATIC_ASSERT( sizeof(ag_vote_serde_t          )==10UL+sizeof(fd_hash_t)+sizeof(ag_vote_signature_serde_t), ag_vote_serde );

static uchar const *
vote_signature( ag_vote_t const * self ) {
  switch( self->kind ) {
  case AG_VOTE_TYPE_NOTAR:          return self->inner.notar.sig;
  case AG_VOTE_TYPE_NOTAR_FALLBACK: return self->inner.notar_fallback.sig;
  case AG_VOTE_TYPE_SKIP:           return self->inner.skip.sig;
  case AG_VOTE_TYPE_SKIP_FALLBACK:  return self->inner.skip_fallback.sig;
  default:                          return self->inner.final.sig;
  }
}

int
ag_vote_ser( ag_vote_t const * self,
             ushort            shred_version,
             uchar *           buf,
             ulong             buf_max,
             ulong *           buf_sz ) {
  fd_hash_t const * block_id = ag_vote_block_hash( self );
  ulong             sz       = sizeof(ag_vote_serde_t) - ( block_id ? 0UL : sizeof(fd_hash_t) );
  if( FD_UNLIKELY( buf_max<sz ) ) return -1;

  ag_vote_serde_t *           out       = (ag_vote_serde_t *)buf;
  ag_vote_signature_serde_t * signature = block_id ? &out->block_vote.signature : &out->slot_vote.signature;

  out->version = (uchar)1;
  out->kind    = (uchar)( self->kind+1U );
  out->slot    = ag_vote_slot( self );
  if( block_id ) out->block_vote.block_id = *block_id;
  fd_memcpy( signature->signature, vote_signature( self ), AG_BLS_SIG_SZ );
  signature->shred_version = shred_version;

  if( buf_sz ) *buf_sz = sz;
  return 0;
}

int
ag_vote_de( ag_vote_t *   out,
            ushort        shred_version,
            uchar const * buf,
            ulong         buf_max,
            ulong *       buf_sz ) {
  if( FD_UNLIKELY( buf_max<2UL ) ) return AG_VOTE_DE_ERR_TRUNCATED;

  ag_vote_serde_t const * vote = (ag_vote_serde_t const *)buf;
  if( FD_UNLIKELY( vote->version!=1 ) ) return AG_VOTE_DE_ERR_UNSUPPORTED;

  uint kind;
  switch( vote->kind ) {
  case 1: kind = AG_VOTE_TYPE_NOTAR;          break;
  case 2: kind = AG_VOTE_TYPE_FINAL;          break;
  case 3: kind = AG_VOTE_TYPE_SKIP;           break;
  case 4: kind = AG_VOTE_TYPE_NOTAR_FALLBACK; break;
  case 5: kind = AG_VOTE_TYPE_SKIP_FALLBACK;  break;
  case 6: return AG_VOTE_DE_ERR_UNSUPPORTED;
  default: return AG_VOTE_DE_ERR_MALFORMED;
  }

  int   has_block_id = kind==AG_VOTE_TYPE_NOTAR || kind==AG_VOTE_TYPE_NOTAR_FALLBACK;
  ulong sz           = sizeof(ag_vote_serde_t) - ( has_block_id ? 0UL : sizeof(fd_hash_t) );
  if( FD_UNLIKELY( buf_max<sz ) ) return AG_VOTE_DE_ERR_TRUNCATED;

  ag_vote_signature_serde_t const * signature = has_block_id ? &vote->block_vote.signature : &vote->slot_vote.signature;
  if( FD_UNLIKELY( signature->shred_version!=shred_version ) ) return AG_VOTE_DE_ERR_SHRED_VERSION;

  fd_memset( out, 0, sizeof(ag_vote_t) );
  out->kind = kind;

  ag_vote_set_signer( out, USHORT_MAX ); /* FIXME */

  switch( kind ) {
  case AG_VOTE_TYPE_NOTAR:
    out->inner.notar.slot       = vote->slot;
    out->inner.notar.block_hash = vote->block_vote.block_id;
    fd_memcpy( out->inner.notar.sig, signature->signature, AG_BLS_SIG_SZ );
    break;
  case AG_VOTE_TYPE_NOTAR_FALLBACK:
    out->inner.notar_fallback.slot       = vote->slot;
    out->inner.notar_fallback.block_hash = vote->block_vote.block_id;
    fd_memcpy( out->inner.notar_fallback.sig, signature->signature, AG_BLS_SIG_SZ );
    break;
  case AG_VOTE_TYPE_SKIP:
    out->inner.skip.slot = vote->slot;
    fd_memcpy( out->inner.skip.sig, signature->signature, AG_BLS_SIG_SZ );
    break;
  case AG_VOTE_TYPE_SKIP_FALLBACK:
    out->inner.skip_fallback.slot = vote->slot;
    fd_memcpy( out->inner.skip_fallback.sig, signature->signature, AG_BLS_SIG_SZ );
    break;
  default:
    out->inner.final.slot = vote->slot;
    fd_memcpy( out->inner.final.sig, signature->signature, AG_BLS_SIG_SZ );
    break;
  }

  if( buf_sz ) *buf_sz = sz;
  return AG_VOTE_DE_SUCCESS;
}

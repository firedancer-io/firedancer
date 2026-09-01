#include "fd_reward_cert.h"

#include "../../ballet/bls/fd_bls12_381.h"

int
fd_reward_cert_from_agg( fd_reward_cert_t *   cert,
                         ulong                slot,
                         uchar const *        block_hash,
                         ag_bls_agg_t const * agg ) {
  ulong last = signer_set_last( agg->bitmask );
  if( FD_UNLIKELY( last>=AG_VAT_MAX ) ) return 0; /* nobody signed, or a rank the footer cannot name */

  fd_memset( cert, 0, sizeof(fd_reward_cert_t) );
  cert->slot  = slot;
  cert->nbits = (ushort)( last+1UL );
  if( block_hash ) memcpy( cert->block_id.uc, block_hash, sizeof(fd_hash_t) );
  memcpy( cert->signer_set, agg->bitmask, sizeof(cert->signer_set) );
  return !fd_bls12_381_g2_compress( cert->sig, agg->sig, 1 );
}

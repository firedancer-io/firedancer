#include "fd_block_marker.h"

int
fd_block_footer_cert_from_agg( fd_block_footer_cert_t * cert,
                               ulong                    slot,
                               uchar const *            block_hash,
                               ag_bls_agg_t const *     agg ) {
  if( FD_UNLIKELY( ag_bls_set_is_null( agg->set ) ) ) return 0; /* nobody signed */

  fd_memset( cert, 0, sizeof(fd_block_footer_cert_t) );
  cert->slot  = slot;
  cert->nbits = (ushort)( ag_bls_set_last( agg->set )+1UL );
  if( block_hash ) memcpy( cert->block_id.uc, block_hash, sizeof(fd_hash_t) );
  ag_bls_set_copy( cert->signer_set, agg->set );
  blst_p2_affine a[1];
  blst_p2_to_affine( a, &agg->sig );
  blst_p2_affine_compress( cert->sig, a );
  return 1;
}

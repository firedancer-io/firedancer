#include "fd_gossip_private.h"

void
fd_gossip_generate_crds_value_hash( fd_sha256_t * sha,
                       uchar const * crds_value,
                       ulong         crds_value_sz,
                       uchar         out_hash[ static 32UL ] ) {
  fd_sha256_init( sha );
  fd_sha256_append( sha, crds_value, crds_value_sz );
  fd_sha256_fini( sha, out_hash );
}

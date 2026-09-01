#include "fd_epoch_stakes_digest.h"
#include "../runtime/fd_runtime_const.h"
#include "../../ballet/sha256/fd_sha256.h"

void
fd_epoch_stakes_digest( fd_vote_stake_weight_t * entries,
                        ulong                    entry_cnt,
                        ulong                    epoch,
                        fd_hash_t *              hash_out ) {

  sort_vote_weights_by_vote_key_inplace( entries, entry_cnt );

  fd_sha256_t sha[1];
  fd_sha256_init( sha );

  ulong hdr[2];
  FD_STORE( ulong, &hdr[0], epoch     );
  FD_STORE( ulong, &hdr[1], entry_cnt );
  fd_sha256_append( sha, hdr, sizeof(hdr) );

  for( ulong i=0UL; i<entry_cnt; i++ ) {
    fd_vote_stake_weight_t const * ele = &entries[ i ];
    ulong stake_le[1];
    FD_STORE( ulong, stake_le, ele->stake );
    fd_sha256_append( sha, ele->vote_key.uc, sizeof(fd_pubkey_t) );
    fd_sha256_append( sha, ele->id_key.uc,   sizeof(fd_pubkey_t) );
    fd_sha256_append( sha, stake_le,         sizeof(ulong)       );
  }

  fd_sha256_fini( sha, hash_out->hash );
}

void
fd_epoch_stakes_digest_tier( fd_vote_stakes_t const * vote_stakes,
                             ulong                    fork_id,
                             int                      iter_kind,
                             ulong                    epoch,
                             fd_vote_stake_weight_t * scratch,
                             fd_hash_t *              hash_out ) {

  ulong cnt = 0UL;
  uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
  for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, fork_id, iter_kind, iter_mem );
       !fd_vote_stakes_iter_done( vote_stakes, fork_id, iter_kind, iter );
       fd_vote_stakes_iter_next( vote_stakes, fork_id, iter_kind, iter ) ) {
    FD_TEST( cnt<FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS );
    fd_vote_stake_weight_t * ele = &scratch[ cnt++ ];
    fd_vote_stakes_iter_ele( vote_stakes, fork_id, iter_kind, iter,
                             &ele->vote_key, &ele->id_key, &ele->stake,
                             NULL, NULL, NULL, NULL, NULL, NULL );
  }

  fd_epoch_stakes_digest( scratch, cnt, epoch, hash_out );
}

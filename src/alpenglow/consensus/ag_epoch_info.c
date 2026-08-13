#include "ag_epoch_info.h"

#include "../../ballet/bls/fd_bls12_381.h"

void
ag_epoch_info_init( ag_epoch_info_t *           self,
                    ag_validator_info_t const * validators,
                    ulong                       validator_cnt ) {
  FD_TEST( self );
  FD_TEST( validator_cnt>0UL && validator_cnt<=AG_VAT_MAX );

  ulong total = 0UL;
  for( ulong i=0UL; i<validator_cnt; i++ ) {
    FD_TEST( validators[i].id==i );
    self->validators[i] = validators[i];
    total              += validators[i].stake;
  }
  self->validator_cnt = validator_cnt;
  self->total_stake   = total;
}

/* The quorum comparison is cross multiplied in uint128 so it neither
   rounds nor overflows. */

FD_FN_CONST static int
fraction_is_met( ulong stake,
                 ulong total,
                 ulong numer,
                 ulong denom ) {
  return (uint128)stake*(uint128)denom >= (uint128)total*(uint128)numer;
}

FD_FN_PURE int
ag_epoch_info_is_weakest_quorum( ag_epoch_info_t const * self, ulong stake ) {
  return fraction_is_met( stake, self->total_stake, AG_WEAKEST_QUORUM_THRESHOLD_NUMER, AG_QUORUM_THRESHOLD_DENOM );
}

FD_FN_PURE int
ag_epoch_info_is_weak_quorum( ag_epoch_info_t const * self, ulong stake ) {
  return fraction_is_met( stake, self->total_stake, AG_WEAK_QUORUM_THRESHOLD_NUMER, AG_QUORUM_THRESHOLD_DENOM );
}

FD_FN_PURE int
ag_epoch_info_is_quorum( ag_epoch_info_t const * self, ulong stake ) {
  return fraction_is_met( stake, self->total_stake, AG_QUORUM_THRESHOLD_NUMER, AG_QUORUM_THRESHOLD_DENOM );
}

FD_FN_PURE int
ag_epoch_info_is_strong_quorum( ag_epoch_info_t const * self, ulong stake ) {
  return fraction_is_met( stake, self->total_stake, AG_STRONG_QUORUM_THRESHOLD_NUMER, AG_QUORUM_THRESHOLD_DENOM );
}

/* Rank-ordering key: stake descending, tie-broken by the compressed BLS
   pubkey ascending.  bls points into the caller's pubkey array, which is
   stable for the duration of the sort. */

struct ei_rank { ulong stake; uchar const * bls; ulong src; };
typedef struct ei_rank ei_rank_t;

#define SORT_NAME        ei_rank_sort
#define SORT_KEY_T       ei_rank_t
#define SORT_BEFORE(a,b) ( (a).stake>(b).stake ||                                            \
                           ( (a).stake==(b).stake &&                                         \
                             memcmp( (a).bls, (b).bls, AG_AGGSIG_PUBKEY_COMPRESSED_SZ )<0 ) )
#include "../../util/tmpl/fd_sort.c"

ulong
ag_epoch_info_rank( ag_validator_info_t *          out,
                    ulong                          out_max,
                    fd_vote_stake_weight_t const * stakes,
                    ulong                          stake_cnt,
                    uchar const *                  bls_pubkeys ) {
  ei_rank_t rank[ AG_AGGSIG_MAX_SIGNERS ]; /* surviving validators, pre-sort */
  ulong     in_cnt = fd_ulong_min( stake_cnt, AG_AGGSIG_MAX_SIGNERS );
  ulong     m      = 0UL;
  for( ulong i=0UL; i<in_cnt; i++ ) {
    if( FD_UNLIKELY( stakes[i].stake==0UL ) ) continue;
    uchar const * bls = bls_pubkeys + i*AG_AGGSIG_PUBKEY_COMPRESSED_SZ;
    ag_aggsig_pk_t probe;
    if( FD_UNLIKELY( fd_bls12_381_g1_decompress_syscall( probe.v, bls, 1 ) ) ) continue; /* no / invalid BLS key */
    rank[m].stake = stakes[i].stake;
    rank[m].bls   = bls;
    rank[m].src   = i;
    m++;
  }
  ei_rank_sort_inplace( rank, m );

  ulong cnt = fd_ulong_min( m, out_max );
  for( ulong r=0UL; r<cnt; r++ ) {
    ulong                 src = rank[r].src;
    ag_validator_info_t * vi  = out + r;
    memset( vi, 0, sizeof(ag_validator_info_t) );
    vi->id     = r;
    vi->stake  = stakes[src].stake;
    vi->pubkey = stakes[src].id_key;
    if( FD_UNLIKELY( fd_bls12_381_g1_decompress_syscall( vi->voting_pubkey.v,
                                                         bls_pubkeys + src*AG_AGGSIG_PUBKEY_COMPRESSED_SZ,
                                                         1 /* big endian */ ) ) ) {
      FD_LOG_CRIT(( "BLS voting pubkey for source %lu failed to decompress after the filter", src ));
    }
  }
  return cnt;
}

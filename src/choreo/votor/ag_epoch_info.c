#include "ag_epoch_info.h"

void
ag_epoch_info( ag_epoch_info_t *           self,
               ag_validator_info_t const * validators,
               ulong                       validator_cnt ) {
  self->total_stake = 0UL;
  for( ulong i=0UL; i<validator_cnt; i++ ) {
    FD_TEST( validators[i].id==i );
    self->validators[i] = validators[i];
    FD_TEST( !ag_bls_pub_native_from_bytes( self->pubkeys+i, &validators[i].bls_key ) );
    self->total_stake += validators[i].stake;
  }
  self->validator_cnt = validator_cnt;
  ag_bls_pub_cache_init( &self->pubkey_cache, self->pubkeys, validator_cnt );
}

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

struct epoch_info_rank { ulong stake; uchar const * bls; uchar const * id; ulong src; ulong drop; ag_bls_pub_t pk; };
typedef struct epoch_info_rank epoch_info_rank_t;

#define SORT_NAME        epoch_info_rank_sort
#define SORT_KEY_T       epoch_info_rank_t
#define SORT_BEFORE(a,b) ( (a).stake>(b).stake ||                                            \
                          ( (a).stake==(b).stake &&                                         \
                            memcmp( (a).bls, (b).bls, AG_BLS_PUB_COMPRESSED_SZ )<0 ) )
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME        epoch_info_bls_sort
#define SORT_KEY_T       epoch_info_rank_t
#define SORT_BEFORE(a,b) ( memcmp( (a).bls, (b).bls, AG_BLS_PUB_COMPRESSED_SZ )<0 )
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME        epoch_info_id_sort
#define SORT_KEY_T       epoch_info_rank_t
#define SORT_BEFORE(a,b) ( memcmp( (a).id, (b).id, sizeof(fd_pubkey_t) )<0 )
#include "../../util/tmpl/fd_sort.c"

FD_STATIC_ASSERT( sizeof(((fd_vote_stake_weight_t *)0)->bls_key)==AG_BLS_PUB_COMPRESSED_SZ, bls_key_sz );

ag_epoch_info_t *
ag_epoch_info_rank( ag_epoch_info_t *              mem,
                    fd_vote_stake_weight_t const * stakes,
                    ulong                          stake_cnt ) {
  epoch_info_rank_t rank[ AG_VAT_MAX ]; /* surviving validators, pre-sort */
  ulong     in_cnt = fd_ulong_min( stake_cnt, AG_VAT_MAX );
  ulong     m      = 0UL;
  for( ulong i=0UL; i<in_cnt; i++ ) {
    if( FD_UNLIKELY( !stakes[i].stake ) ) continue; /* re-check nonzero stake, in case stakes came verbatim from a snapshot */
    uchar const * bls = stakes[i].bls_key;
#if FD_HAS_BLST
    if( FD_UNLIKELY( ag_bls_pub_try_from_bytes( &rank[m].pk, bls, AG_BLS_PUB_COMPRESSED_SZ ) ) ) continue; /* no / invalid BLS key */
#else
    memset( &rank[m].pk, 0, sizeof(ag_bls_pub_t) );
    fd_memcpy( rank[m].pk.bytes, bls, AG_BLS_PUB_COMPRESSED_SZ ); /* stub builds do not verify signatures */
#endif
    rank[m].stake = stakes[i].stake;
    rank[m].bls   = bls;
    rank[m].id    = stakes[i].id_key.uc;
    rank[m].src   = i;
    rank[m].drop  = 0UL;
    m++;
  }

  /* ALL copies of a duplicated BLS key or identity are dropped.  Sort
     by each key so duplicates are adjacent, then mark adjacent-equal
     runs. */

  epoch_info_bls_sort_inplace( rank, m );
  for( ulong i=1UL; i<m; i++ ) {
    if( FD_UNLIKELY( !memcmp( rank[i].bls, rank[i-1UL].bls, AG_BLS_PUB_COMPRESSED_SZ ) ) ) {
      rank[i].drop = rank[i-1UL].drop = 1UL;
    }
  }

  epoch_info_id_sort_inplace( rank, m );
  for( ulong i=1UL; i<m; i++ ) {
    if( FD_UNLIKELY( !memcmp( rank[i].id, rank[i-1UL].id, sizeof(fd_pubkey_t) ) ) ) {
      rank[i].drop = rank[i-1UL].drop = 1UL;
    }
  }

  ulong k = 0UL;
  for( ulong i=0UL; i<m; i++ ) if( FD_LIKELY( !rank[i].drop ) ) rank[k++] = rank[i];

  if( FD_UNLIKELY( !k ) ) { FD_LOG_WARNING(( "no validators survived ranking" )); return NULL; }

  epoch_info_rank_sort_inplace( rank, k );

  ag_epoch_info_t * epoch_info = mem;

  ulong total = 0UL;
  for( ulong r=0UL; r<k; r++ ) {
    ulong                 src = rank[r].src;
    ag_validator_info_t * vi  = epoch_info->validators + r;
    memset( vi, 0, sizeof(ag_validator_info_t) );
    vi->id    = r;
    vi->stake = stakes[src].stake;
    fd_memcpy( vi->id_key,   stakes[src].id_key.uc,   sizeof(ag_id_key_t)   );
    fd_memcpy( vi->vote_key, stakes[src].vote_key.uc, sizeof(ag_vote_key_t) );
    vi->bls_key            = rank[r].pk;
    FD_TEST( !ag_bls_pub_native_from_bytes( epoch_info->pubkeys+r, &rank[r].pk ) );
    total += vi->stake;
  }
  epoch_info->validator_cnt = k;
  epoch_info->total_stake   = total;
  ag_bls_pub_cache_init( &epoch_info->pubkey_cache, epoch_info->pubkeys, k );
  return mem;
}

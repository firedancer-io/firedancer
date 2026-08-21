#include "ag_epoch_info.h"

void
ag_epoch_info( ag_epoch_info_t *           self,
               ag_validator_info_t const * validators,
               ulong                       validator_cnt ) {
  self->total_stake = 0UL;
  for( ulong i=0UL; i<validator_cnt; i++ ) {
    FD_TEST( validators[i].id==i );
    self->validators[i] = validators[i];
    self->total_stake += validators[i].stake;
  }
  self->validator_cnt = validator_cnt;
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

#if FD_HAS_BLST
#include "../../ballet/bls/fd_bls12_381.h"
#endif

/* Rank-ordering key: stake descending, tie-broken by the compressed BLS
   pubkey ascending.  bls/id point into the caller's stakes array, which
   is stable for the duration of the sorts.  pk carries the decompressed
   voting pubkey from the filter pass so it is decompressed only once. */

struct ei_rank { ulong stake; uchar const * bls; uchar const * id; ulong src; ulong drop; ag_bls_pub_t pk; };
typedef struct ei_rank ei_rank_t;

#define SORT_NAME        ei_rank_sort
#define SORT_KEY_T       ei_rank_t
#define SORT_BEFORE(a,b) ( (a).stake>(b).stake ||                                            \
                          ( (a).stake==(b).stake &&                                         \
                            memcmp( (a).bls, (b).bls, AG_BLS_PUB_COMPRESSED_SZ )<0 ) )
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME        ei_bls_sort
#define SORT_KEY_T       ei_rank_t
#define SORT_BEFORE(a,b) ( memcmp( (a).bls, (b).bls, AG_BLS_PUB_COMPRESSED_SZ )<0 )
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME        ei_id_sort
#define SORT_KEY_T       ei_rank_t
#define SORT_BEFORE(a,b) ( memcmp( (a).id, (b).id, sizeof(fd_pubkey_t) )<0 )
#include "../../util/tmpl/fd_sort.c"

FD_STATIC_ASSERT( sizeof(((fd_vote_stake_weight_t *)0)->bls_key)==AG_BLS_PUB_COMPRESSED_SZ, bls_key_sz );

ag_epoch_info_t *
ag_epoch_info_init( ag_epoch_info_t *              mem,
                    fd_vote_stake_weight_t const * stakes,
                    ulong                          stake_cnt ) {
  /* Drop entries whose compressed BLS voting pubkey is missing or does
     not decode to a valid G1 point.  The producer already guarantees
     nonzero stake and VAT admission (fd_stakes_activate_epoch), so
     those are not re-checked. */

  ei_rank_t rank[ AG_VAT_MAX ]; /* surviving validators, pre-sort */
  ulong     in_cnt = fd_ulong_min( stake_cnt, AG_VAT_MAX );
  ulong     m      = 0UL;
  for( ulong i=0UL; i<in_cnt; i++ ) {
    if( FD_UNLIKELY( !stakes[i].stake ) ) continue; /* re-check nonzero stake, in case stakes came verbatim from a snapshot */
    uchar const * bls = stakes[i].bls_key;
#if FD_HAS_BLST
    if( FD_UNLIKELY( fd_bls12_381_g1_decompress_syscall( rank[m].pk, bls, 1 ) ) ) continue; /* no / invalid BLS key */
#else
    memset( &rank[m].pk, 0, sizeof(ag_bls_pub_t) );
    fd_memcpy( rank[m].pk, bls, AG_BLS_PUB_COMPRESSED_SZ ); /* stub builds do not verify signatures */
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

  ei_bls_sort_inplace( rank, m );
  for( ulong i=1UL; i<m; i++ ) {
    if( FD_UNLIKELY( !memcmp( rank[i].bls, rank[i-1UL].bls, AG_BLS_PUB_COMPRESSED_SZ ) ) ) {
      rank[i].drop = rank[i-1UL].drop = 1UL;
    }
  }

  ei_id_sort_inplace( rank, m );
  for( ulong i=1UL; i<m; i++ ) {
    if( FD_UNLIKELY( !memcmp( rank[i].id, rank[i-1UL].id, sizeof(fd_pubkey_t) ) ) ) {
      rank[i].drop = rank[i-1UL].drop = 1UL;
    }
  }

  ulong k = 0UL;
  for( ulong i=0UL; i<m; i++ ) if( FD_LIKELY( !rank[i].drop ) ) rank[k++] = rank[i];

  if( FD_UNLIKELY( !k ) ) { FD_LOG_WARNING(( "no validators survived ranking" )); return NULL; }

  ei_rank_sort_inplace( rank, k );

  ag_epoch_info_t * ei = mem;

  ulong total = 0UL;
  for( ulong r=0UL; r<k; r++ ) {
    ulong                 src = rank[r].src;
    ag_validator_info_t * vi  = ei->validators + r;
    memset( vi, 0, sizeof(ag_validator_info_t) );
    vi->id    = r;
    vi->stake = stakes[src].stake;
    fd_memcpy( vi->id_key,   stakes[src].id_key.uc,   sizeof(ag_id_key_t)   );
    fd_memcpy( vi->vote_key, stakes[src].vote_key.uc, sizeof(ag_vote_key_t) );
    fd_memcpy( vi->bls_key,  rank[r].pk,              sizeof(ag_bls_pub_t)  );
    fd_memcpy( ei->pubkeys[ r ], rank[r].pk,          sizeof(ag_bls_pub_t)  );
    total += vi->stake;
  }
  ei->validator_cnt = k;
  ei->total_stake   = total;
  return mem;
}

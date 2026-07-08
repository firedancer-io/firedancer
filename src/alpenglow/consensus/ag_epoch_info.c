#include "ag_epoch_info.h"

ulong
ag_epoch_info_align( void ) {
  return alignof(ag_epoch_info_t);
}

ulong
ag_epoch_info_footprint( ulong validator_cnt ) {

  return sizeof(ag_epoch_info_t)
       + validator_cnt*sizeof(ag_validator_info_t)
       + validator_cnt*sizeof(ag_aggsig_pk_t);
}

void *
ag_epoch_info_new( void *                      mem,
                   ag_validator_info_t const * validators,
                   ulong                       validator_cnt ) {
  if( FD_UNLIKELY( !mem ) ) { FD_LOG_WARNING(( "NULL mem" )); return NULL; }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, ag_epoch_info_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" )); return NULL;
  }
  FD_TEST( validator_cnt>0UL );

  ag_epoch_info_t *     ei  = (ag_epoch_info_t *)mem;
  ag_validator_info_t * v   = (ag_validator_info_t *)(ei+1);
  ag_aggsig_pk_t *      vpk = (ag_aggsig_pk_t *)(v+validator_cnt);

  ulong total = 0UL;
  for( ulong i=0UL; i<validator_cnt; i++ ) {
    FD_TEST( validators[i].id==i );
    v[i]   = validators[i];
    vpk[i] = validators[i].voting_pubkey;
    total += validators[i].stake;
  }
  ei->validator_cnt = validator_cnt;
  ei->total_stake   = total;
  return mem;
}

ag_epoch_info_t *
ag_epoch_info_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) { FD_LOG_WARNING(( "NULL mem" )); return NULL; }
  return (ag_epoch_info_t *)mem;
}

#if FD_HAS_BLST
#include "../../ballet/bls/fd_bls12_381.h"
#endif

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
#if FD_HAS_BLST
    ag_aggsig_pk_t probe;
    if( FD_UNLIKELY( fd_bls12_381_g1_decompress_syscall( probe.v, bls, 1 ) ) ) continue; /* no / invalid BLS key */
#endif
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
#if FD_HAS_BLST
    if( FD_UNLIKELY( fd_bls12_381_g1_decompress_syscall( vi->voting_pubkey.v,
                                                         bls_pubkeys + src*AG_AGGSIG_PUBKEY_COMPRESSED_SZ,
                                                         1 /* big endian */ ) ) ) {
      FD_LOG_CRIT(( "BLS voting pubkey for source %lu failed to decompress after the filter", src ));
    }
#else
    fd_memcpy( vi->voting_pubkey.v, bls_pubkeys + src*AG_AGGSIG_PUBKEY_COMPRESSED_SZ,
               AG_AGGSIG_PUBKEY_COMPRESSED_SZ ); /* stub builds do not verify signatures */
#endif
  }
  return cnt;
}

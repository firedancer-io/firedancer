#include "fd_ssmanifest_writer.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/program/vote/fd_vote_state_versioned.h"
#include "../../ballet/bls/fd_bls.h"

#define SORT_NAME        sort_epoch_vote_by_node
#define SORT_KEY_T       fd_ssmanifest_epoch_vote_t
#define SORT_BEFORE(a,b) (0>memcmp( (a).node.uc, (b).node.uc, sizeof(fd_pubkey_t) ))
#include "../../util/tmpl/fd_sort.c"

#define STATE_BLOCKHASH_QUEUE        1
#define STATE_HASHES                 2
#define STATE_HARD_FORKS             3
#define STATE_COUNTERS               4
#define STATE_VOTE_ACCOUNTS          5
#define STATE_STAKE_DELEGATION       6
#define STATE_STAKE_EPOCH            7
#define STATE_STAKE_HISTORY          8
#define STATE_BANK_TRAILER           9
#define STATE_ACCOUNT_STORAGE_ENTRY 10
#define STATE_BANK_HASH_INFO        11
#define STATE_EPOCH_STAKES          12
#define STATE_EPOCH_STAKES_STAKES   13
#define STATE_EPOCH_STAKES_EPOCH    14
#define STATE_EPOCH_STAKE_HISTORY   15
#define STATE_EPOCH_TOTAL_STAKE     16
#define STATE_NODE_VOTE_ACCOUNTS    17
#define STATE_AUTH_VOTER            18
#define STATE_LTHASH                19
#define STATE_BLOCK_ID              20
#define STATE_DONE                  21
#define STATE_INIT STATE_BLOCKHASH_QUEUE

/* Epoch stakes entries are keyed max(E-3,0)..E+1, as agave retains.
   Key E+1 is the t-1 set with credits, E the t-2 set, E-1..E-3 the
   t-3..t-5 sets. */

static inline ulong
epoch_stakes_key( fd_bank_t const * bank,
                  ulong             epoch_idx ) {
  ulong epoch = bank->f.epoch;
  return ( epoch>3UL ? epoch-3UL : 0UL ) + epoch_idx;
}

static inline int
epoch_stakes_iter_kind( fd_bank_t const * bank,
                        ulong             epoch_idx ) {
  return (int)( bank->f.epoch + 2UL - epoch_stakes_key( bank, epoch_idx ) );
}

static fd_epoch_credits_t const *
find_epoch_credits( fd_ssmanifest_writer_t const * enc,
                    fd_pubkey_t const *            pubkey ) {
  for( ulong i=0UL; i<enc->epoch_credits_cnt; i++ ) {
    fd_epoch_credits_t const * epoch_credits = &enc->epoch_credits[ i ];
    if( fd_memeq( epoch_credits->pubkey, pubkey, sizeof(fd_pubkey_t) ) ) return epoch_credits;
  }
  return NULL;
}

/* Size estimate */

#define ENCODE_FN     static ulong manifest_estimate( fd_ssmanifest_writer_t * enc )
#define PREP          ulong sz = 0UL;
#define PUSH_VAL(t,n) do { sz += sizeof(t); (void)(n); } while(0)
#define RET_EXPR      sz
#include "fd_ssmanifest_encoder.c"

fd_ssmanifest_writer_t *
fd_ssmanifest_writer_init( fd_ssmanifest_writer_t *   enc,
                           fd_bank_t *                bank,
                           fd_pubkey_t const *        leader,
                           fd_epoch_credits_t const * epoch_credits,
                           ulong                      epoch_credits_cnt,
                           fd_accdb_t *               accdb,
                           fd_accdb_fork_id_t         accdb_fork_id,
                           uchar *                    acc_data ) {
  enc->state             = STATE_BLOCKHASH_QUEUE;
  enc->bank              = bank;
  enc->leader            = *leader;
  enc->epoch_credits     = epoch_credits;
  enc->epoch_credits_cnt = epoch_credits_cnt;
  enc->epoch_idx         = 0;
  enc->epoch_cnt   = 0;
  enc->vote_cnt    = 0;
  enc->vote_idx    = 0;
  enc->total_stake = 0UL;

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );
  ulong              fork_id     = bank->vote_stakes_fork_id;
  ulong              epoch_cnt   = fd_ulong_min( bank->f.epoch, 3UL ) + 2UL;
  for( ulong epoch_idx=0UL; epoch_idx<epoch_cnt; epoch_idx++ ) {
    fd_ssmanifest_epoch_map_t * map = &enc->epoch_map[ epoch_idx ];
    ulong epoch_key = epoch_stakes_key( bank, epoch_idx );
    int   iter_kind = epoch_stakes_iter_kind( bank, epoch_idx );

    /* Agave only reads the maps of the previous, current and next
       epoch.  Older sets keep empty maps. */
    map->vote_cnt = 0UL;
    map->node_cnt = 0UL;
    if( iter_kind>FD_VOTE_STAKES_ITER_T_3 ) continue;

    for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, fork_id, iter_kind, enc->vote_stakes_iter_mem );
         !fd_vote_stakes_iter_done( vote_stakes, fork_id, iter_kind, iter );
         fd_vote_stakes_iter_next( vote_stakes, fork_id, iter_kind, iter ) ) {
      fd_ssmanifest_epoch_vote_t * ele = &map->vote[ map->vote_cnt ];
      fd_vote_stakes_iter_ele( vote_stakes, fork_id, iter_kind, iter, &ele->vote, &ele->node, &ele->stake,
                               NULL, NULL, NULL, NULL, NULL, NULL, NULL );

      ulong lamports;
      int   executable;
      uchar owner[ 32UL ];
      ulong data_len;
      fd_accdb_read_one_nocache( accdb, accdb_fork_id, ele->vote.uc, &lamports, &executable, owner, acc_data, &data_len );
      if( FD_UNLIKELY( !lamports ||
                       !fd_vsv_is_correct_size_owner_and_init( owner, acc_data, data_len ) ||
                       fd_vote_account_authorized_voter( acc_data, data_len, epoch_key, &ele->voter ) ) ) {
        continue;
      }
      map->vote_cnt++;
    }

    sort_epoch_vote_by_node_inplace( map->vote, map->vote_cnt );
    for( ulong i=0UL; i<map->vote_cnt; i++ ) {
      int new_node = ( i==0UL ) || !fd_memeq( map->vote[ i ].node.uc, map->vote[ i-1UL ].node.uc, sizeof(fd_pubkey_t) );
      if( new_node ) {
        map->node_cnt++;
      }
    }
  }

  enc->serialized_sz = 0UL;
  for(;;) {
    ulong chunk = manifest_estimate( enc );
    if( FD_UNLIKELY( !chunk ) ) break;
    enc->serialized_sz += chunk;
  }
  return enc;
}

/* Actual encoder */

__attribute__((cold,noreturn))
static void fail( fd_ssmanifest_writer_t const * enc,
                  ulong buf_sz,
                  ulong line_nr ) {
  FD_LOG_ERR(( "buffer overflow (state=%u, buf_sz=%lu, line_nr=%lu)", enc->state, buf_sz, line_nr ));
}

#define ENCODE_FN                                                         \
  ulong                                                                   \
  fd_snap_manifest_serialize( fd_ssmanifest_writer_t * enc,               \
                              uchar out_buf[ FD_SSMANIFEST_BUF_MIN ],     \
                              ulong buf_sz )
#define PREP                                                              \
  uchar * p  = out_buf;                                                   \
  uchar * p1 = out_buf+buf_sz;
#define PUSH_VAL( t, n )                                                  \
  FD_STORE( t, __extension__({                                            \
    /* compile time bounds check elide */                                 \
    if( FD_UNLIKELY( p+sizeof(t) > p1 ) ) fail( enc, buf_sz, __LINE__ );  \
    uchar * ret = p;                                                      \
    p += sizeof(t);                                                       \
    ret;                                                                  \
  }), (n) )
#define RET_EXPR (ulong)( p - out_buf )
#include "fd_ssmanifest_encoder.c"

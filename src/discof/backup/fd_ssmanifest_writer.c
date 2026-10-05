#include "fd_ssmanifest_writer.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/program/fd_vote_program.h"
#include "../../flamenco/runtime/program/vote/fd_vote_state_versioned.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_stake_history.h"
#include "../../flamenco/stakes/fd_stakes.h"
#include "../../ballet/bls/fd_bls.h"

#define MAP_NAME              vote_account_map
#define MAP_T                 fd_ssmanifest_vote_account_t
#define MAP_LG_SLOT_CNT       FD_SSMANIFEST_VOTE_ACCOUNT_LG_SLOT_CNT
#define MAP_KEY_T             fd_pubkey_t
#define MAP_KEY               pubkey
#define MAP_KEY_NULL          ((fd_pubkey_t){0})
#define MAP_KEY_INVAL(k)      (!((k).ul[0]|(k).ul[1]|(k).ul[2]|(k).ul[3]))
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp( (k0).uc, (k1).uc, sizeof(fd_pubkey_t) ))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH(key)     ((uint)fd_hash( 0UL, (key).uc, sizeof(fd_pubkey_t) ))
#include "../../util/tmpl/fd_map.c"

#define SORT_NAME        sort_epoch_vote_by_node
#define SORT_KEY_T       fd_ssmanifest_epoch_vote_t
#define SORT_BEFORE(a,b) (0>memcmp( (a).node.uc, (b).node.uc, sizeof(fd_pubkey_t) ))
#include "../../util/tmpl/fd_sort.c"

#define STATE_BLOCKHASH_QUEUE           1
#define STATE_HASHES                    2
#define STATE_HARD_FORKS                3
#define STATE_COUNTERS                  4
#define STATE_VOTE_ACCOUNTS             5
#define STATE_VOTE_ACCOUNT_ENTRIES      6
#define STATE_STAKE_DELEGATIONS         7
#define STATE_STAKE_DELEGATION_ENTRIES  8
#define STATE_STAKE_HISTORY             9
#define STATE_BANK_TRAILER             10
#define STATE_ACCOUNT_STORAGE_ENTRY    11
#define STATE_BANK_HASH_INFO           12
#define STATE_EPOCH_STAKES             13
#define STATE_EPOCH_STAKES_STAKES      14
#define STATE_EPOCH_STAKES_EPOCH       15
#define STATE_EPOCH_STAKE_HISTORY      16
#define STATE_EPOCH_TOTAL_STAKE        17
#define STATE_NODE_VOTE_ACCOUNTS       18
#define STATE_AUTH_VOTER               19
#define STATE_LTHASH                   20
#define STATE_BLOCK_ID                 21
#define STATE_DONE                     22
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

/* read_vote_account reads pubkey's account into acc_data and returns
   its data length, or 0 if it does not exist or is not a vote account. */

static uint
read_vote_account( fd_accdb_t *        accdb,
                   fd_accdb_fork_id_t  accdb_fork_id,
                   fd_pubkey_t const * pubkey,
                   uchar *             acc_data ) {
  ulong lamports;
  int   executable;
  uchar owner[ 32UL ];
  ulong data_len;
  fd_accdb_read_one_nocache( accdb, accdb_fork_id, pubkey->uc, &lamports, &executable, owner, acc_data, &data_len );
  if( FD_UNLIKELY( !lamports || !fd_vsv_is_correct_size_owner_and_init( owner, acc_data, data_len ) ) ) {
    return 0U;
  }
  return (uint)data_len;
}

static fd_epoch_credits_t const *
find_epoch_credits( fd_bank_t *          bank,
                    fd_pubkey_t const * pubkey ) {
  ulong epoch_credits_len = *fd_bank_epoch_credits_len( bank );
  for( ulong i=0UL; i<epoch_credits_len; i++ ) {
    fd_epoch_credits_t const * epoch_credits = &fd_bank_epoch_credits( bank )[ i ];
    if( fd_memeq( epoch_credits->pubkey, pubkey, sizeof(fd_pubkey_t) ) ) return epoch_credits;
  }
  return NULL;
}

/* Size estimate */

#define ENCODE_FN     static ulong manifest_estimate( fd_ssmanifest_writer_t * enc )
#define PREP          ulong sz = 0UL;
#define PUSH_VAL(t,n)             do { sz += sizeof(t); (void)(n); } while(0)
#define PUSH_BYTES(src,n)         do { sz += (n); (void)(src); } while(0)
#define PUSH_VOTE_ACCOUNT(v)      do { sz += FD_SSMANIFEST_VOTE_ACCOUNT_HDR_SZ+(v)->data_len; } while(0)
#define PUSH_STAKE_DELEGATIONS(n) do { sz += (n)*FD_SSMANIFEST_STAKE_DELEGATION_SZ; } while(0)
#define RET_EXPR      sz
#include "fd_ssmanifest_encoder.c"

fd_ssmanifest_writer_t *
fd_ssmanifest_writer_init( fd_ssmanifest_writer_t * enc,
                           fd_bank_t *              bank,
                           fd_pubkey_t const *      leader,
                           fd_accdb_t *             accdb,
                           fd_accdb_fork_id_t       accdb_fork_id,
                           fd_stake_delegations_t * stake_delegations,
                           uchar *                  acc_data ) {
  enc->state         = STATE_BLOCKHASH_QUEUE;
  enc->bank          = bank;
  enc->leader        = *leader;
  enc->epoch_idx     = 0;
  enc->epoch_cnt     = 0;
  enc->vote_cnt      = 0;
  enc->vote_idx      = 0;
  enc->total_stake   = 0UL;
  enc->accdb         = accdb;
  enc->accdb_fork_id = accdb_fork_id;

  /* Stake history from the bank's sysvar cache */
  enc->stake_history = (fd_stake_history_t){ .entries = NULL, .len = 0UL };
  ulong         stake_history_sz;
  uchar const * stake_history_data = fd_sysvar_cache_data_query( &bank->f.sysvar_cache, fd_sysvar_stake_history_id.uc, &stake_history_sz );
  if( FD_LIKELY( stake_history_data ) ) {
    fd_sysvar_stake_history_view( &enc->stake_history, stake_history_data, stake_history_sz );
  }

  /* Count delegations and sum delegated stake per vote account */
  fd_ssmanifest_vote_account_t * map = vote_account_map_join( vote_account_map_new( enc->vote_account ) );
  ulong map_cnt             = 0UL;
  int   capped              = 0;
  int   use_fixed_point     = FD_FEATURE_ACTIVE_BANK( bank, upgrade_bpf_stake_program_to_v5_1 );
  enc->stake_delegations    = stake_delegations;
  enc->stake_delegation_cnt = 0UL;

  FD_CHECK_CRIT( bank->stake_delegations_fork_id==USHORT_MAX, "snapshot bank is not the root" );
  fd_stake_delegations_view_begin( stake_delegations, bank->f.epoch, &enc->stake_history, &bank->f.warmup_cooldown_rate_epoch, use_fixed_point, USHORT_MAX );

  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * delegation = fd_stake_delegations_iter_ele( iter );
    fd_ssmanifest_vote_account_t * vote_account = vote_account_map_query( map, delegation->vote_account, NULL );
    if( FD_UNLIKELY( !vote_account && map_cnt<FD_RUNTIME_MAX_SNAPSHOT_VOTE_ACCOUNTS ) ) {
      vote_account        = vote_account_map_insert( map, delegation->vote_account );
      vote_account->stake = 0UL;
      map_cnt++;
    }
    if( FD_LIKELY( vote_account ) ) {
      vote_account->stake += fd_stake_delegation_activation_status( delegation, bank->f.epoch, &enc->stake_history, &bank->f.warmup_cooldown_rate_epoch, use_fixed_point ).effective;
    } else {
      capped = 1;
    }
    enc->stake_delegation_cnt++;
  }

  fd_stake_delegations_view_end( stake_delegations, &enc->stake_history, &bank->f.warmup_cooldown_rate_epoch, use_fixed_point );
  if( FD_UNLIKELY( capped ) ) {
    FD_LOG_WARNING(( "more than %lu vote accounts have stake delegated, the snapshot lists only that many", FD_RUNTIME_MAX_SNAPSHOT_VOTE_ACCOUNTS ));
  }

  /* Agave fails to load if a delegation's vote account is valid but
     absent here, or if an entry here is not a valid vote account.  To
     save memory, we double the vote accounts map as an array and
     encode it directly. */
  enc->vote_account_cnt = 0UL;
  for( ulong slot=0UL; slot<vote_account_map_slot_cnt(); slot++ ) {
    fd_ssmanifest_vote_account_t * vote_account = &map[ slot ];
    if( vote_account_map_key_inval( vote_account->pubkey ) ) {
      continue;
    }
    uint data_len = read_vote_account( accdb, accdb_fork_id, &vote_account->pubkey, acc_data );
    if( !data_len ) {
      continue;
    }
    vote_account->data_len = data_len;
    enc->vote_account[ enc->vote_account_cnt ] = *vote_account;
    enc->vote_account_cnt++;
  }

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

      uint data_len = read_vote_account( accdb, accdb_fork_id, &ele->vote, acc_data );
      if( FD_UNLIKELY( !data_len || fd_vote_account_authorized_voter( acc_data, data_len, epoch_key, &ele->voter ) ) ) {
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

static uchar *
write_vote_account( fd_ssmanifest_writer_t const *       enc,
                    fd_ssmanifest_vote_account_t const * vote_account,
                    uchar *                              p ) {
  ulong       lamports;
  int         executable;
  fd_pubkey_t owner;
  ulong       data_len;
  uchar *     data = p+sizeof(fd_pubkey_t)+3UL*sizeof(ulong);
  fd_accdb_read_one_nocache( enc->accdb, enc->accdb_fork_id, vote_account->pubkey.uc, &lamports, &executable, owner.uc, data, &data_len );
  FD_CHECK_CRIT( lamports && data_len==vote_account->data_len, "vote account changed during snapshot" );

  FD_STORE( fd_pubkey_t, p, vote_account->pubkey ); p += sizeof(fd_pubkey_t);
  FD_STORE( ulong,       p, vote_account->stake  ); p += sizeof(ulong);
  FD_STORE( ulong,       p, lamports             ); p += sizeof(ulong);
  FD_STORE( ulong,       p, data_len             ); p += sizeof(ulong);
  p += data_len;
  FD_STORE( fd_pubkey_t, p, owner                ); p += sizeof(fd_pubkey_t);
  FD_STORE( uchar,       p, (uchar)!!executable  ); p += sizeof(uchar);
  FD_STORE( ulong,       p, 0UL                  ); p += sizeof(ulong);
  return p;
}

/* write_stake_delegations writes the next n delegations of the root,
   viewing it for just this call.  The walk resumes where the previous
   call stopped, which the store allows as long as the root does not
   advance, and it does not while a snapshot is being made. */

static uchar *
write_stake_delegations( fd_ssmanifest_writer_t * enc,
                         ulong                    n,
                         uchar *                  p ) {
  fd_bank_t *              bank              = enc->bank;
  fd_stake_delegations_t * stake_delegations = enc->stake_delegations;
  int                      use_fixed_point   = FD_FEATURE_ACTIVE_BANK( bank, upgrade_bpf_stake_program_to_v5_1 );

  fd_stake_delegations_view_begin( stake_delegations, bank->f.epoch, &enc->stake_history, &bank->f.warmup_cooldown_rate_epoch, use_fixed_point, USHORT_MAX );
  fd_stake_delegations_iter_t * iter = &enc->stake_delegation_iter;
  if( !enc->stake_delegation_idx ) {
    fd_stake_delegations_iter_init( iter, stake_delegations );
  }
  for( ulong i=0UL; i<n; i++ ) {
    FD_CHECK_CRIT( !fd_stake_delegations_iter_done( iter ), "stake delegations changed during snapshot" );
    fd_stake_delegation_t const * delegation = fd_stake_delegations_iter_ele( iter );
    FD_STORE( fd_pubkey_t,     p, delegation->stake_account                         ); p += sizeof(fd_pubkey_t);
    FD_STORE( fd_delegation_t, p, fd_delegation_from_stake_delegation( delegation ) ); p += sizeof(fd_delegation_t);
    fd_stake_delegations_iter_next( iter );
  }
  if( enc->stake_delegation_idx+n==enc->stake_delegation_cnt ) {
    FD_CHECK_CRIT( fd_stake_delegations_iter_done( iter ), "stake delegations changed during snapshot" );
  }
  fd_stake_delegations_view_end( stake_delegations, &enc->stake_history, &bank->f.warmup_cooldown_rate_epoch, use_fixed_point );
  return p;
}

#define PUSH_BYTES( src, n )                                              \
  do {                                                                    \
    if( FD_UNLIKELY( p+(n) > p1 ) ) fail( enc, buf_sz, __LINE__ );        \
    fd_memcpy( p, (src), (n) );                                           \
    p += (n);                                                             \
  } while(0)
#define PUSH_VOTE_ACCOUNT( v )                                            \
  do {                                                                    \
    ulong room = FD_SSMANIFEST_VOTE_ACCOUNT_HDR_SZ+FD_RUNTIME_ACC_SZ_MAX; \
    if( FD_UNLIKELY( p+room > p1 ) ) fail( enc, buf_sz, __LINE__ );       \
    p = write_vote_account( enc, (v), p );                                \
  } while(0)
#define PUSH_STAKE_DELEGATIONS( n )                                       \
  do {                                                                    \
    ulong bytes = (n)*FD_SSMANIFEST_STAKE_DELEGATION_SZ;                  \
    if( FD_UNLIKELY( p+bytes > p1 ) ) fail( enc, buf_sz, __LINE__ );      \
    p = write_stake_delegations( enc, (n), p );                           \
  } while(0)
#define RET_EXPR (ulong)( p - out_buf )
#include "fd_ssmanifest_encoder.c"

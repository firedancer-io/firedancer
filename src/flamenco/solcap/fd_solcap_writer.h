#ifndef HEADER_fd_src_flamenco_solcap_fd_solcap_writer_h
#define HEADER_fd_src_flamenco_solcap_fd_solcap_writer_h

#include "fd_pkt_writer.h"
#include "../types/fd_types_custom.h"
#include "../../ballet/pb/fd_pb_encode.h"

/* FD_SOLCAP_MSG_* give solcap message types */

#define FD_SOLCAP_MSG_BANK_CREATE         1
#define FD_SOLCAP_MSG_BANK_CLONE          2
#define FD_SOLCAP_MSG_BANK_DESTROY        3
#define FD_SOLCAP_MSG_LEADER_SLOT         4
#define FD_SOLCAP_MSG_TXN_EXEC_START      5
#define FD_SOLCAP_MSG_TXN_EXEC_PREFLIGHT  6
#define FD_SOLCAP_MSG_TXN_EXEC_END        7
#define FD_SOLCAP_MSG_INSTR_EXEC_START    8
#define FD_SOLCAP_MSG_INSTR_EXEC_END      9
#define FD_SOLCAP_MSG_LTHASH_UPDATE      10
#define FD_SOLCAP_MSG_BANK_HASH          11
#define FD_SOLCAP_MSG_STAKE_REWARD       12

/* FD_SOLCAP_MTU gives a recommended MTU for solcap Protobuf messages */

#define FD_SOLCAP_MTU (65536UL)

FD_PROTOTYPES_BEGIN

FD_FN_UNUSED static void
fd_solcap_bank_create( fd_pkt_writer_t * pw,
                       ulong             bank_id,
                       ulong             slot ) {
  if( FD_LIKELY( !pw ) ) return;
  uchar * frame = fd_pkt_writer_alloc( pw );
  fd_pb_encoder_t enc[1];
  fd_pb_encoder_init( enc, frame, pw->mtu );
  fd_pb_submsg_open ( enc, FD_SOLCAP_MSG_BANK_CREATE );
  fd_pb_push_uint64 ( enc, 1U, bank_id );
  fd_pb_push_uint64 ( enc, 2U, slot    );
  fd_pb_submsg_close( enc );
  fd_pkt_writer_post( pw, fd_pb_encoder_out_sz( enc ) );
}

FD_FN_UNUSED static void
fd_solcap_bank_clone( fd_pkt_writer_t * pw,
                      ulong             dst_bank_id,
                      ulong             src_bank_id ) {
  if( FD_LIKELY( !pw ) ) return;
  uchar * frame = fd_pkt_writer_alloc( pw );
  fd_pb_encoder_t enc[1];
  fd_pb_encoder_init( enc, frame, pw->mtu );
  fd_pb_submsg_open ( enc, FD_SOLCAP_MSG_BANK_CLONE );
  fd_pb_push_uint64 ( enc, 1U, dst_bank_id );
  fd_pb_push_uint64 ( enc, 2U, src_bank_id );
  fd_pb_submsg_close( enc );
  fd_pkt_writer_post( pw, fd_pb_encoder_out_sz( enc ) );
}

FD_FN_UNUSED static void
fd_solcap_bank_destroy( fd_pkt_writer_t * pw,
                        ulong             bank_id ) {
  if( FD_LIKELY( !pw ) ) return;
  uchar * frame = fd_pkt_writer_alloc( pw );
  fd_pb_encoder_t enc[1];
  fd_pb_encoder_init( enc, frame, pw->mtu );
  fd_pb_submsg_open ( enc, FD_SOLCAP_MSG_BANK_DESTROY );
  fd_pb_push_uint64 ( enc, 1U, bank_id );
  fd_pb_submsg_close( enc );
  fd_pkt_writer_post( pw, fd_pb_encoder_out_sz( enc ) );
}

struct fd_solcap_txn_exec_start {
  ulong         bank_id;
  uchar const * serialized_txn;
  ulong         serialized_txn_sz;
};
typedef struct fd_solcap_txn_exec_start fd_solcap_txn_exec_start_t;

FD_FN_UNUSED static void
fd_solcap_txn_exec_start( fd_pkt_writer_t *                  pw,
                          fd_solcap_txn_exec_start_t const * start ) {
  if( FD_LIKELY( !pw ) ) return;
  uchar * frame = fd_pkt_writer_alloc( pw );
  fd_pb_encoder_t enc[1];
  fd_pb_encoder_init( enc, frame, pw->mtu );
  FD_CRIT( pw->mtu>=4096, "MTU too small" );
  FD_CRIT( start->serialized_txn_sz<=2048, "serialized_txn too large" );
  fd_pb_submsg_open ( enc, FD_SOLCAP_MSG_TXN_EXEC_START );
  fd_pb_push_uint64 ( enc, 1U, start->bank_id );
  fd_pb_push_bytes  ( enc, 2U, start->serialized_txn, start->serialized_txn_sz );
  fd_pb_submsg_close( enc );
  fd_pkt_writer_post( pw, fd_pb_encoder_out_sz( enc ) );
}

struct fd_solcap_txn_exec_preflight {
  ulong bank_id;
  uchar signature[64];
  uchar fee_payer[32];
  ulong fee_lamports;
};
typedef struct fd_solcap_txn_exec_preflight fd_solcap_txn_exec_preflight_t;

FD_FN_UNUSED static void
fd_solcap_txn_exec_preflight( fd_pkt_writer_t *                      pw,
                              fd_solcap_txn_exec_preflight_t const * preflight ) {
  if( FD_LIKELY( !pw ) ) return;
  uchar * frame = fd_pkt_writer_alloc( pw );
  FD_CRIT( pw->mtu>=256, "undersize MTU" );
  fd_pb_encoder_t enc[1];
  fd_pb_encoder_init( enc, frame, pw->mtu );
  fd_pb_submsg_open ( enc, FD_SOLCAP_MSG_TXN_EXEC_PREFLIGHT );
  fd_pb_push_uint64 ( enc, 1U, preflight->bank_id       );
  fd_pb_push_bytes  ( enc, 2U, preflight->signature, 64 );
  fd_pb_push_bytes  ( enc, 3U, preflight->fee_payer, 32 );
  fd_pb_push_uint64 ( enc, 4U, preflight->fee_lamports  );
  fd_pb_submsg_close( enc );
  fd_pkt_writer_post( pw, fd_pb_encoder_out_sz( enc ) );
}

struct fd_solcap_txn_exec_end {
  ulong bank_id;
  uchar signature[64];
  int   error_code;
};
typedef struct fd_solcap_txn_exec_end fd_solcap_txn_exec_end_t;

FD_FN_UNUSED static void
fd_solcap_txn_exec_end( fd_pkt_writer_t *                pw,
                        fd_solcap_txn_exec_end_t const * end ) {
  if( FD_LIKELY( !pw ) ) return;
  uchar * frame = fd_pkt_writer_alloc( pw );
  FD_CRIT( pw->mtu>=128, "undersize MTU" );
  fd_pb_encoder_t enc[1];
  fd_pb_encoder_init( enc, frame, pw->mtu );
  fd_pb_push_uint64 ( enc, 1U, end->bank_id       );
  fd_pb_push_bytes  ( enc, 1U, end->signature, 64 );
  fd_pb_push_int32  ( enc, 2U, end->error_code    );
  fd_pkt_writer_post( pw, fd_pb_encoder_out_sz( enc ) );
}

struct fd_solcap_instr_exec_start {
  ulong bank_id;
  uchar signature[64];
  uint  instr_seq;
  uint  depth;
  ulong cu_rem;
};
typedef struct fd_solcap_instr_exec_start fd_solcap_instr_exec_start_t;

FD_FN_UNUSED static void
fd_solcap_instr_exec_start( fd_pkt_writer_t *                    pw,
                            fd_solcap_instr_exec_start_t const * start ) {
  if( FD_LIKELY( !pw ) ) return;
  uchar * frame = fd_pkt_writer_alloc( pw );
  FD_CRIT( pw->mtu>=128, "undersize MTU" );
  fd_pb_encoder_t enc[1];
  fd_pb_encoder_init( enc, frame, pw->mtu );
  fd_pb_push_uint64 ( enc, 1U, start->bank_id       );
  fd_pb_push_bytes  ( enc, 2U, start->signature, 64 );
  fd_pb_push_uint32 ( enc, 3U, start->instr_seq     );
  fd_pb_push_uint32 ( enc, 4U, start->depth         );
  fd_pb_push_uint64 ( enc, 5U, start->cu_rem        );
  fd_pkt_writer_post( pw, fd_pb_encoder_out_sz( enc ) );
}

struct fd_solcap_instr_exec_end {
  ulong bank_id;
  uchar signature[64];
  uint  instr_seq;
  int   error_code;
  ulong cu_used;
  ulong return_code;
};
typedef struct fd_solcap_instr_exec_end fd_solcap_instr_exec_end_t;

FD_FN_UNUSED static void
fd_solcap_instr_exec_end( fd_pkt_writer_t *                  pw,
                          fd_solcap_instr_exec_end_t const * end ) {
  if( FD_LIKELY( !pw ) ) return;
  uchar * frame = fd_pkt_writer_alloc( pw );
  FD_CRIT( pw->mtu>=192, "undersize MTU" );
  fd_pb_encoder_t enc[1];
  fd_pb_encoder_init( enc, frame, pw->mtu );
  fd_pb_push_uint64 ( enc, 1U, end->bank_id       );
  fd_pb_push_bytes  ( enc, 2U, end->signature, 64 );
  fd_pb_push_uint32 ( enc, 3U, end->instr_seq     );
  fd_pb_push_int32  ( enc, 4U, end->error_code    );
  fd_pb_push_uint64 ( enc, 5U, end->cu_used       );
  fd_pb_push_uint64 ( enc, 6U, end->return_code   );
  fd_pkt_writer_post( pw, fd_pb_encoder_out_sz( enc ) );
}

FD_FN_UNUSED static void
fd_solcap_lthash_init( fd_pkt_writer_t * pw,
                       ulong             bank_id,
                       uchar const       lthash_post[ 2048 ] ) {
  if( FD_LIKELY( !pw ) ) return;
  uchar * frame = fd_pkt_writer_alloc( pw );
  fd_pb_encoder_t enc[1];
  fd_pb_encoder_init( enc, frame, pw->mtu );
  fd_pb_push_uint64 ( enc, 1U, bank_id );
  fd_pb_push_int32  ( enc, 2U, 2 ); /* LthashDeltaType SET */
  fd_pb_push_bytes  ( enc, 3U, lthash_post, 2048 );
  fd_pkt_writer_post( pw, fd_pb_encoder_out_sz( enc ) );
}

FD_FN_UNUSED static void
fd_solcap_lthash_update( fd_pkt_writer_t * pw,
                         ulong             bank_id,
                         uchar const       lthash_delta[32],
                         _Bool             is_subtract,
                         uchar const       account_address[32] ) {
  if( FD_LIKELY( !pw ) ) return;
  uchar * frame = fd_pkt_writer_alloc( pw );
  FD_CRIT( pw->mtu>=192, "undersize MTU" );
  fd_pb_encoder_t enc[1];
  fd_pb_encoder_init( enc, frame, pw->mtu );
  fd_pb_push_uint64 ( enc, 1U, bank_id );
  fd_pb_push_int32  ( enc, 2U, !!is_subtract ); /* LthashDeltaType */
  fd_pb_push_bytes  ( enc, 3U, lthash_delta,    32 );
  fd_pb_push_bytes  ( enc, 4U, account_address, 32 );
  fd_pkt_writer_post( pw, fd_pb_encoder_out_sz( enc ) );
}

FD_FN_UNUSED static void
fd_solcap_lthash_add( fd_pkt_writer_t * pw,
                      ulong             bank_id,
                      uchar const       lthash_delta[32],
                      uchar const       account_address[32] ) {
  fd_solcap_lthash_update( pw, bank_id, lthash_delta, 0, account_address );
}

FD_FN_UNUSED static void
fd_solcap_lthash_sub( fd_pkt_writer_t * pw,
                      ulong             bank_id,
                      uchar const       lthash_delta[32],
                      uchar const       account_address[32] ) {
  fd_solcap_lthash_update( pw, bank_id, lthash_delta, 1, account_address );
}

struct fd_solcap_bank_hash {
  ulong         bank_id;
  uchar const * bank_hash_post; /* 32 bytes */
  uchar const * bank_hash_pre;  /* 32 bytes */
  uchar const * block_hash;     /* 32 bytes */
  ulong         slot;
  ulong         cum_signature_cnt;
  uchar const * lthash; /* 2048 bytes */
};

typedef struct fd_solcap_bank_hash fd_solcap_bank_hash_t;

FD_FN_UNUSED static void
fd_solcap_bank_hash( fd_pkt_writer_t *             pw,
                     fd_solcap_bank_hash_t const * bank_hash ) {
  if( FD_LIKELY( !pw ) ) return;
  uchar * frame = fd_pkt_writer_alloc( pw );
  FD_CRIT( pw->mtu>=2500, "undersize MTU" );
  fd_pb_encoder_t enc[1];
  fd_pb_encoder_init( enc, frame, pw->mtu );
  fd_pb_push_uint64 ( enc, 1U, bank_hash->bank_id            );
  fd_pb_push_bytes  ( enc, 2U, bank_hash->bank_hash_post, 32 );
  fd_pb_push_bytes  ( enc, 3U, bank_hash->bank_hash_pre,  32 );
  fd_pb_push_bytes  ( enc, 4U, bank_hash->block_hash,     32 );
  fd_pb_push_uint64 ( enc, 5U, bank_hash->slot               );
  fd_pb_push_uint64 ( enc, 6U, bank_hash->cum_signature_cnt  );
  fd_pb_push_bytes  ( enc, 7U, bank_hash->lthash,       2048 );
  fd_pkt_writer_post( pw, fd_pb_encoder_out_sz( enc ) );
}

struct fd_solcap_stake_inflation {
  ulong bank_id;
  ulong payout_epoch;
  ulong inflation_lamports;
  uchar total_points[16]; /* uint128 host order */
};
typedef struct fd_solcap_stake_inflation fd_solcap_stake_inflation_t;

FD_FN_UNUSED static void
fd_solcap_stake_inflation( fd_pkt_writer_t *                   pw,
                           fd_solcap_stake_inflation_t const * inflation ) {
  if( FD_LIKELY( !pw ) ) return;
  uchar * frame = fd_pkt_writer_alloc( pw );
  FD_CRIT( pw->mtu>=512, "undersize MTU" );
  fd_pb_encoder_t enc[1];
  fd_pb_encoder_init( enc, frame, pw->mtu );
  fd_pb_push_uint64 ( enc, 1U, inflation->bank_id             );
  fd_pb_push_uint64 ( enc, 2U, inflation->payout_epoch        );
  fd_pb_push_uint64 ( enc, 3U, inflation->inflation_lamports  );
  fd_pb_push_bytes  ( enc, 4U, inflation->total_points, 16    );
  fd_pkt_writer_post( pw, fd_pb_encoder_out_sz( enc ) );
}

struct fd_solcap_stake_reward {
  ulong          bank_id;
  uchar const (* stake_account)[ 32 ];
  uchar const (* vote_account )[ 32 ];
  uint           commission;
  ulong          stake_rewards;
  ulong          vote_rewards;
  ulong          new_credits_observed;
};
typedef struct fd_solcap_stake_reward fd_solcap_stake_reward_t;

FD_FN_UNUSED static void
fd_solcap_stake_reward( fd_pkt_writer_t *                 pw,
                         fd_solcap_stake_reward_t const * reward ) {
  if( FD_LIKELY( !pw ) ) return;
  uchar * frame = fd_pkt_writer_alloc( pw );
  FD_CRIT( pw->mtu>=256, "undersize MTU" );
  fd_pb_encoder_t enc[1];
  fd_pb_encoder_init( enc, frame, pw->mtu );
  fd_pb_push_uint64 ( enc, 1U, reward->bank_id              );
  fd_pb_push_bytes  ( enc, 2U, reward->stake_account, 32    );
  fd_pb_push_bytes  ( enc, 3U, reward->vote_account,  32    );
  fd_pb_push_uint32 ( enc, 4U, reward->commission           );
  fd_pb_push_uint64 ( enc, 5U, reward->stake_rewards        );
  fd_pb_push_uint64 ( enc, 6U, reward->vote_rewards         );
  fd_pb_push_uint64 ( enc, 7U, reward->new_credits_observed );
  fd_pkt_writer_post( pw, fd_pb_encoder_out_sz( enc ) );
}

struct fd_solcap_stake_reward_payout {
  ulong bank_id;
  uchar const * stake_pubkey;
  ulong slot;
  ulong lamports;
  ulong stake_lamports;
  ulong credits_observed;
  long  lamports_delta;
  long  stake_lamports_delta;
  long  credits_observed_delta;
};
typedef struct fd_solcap_stake_reward_payout fd_solcap_stake_reward_payout_t;

FD_FN_UNUSED static void
fd_solcap_stake_reward_payout( fd_pkt_writer_t *                       pw,
                               fd_solcap_stake_reward_payout_t const * payout ) {
  if( FD_LIKELY( !pw ) ) return;
  uchar * frame = fd_pkt_writer_alloc( pw );
  FD_CRIT( pw->mtu>=256, "undersize MTU" );
  fd_pb_encoder_t enc[1];
  fd_pb_encoder_init( enc, frame, pw->mtu );
  fd_pb_push_uint64 ( enc, 1U, payout->bank_id                );
  fd_pb_push_bytes  ( enc, 2U, payout->stake_pubkey, 32       );
  fd_pb_push_uint64 ( enc, 3U, payout->slot                   );
  fd_pb_push_uint64 ( enc, 4U, payout->lamports               );
  fd_pb_push_uint64 ( enc, 5U, payout->stake_lamports         );
  fd_pb_push_uint64 ( enc, 6U, payout->credits_observed       );
  fd_pb_push_int64  ( enc, 7U, payout->lamports_delta         );
  fd_pb_push_int64  ( enc, 8U, payout->stake_lamports_delta   );
  fd_pb_push_int64  ( enc, 9U, payout->credits_observed_delta );
  fd_pkt_writer_post( pw, fd_pb_encoder_out_sz( enc ) );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_solcap_fd_solcap_writer_h */

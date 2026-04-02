#ifndef HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_codec_h
#define HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_codec_h

#include "../../../types/fd_types_custom.h"

/* Vote program type definitions and (de)serializers.

   Supported versions: v1_14_11, v3, v4. */

/**********************************************************************/
/* Constants -- vote state                                            */
/**********************************************************************/

/* Note we add to each of the bounds for the max capacity to account
   for edge cases where elements are added beyond theoretical capacity
   and then popped within execution. */

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v5.1.1/vote-interface/src/state/mod.rs#L39 */
#define MAX_LOCKOUT_HISTORY          (31UL)
#define MAX_LOCKOUT_HISTORY_CAPACITY (MAX_LOCKOUT_HISTORY+1UL)

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v5.1.1/vote-interface/src/state/mod.rs#L43 */
#define MAX_EPOCH_CREDITS_HISTORY          (64UL)
#define MAX_EPOCH_CREDITS_HISTORY_CAPACITY (MAX_EPOCH_CREDITS_HISTORY+1UL)

/* This is an implicit bound derived from the vote program logic.  When
   authorized voters are updated inside the vote program, any authorized
   voters outside of the [epoch-1, epoch+2] range are purged.  In
   between execution, up to 2 authorized voters can be added, so we
   need to allocate extra capacity accordingly. */
#define MAX_AUTHORIZED_VOTERS          (4UL)
#define MAX_AUTHORIZED_VOTERS_CAPACITY (MAX_AUTHORIZED_VOTERS+2UL)

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v5.1.1/vote-interface/src/state/mod.rs#L154 */
#define PRIOR_VOTERS_MAX (32UL)

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v5.1.1/vote-interface/src/state/mod.rs#L33 */
#define FD_BLS_PUBKEY_COMPRESSED_SZ (48UL)

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v5.0.0/vote-interface/src/state/mod.rs#L36 */
#define FD_BLS_PROOF_OF_POSSESSION_COMPRESSED_SZ (96UL)

/**********************************************************************/
/* Constants -- vote instruction footprints                           */
/**********************************************************************/

/* Some vote instruction types are dynamically sized:
    - tower_sync_switch                (contains deque of fd_vote_lockout_t)
    - tower_sync                       (contains deque of fd_vote_lockout_t)
    - compact_vote_state_update_switch (vector of fd_lockout_offset_t)
    - compact_vote_state_update        (vector of fd_lockout_offset_t)
    - authorize_checked_with_seed      (char vector of current_authority_derived_key_seed)
    - authorize_with_seed              (char vector of current_authority_derived_key_seed)
    - update_vote_state_switch         (contains deque of fd_vote_lockout_t)
    - update_vote_state                (contains deque of fd_vote_lockout_t)
    - vote_switch                      (deque of slot numbers)
    - vote                             (deque of slot numbers)
   All other vote instruction types are statically sized.

   A loose bound on the max amount of encoded fd_vote_lockout_t
   possible is 1232 bytes/(12 bytes/per lockout) = 102 lockouts.  So
   the worst case bound for the deque of fd_vote_lockout is
   32 + (102 * sizeof(fd_vote_lockout_t)) = 1644 bytes.

   The worst case vector of fd_lockout_offset_t is one where each
   encoded element is 2 bytes.  This means that we can have 1232/2 =
   616 elements.  They are represented as being 16 bytes each, so the
   total footprint would be 9856 bytes.

   The deque of slot numbers is a vector of ulong, which is 8 bytes.
   So the worst case is 1232 bytes/8 bytes = 154 elements.  So, the
   total footprint is 32 + (154 * 8 bytes) = 1264 bytes.

   The worst case char vector is 1232 bytes as each element is 1 byte
   up to the txn MTU.

   With this, that means that the compact_vote_state_update_switch
   can have the largest worst case footprint where the struct is
   104 bytes (sizeof(fd_compact_vote_state_update_switch_t) + the
   worst case lockout vector of 616 elements. */
#define FD_VOTE_INSTR_MAX_LOCKOUTS_LEN         (102UL)
#define FD_VOTE_INSTR_MAX_LOCKOUT_OFFSETS_LEN  (616UL)
#define FD_VOTE_INSTR_MAX_SLOT_NUMS_LEN        (154UL)

/* Footprints for embedded memory arrays inside vote instruction
   sub-structs.  Validated by test_vote_instruction_footprints
   in test_vote_program. */
#define FD_VOTE_INSTR_SLOTS_ALIGN               (8UL)
#define FD_VOTE_INSTR_SLOTS_FOOTPRINT           (1264UL)
#define FD_VOTE_INSTR_UPDATE_LOCKOUTS_ALIGN     (8UL)
#define FD_VOTE_INSTR_UPDATE_LOCKOUTS_FOOTPRINT (1664UL)
#define FD_VOTE_INSTR_LOCKOUT_OFFSET_ALIGN      (8UL)
#define FD_VOTE_INSTR_LOCKOUT_OFFSET_FOOTPRINT  (9856UL)
#define FD_VOTE_INSTR_SEED_MAX                  (1232UL)

/* Footprints for runtime buffers that hold lockouts / landed votes
   derived from vote instruction data.  The max element count is
   FD_VOTE_INSTR_MAX_LOCKOUT_OFFSETS_LEN (616) because the tower sync
   and compact vote state update paths can produce that many entries. */
#define FD_VOTE_INSTR_LOCKOUTS_ALIGN         (8UL)
#define FD_VOTE_INSTR_LOCKOUTS_FOOTPRINT     (9888UL)
#define FD_VOTE_INSTR_LANDED_VOTES_ALIGN     (8UL)
#define FD_VOTE_INSTR_LANDED_VOTES_FOOTPRINT (14816UL)

/**********************************************************************/
/* Constants -- vote account state footprints                         */
/**********************************************************************/

/* Alignments and footprints for the authorized voters pool and treap at
   MAX_AUTHORIZED_VOTERS_CAPACITY.  Validated by
   test_authorized_voters_footprint in test_vote_program. */
#define FD_AUTHORIZED_VOTERS_POOL_ALIGN      (128UL)
#define FD_AUTHORIZED_VOTERS_POOL_FOOTPRINT  (512UL)
#define FD_AUTHORIZED_VOTERS_TREAP_ALIGN     (8UL)
#define FD_AUTHORIZED_VOTERS_TREAP_FOOTPRINT (24UL)

/* Alignment and footprint for the landed votes at
   MAX_LOCKOUT_HISTORY_CAPACITY.  Validated by
   test_landed_votes_footprint in test_vote_program. */
#define FD_LANDED_VOTES_FOOTPRINT (800UL)
#define FD_LANDED_VOTES_ALIGN     (8UL)

/* Alignment and footprint for the epoch credits at
   MAX_EPOCH_CREDITS_HISTORY_CAPACITY.  Validated by
   test_epoch_credits_footprint in test_vote_program. */
#define FD_EPOCH_CREDITS_FOOTPRINT (1576UL)
#define FD_EPOCH_CREDITS_ALIGN     (8UL)

/**********************************************************************/
/* Shared leaf types                                                  */
/**********************************************************************/

struct fd_vote_lockout {
  ulong slot;
  uint  confirmation_count;
};
typedef struct fd_vote_lockout fd_vote_lockout_t;
#define FD_VOTE_LOCKOUT_ALIGN alignof(fd_vote_lockout_t)

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v5.1.1/vote-interface/src/authorized_voters.rs#L11-L13 */
struct fd_vote_authorized_voter {
  ulong       epoch;
  fd_pubkey_t pubkey;

  /* Treap/pool index fields.  uchar is sufficient because the max
     authorized voters capacity is MAX_AUTHORIZED_VOTERS_CAPACITY (6). */
  uchar       parent;
  uchar       left;
  uchar       right;
  uchar       prio;
};
typedef struct fd_vote_authorized_voter fd_vote_authorized_voter_t;
#define FD_VOTE_AUTHORIZED_VOTER_ALIGN alignof(fd_vote_authorized_voter_t)

struct fd_vote_prior_voter {
  fd_pubkey_t pubkey;
  ulong       epoch_start;
  ulong       epoch_end;
};
typedef struct fd_vote_prior_voter fd_vote_prior_voter_t;
#define FD_VOTE_PRIOR_VOTER_ALIGN alignof(fd_vote_prior_voter_t)

struct __attribute__((packed)) fd_vote_epoch_credits {
  ulong epoch;
  ulong credits;
  ulong prev_credits;
};
typedef struct fd_vote_epoch_credits fd_vote_epoch_credits_t;
#define FD_VOTE_EPOCH_CREDITS_ALIGN alignof(fd_vote_epoch_credits_t)

struct fd_vote_block_timestamp {
  ulong slot;
  long  timestamp;
};
typedef struct fd_vote_block_timestamp fd_vote_block_timestamp_t;
#define FD_VOTE_BLOCK_TIMESTAMP_ALIGN alignof(fd_vote_block_timestamp_t)

struct fd_vote_prior_voters {
  fd_vote_prior_voter_t buf[PRIOR_VOTERS_MAX];
  ulong                 idx;
  uchar                 is_empty;
};
typedef struct fd_vote_prior_voters fd_vote_prior_voters_t;
#define FD_VOTE_PRIOR_VOTERS_ALIGN alignof(fd_vote_prior_voters_t)

/* This type is reused between all vote states for simplicity. */
struct fd_landed_vote {
  /* Latency is only used in v3+ vote states. */
  uchar             latency;
  fd_vote_lockout_t lockout;
};
typedef struct fd_landed_vote fd_landed_vote_t;
#define FD_LANDED_VOTE_ALIGN alignof(fd_landed_vote_t)

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v5.0.0/vote-interface/src/state/vote_instruction_data.rs#L253 */
struct fd_voter_with_bls_args {
  uchar bls_pubkey[FD_BLS_PUBKEY_COMPRESSED_SZ];
  uchar bls_proof_of_possession[FD_BLS_PROOF_OF_POSSESSION_COMPRESSED_SZ];
};
typedef struct fd_voter_with_bls_args fd_voter_with_bls_args_t;
#define FD_VOTER_WITH_BLS_ARGS_ALIGN alignof(fd_voter_with_bls_args_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L230 */
struct fd_vote_init {
  fd_pubkey_t node_pubkey;
  fd_pubkey_t authorized_voter;
  fd_pubkey_t authorized_withdrawer;
  uchar       commission;
};
typedef struct fd_vote_init fd_vote_init_t;
#define FD_VOTE_INIT_ALIGN alignof(fd_vote_init_t)

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v5.0.0/vote-interface/src/state/vote_instruction_data.rs#L213 */
struct fd_vote_init_v2 {
  fd_pubkey_t node_pubkey;
  fd_pubkey_t authorized_voter;
  uchar       authorized_voter_bls_pubkey[FD_BLS_PUBKEY_COMPRESSED_SZ];
  uchar       authorized_voter_bls_proof_of_possession[FD_BLS_PROOF_OF_POSSESSION_COMPRESSED_SZ];
  fd_pubkey_t authorized_withdrawer;
  ushort      inflation_rewards_commission_bps;
  fd_pubkey_t inflation_rewards_collector;
  ushort      block_revenue_commission_bps;
  fd_pubkey_t block_revenue_collector;
};
typedef struct fd_vote_init_v2 fd_vote_init_v2_t;
#define FD_VOTE_INIT_V2_ALIGN alignof(fd_vote_init_v2_t)

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v5.0.0/vote-interface/src/state/vote_instruction_data.rs#L277 */
struct fd_vote_authorize {
  uint                     discriminant;
  fd_voter_with_bls_args_t voter_with_bls;
};
typedef struct fd_vote_authorize fd_vote_authorize_t;
#define FD_VOTE_AUTHORIZE_ALIGN alignof(fd_vote_authorize_t)

enum {
  fd_vote_authorize_enum_voter          = 0,
  fd_vote_authorize_enum_withdrawer     = 1,
  fd_vote_authorize_enum_voter_with_bls = 2,
};

/**********************************************************************/
/* Static asserts for wire-compatible struct layouts.                  */
/* The custom vote deserializers use direct memcpy for these types,    */
/* relying on the in-memory layout matching the bincode wire format    */
/* on little-endian platforms.                                        */
/**********************************************************************/

FD_STATIC_ASSERT( sizeof(fd_vote_prior_voter_t)==48UL, vote_prior_voter_layout );
FD_STATIC_ASSERT( sizeof(fd_vote_epoch_credits_t)==24UL, vote_epoch_credits_layout );
FD_STATIC_ASSERT( sizeof(fd_vote_block_timestamp_t)==16UL, vote_block_timestamp_layout );
FD_STATIC_ASSERT( sizeof(fd_vote_init_t)==97UL, vote_init_layout );

/**********************************************************************/
/* Deque templates -- instruction sub-types                           */
/**********************************************************************/

#define DEQUE_NAME deq_ulong
#define DEQUE_T ulong
#include "../../../../util/tmpl/fd_deque_dynamic.c"
#undef DEQUE_NAME
#undef DEQUE_T
#undef DEQUE_MAX

#define DEQUE_NAME deq_fd_vote_lockout_t
#define DEQUE_T fd_vote_lockout_t
#include "../../../../util/tmpl/fd_deque_dynamic.c"
#undef DEQUE_NAME
#undef DEQUE_T
#undef DEQUE_MAX

/**********************************************************************/
/* Deque templates -- vote account state                              */
/**********************************************************************/

#define DEQUE_NAME deq_fd_vote_epoch_credits_t
#define DEQUE_T fd_vote_epoch_credits_t
#define DEQUE_MAX MAX_EPOCH_CREDITS_HISTORY_CAPACITY
#include "../../../../util/tmpl/fd_deque.c"
#undef DEQUE_NAME
#undef DEQUE_T
#undef DEQUE_MAX

#define DEQUE_NAME deq_fd_landed_vote_t
#define DEQUE_T fd_landed_vote_t
#include "../../../../util/tmpl/fd_deque_dynamic.c"
#undef DEQUE_NAME
#undef DEQUE_T
#undef DEQUE_MAX

/**********************************************************************/
/* Treap / pool for authorized voters                                 */
/**********************************************************************/

#define POOL_NAME fd_vote_authorized_voters_pool
#define POOL_T fd_vote_authorized_voter_t
#define POOL_IDX_T uchar
#define POOL_NEXT parent
#include "../../../../util/tmpl/fd_pool.c"
#define TREAP_NAME fd_vote_authorized_voters_treap
#define TREAP_T fd_vote_authorized_voter_t
#define TREAP_IDX_T uchar
#define TREAP_QUERY_T ulong
#define TREAP_CMP(q,e) ( (q == (e)->epoch) ? 0 : ( (q < (e)->epoch) ? -1 : 1 ) )
#define TREAP_LT(e0,e1) ((e0)->epoch<(e1)->epoch)
#include "../../../../util/tmpl/fd_treap.c"

struct fd_vote_authorized_voters {
  fd_vote_authorized_voter_t *        pool;
  fd_vote_authorized_voters_treap_t * treap;
};
typedef struct fd_vote_authorized_voters fd_vote_authorized_voters_t;
#define FD_VOTE_AUTHORIZED_VOTERS_ALIGN alignof(fd_vote_authorized_voters_t)

/**********************************************************************/
/* Vote state structs (per version)                                   */
/**********************************************************************/

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v5.1.1/vote-interface/src/state/vote_state_1_14_11.rs#L16-L46 */
struct fd_vote_state_1_14_11 {
  fd_pubkey_t                 node_pubkey;
  fd_pubkey_t                 authorized_withdrawer;
  uchar                       commission;
  fd_landed_vote_t *          votes;
  ulong                       root_slot;
  uchar                       has_root_slot;
  fd_vote_authorized_voters_t authorized_voters;
  fd_vote_prior_voters_t      prior_voters;
  fd_vote_epoch_credits_t *   epoch_credits;
  fd_vote_block_timestamp_t   last_timestamp;
};
typedef struct fd_vote_state_1_14_11 fd_vote_state_1_14_11_t;

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v5.1.1/vote-interface/src/state/vote_state_v3.rs#L30-L60 */
struct fd_vote_state_v3 {
  fd_pubkey_t                 node_pubkey;
  fd_pubkey_t                 authorized_withdrawer;
  uchar                       commission;
  fd_landed_vote_t *          votes;
  ulong                       root_slot;
  uchar                       has_root_slot;
  fd_vote_authorized_voters_t authorized_voters;
  fd_vote_prior_voters_t      prior_voters;
  fd_vote_epoch_credits_t *   epoch_credits;
  fd_vote_block_timestamp_t   last_timestamp;
};
typedef struct fd_vote_state_v3 fd_vote_state_v3_t;

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v5.1.1/vote-interface/src/state/vote_state_v4.rs#L30-L71 */
struct fd_vote_state_v4 {
  fd_pubkey_t                 node_pubkey;
  fd_pubkey_t                 authorized_withdrawer;
  fd_pubkey_t                 inflation_rewards_collector;
  fd_pubkey_t                 block_revenue_collector;
  ushort                      inflation_rewards_commission_bps;
  ushort                      block_revenue_commission_bps;
  ulong                       pending_delegator_rewards;
  uchar                       bls_pubkey_compressed[FD_BLS_PUBKEY_COMPRESSED_SZ];
  uchar                       has_bls_pubkey_compressed;
  fd_landed_vote_t *          votes;
  ulong                       root_slot;
  uchar                       has_root_slot;
  fd_vote_authorized_voters_t authorized_voters;
  fd_vote_epoch_credits_t *   epoch_credits;
  fd_vote_block_timestamp_t   last_timestamp;
};
typedef struct fd_vote_state_v4 fd_vote_state_v4_t;

/**********************************************************************/
/* Versioned vote state (discriminated union)                         */
/**********************************************************************/

struct fd_vote_state_versioned {
  uint kind;
  union {
    fd_vote_state_1_14_11_t v1_14_11;
    fd_vote_state_v3_t      v3;
    fd_vote_state_v4_t      v4;
  };

  /* Memory for dynamic sub-structures */
  uchar landed_votes_mem            [ FD_LANDED_VOTES_FOOTPRINT           ] __attribute__((aligned(FD_LANDED_VOTES_ALIGN)));
  uchar epoch_credits_mem           [ FD_EPOCH_CREDITS_FOOTPRINT          ] __attribute__((aligned(FD_EPOCH_CREDITS_ALIGN)));
  uchar authorized_voters_pool_mem  [ FD_AUTHORIZED_VOTERS_POOL_FOOTPRINT ] __attribute__((aligned(FD_AUTHORIZED_VOTERS_POOL_ALIGN)));
  uchar authorized_voters_treap_mem [ FD_AUTHORIZED_VOTERS_TREAP_FOOTPRINT] __attribute__((aligned(FD_AUTHORIZED_VOTERS_TREAP_ALIGN)));
};
typedef struct fd_vote_state_versioned fd_vote_state_versioned_t;

enum {
  fd_vote_state_versioned_enum_uninitialized = 0,
  fd_vote_state_versioned_enum_v1_14_11      = 1,
  fd_vote_state_versioned_enum_v3            = 2,
  fd_vote_state_versioned_enum_v4            = 3,
};

/**********************************************************************/
/* Vote instruction sub-types                                         */
/**********************************************************************/

struct fd_lockout_offset {
  ulong offset;
  uchar confirmation_count;
};
typedef struct fd_lockout_offset fd_lockout_offset_t;
#define FD_LOCKOUT_OFFSET_ALIGN alignof(fd_lockout_offset_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L133 */
struct fd_vote {
  ulong *   slots;
  fd_hash_t hash;
  long      timestamp;
  uchar     has_timestamp;
  uchar     slots_mem[ FD_VOTE_INSTR_SLOTS_FOOTPRINT ] __attribute__((aligned(FD_VOTE_INSTR_SLOTS_ALIGN)));
};
typedef struct fd_vote fd_vote_t;
#define FD_VOTE_ALIGN alignof(fd_vote_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_instruction.rs#L37 */
struct fd_vote_authorize_pubkey {
  fd_pubkey_t         pubkey;
  fd_vote_authorize_t vote_authorize;
};
typedef struct fd_vote_authorize_pubkey fd_vote_authorize_pubkey_t;
#define FD_VOTE_AUTHORIZE_PUBKEY_ALIGN alignof(fd_vote_authorize_pubkey_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_instruction.rs#L78 */
struct fd_vote_switch {
  fd_vote_t vote;
  fd_hash_t hash;
};
typedef struct fd_vote_switch fd_vote_switch_t;
#define FD_VOTE_SWITCH_ALIGN alignof(fd_vote_switch_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L185 */
struct fd_vote_state_update {
  fd_vote_lockout_t * lockouts;
  ulong               root;
  uchar               has_root;
  fd_hash_t           hash;
  long                timestamp;
  uchar               has_timestamp;
  uchar               lockouts_mem[ FD_VOTE_INSTR_UPDATE_LOCKOUTS_FOOTPRINT ] __attribute__((aligned(FD_VOTE_INSTR_UPDATE_LOCKOUTS_ALIGN)));
};
typedef struct fd_vote_state_update fd_vote_state_update_t;
#define FD_VOTE_STATE_UPDATE_ALIGN alignof(fd_vote_state_update_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_instruction.rs#L104 */
struct fd_update_vote_state_switch {
  fd_vote_state_update_t vote_state_update;
  fd_hash_t              hash;
};
typedef struct fd_update_vote_state_switch fd_update_vote_state_switch_t;
#define FD_UPDATE_VOTE_STATE_SWITCH_ALIGN alignof(fd_update_vote_state_switch_t)

struct fd_compact_vote_state_update {
  ulong                 root;
  ushort                lockouts_len;
  fd_lockout_offset_t * lockouts;
  fd_hash_t             hash;
  long                  timestamp;
  uchar                 has_timestamp;
  uchar                 lockouts_mem[ FD_VOTE_INSTR_LOCKOUT_OFFSET_FOOTPRINT ] __attribute__((aligned(FD_VOTE_INSTR_LOCKOUT_OFFSET_ALIGN)));
};
typedef struct fd_compact_vote_state_update fd_compact_vote_state_update_t;
#define FD_COMPACT_VOTE_STATE_UPDATE_ALIGN alignof(fd_compact_vote_state_update_t)

/* https://github.com/solana-labs/solana/blob/252438e28fbfb2c695fe1215171b83456e4b761c/programs/vote/src/vote_instruction.rs#L143 */
struct fd_compact_vote_state_update_switch {
  fd_compact_vote_state_update_t compact_vote_state_update;
  fd_hash_t                      hash;
};
typedef struct fd_compact_vote_state_update_switch fd_compact_vote_state_update_switch_t;
#define FD_COMPACT_VOTE_STATE_UPDATE_SWITCH_ALIGN alignof(fd_compact_vote_state_update_switch_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L185 */
struct fd_tower_sync {
  fd_vote_lockout_t * lockouts;
  ulong               lockouts_cnt;
  ulong               root;
  uchar               has_root;
  fd_hash_t           hash;
  long                timestamp;
  uchar               has_timestamp;
  fd_hash_t           block_id;
  uchar               lockouts_mem[ FD_VOTE_INSTR_LOCKOUTS_FOOTPRINT ] __attribute__((aligned(FD_VOTE_INSTR_LOCKOUTS_ALIGN)));
};
typedef struct fd_tower_sync fd_tower_sync_t;
#define FD_TOWER_SYNC_ALIGN alignof(fd_tower_sync_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_instruction.rs#L104 */
struct fd_tower_sync_switch {
  fd_tower_sync_t tower_sync;
  fd_hash_t       hash;
};
typedef struct fd_tower_sync_switch fd_tower_sync_switch_t;
#define FD_TOWER_SYNC_SWITCH_ALIGN alignof(fd_tower_sync_switch_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L244 */
struct fd_vote_authorize_with_seed_args {
  fd_vote_authorize_t authorization_type;
  fd_pubkey_t         current_authority_derived_key_owner;
  ulong               current_authority_derived_key_seed_len;
  uchar               current_authority_derived_key_seed[ FD_VOTE_INSTR_SEED_MAX ];
  fd_pubkey_t         new_authority;
};
typedef struct fd_vote_authorize_with_seed_args fd_vote_authorize_with_seed_args_t;
#define FD_VOTE_AUTHORIZE_WITH_SEED_ARGS_ALIGN alignof(fd_vote_authorize_with_seed_args_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/vote/src/vote_state/mod.rs#L252 */
struct fd_vote_authorize_checked_with_seed_args {
  fd_vote_authorize_t authorization_type;
  fd_pubkey_t         current_authority_derived_key_owner;
  ulong               current_authority_derived_key_seed_len;
  uchar               current_authority_derived_key_seed[ FD_VOTE_INSTR_SEED_MAX ];
};
typedef struct fd_vote_authorize_checked_with_seed_args fd_vote_authorize_checked_with_seed_args_t;
#define FD_VOTE_AUTHORIZE_CHECKED_WITH_SEED_ARGS_ALIGN alignof(fd_vote_authorize_checked_with_seed_args_t)

/* https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v5.0.0/vote-interface/src/instruction.rs#L28-L31 */
struct fd_commission_kind {
  uint discriminant;
};
typedef struct fd_commission_kind fd_commission_kind_t;
#define FD_COMMISSION_KIND_ALIGN alignof(fd_commission_kind_t)

enum {
  fd_commission_kind_enum_inflation_rewards = 0,
  fd_commission_kind_enum_block_revenue     = 1,
};

struct fd_update_commission_bps_args {
  ushort               commission_bps;
  fd_commission_kind_t kind;
};
typedef struct fd_update_commission_bps_args fd_update_commission_bps_args_t;
#define FD_UPDATE_COMMISSION_BPS_ARGS_ALIGN alignof(fd_update_commission_bps_args_t)

struct fd_deposit_delegator_rewards_args {
  ulong deposit;
};
typedef struct fd_deposit_delegator_rewards_args fd_deposit_delegator_rewards_args_t;
#define FD_DEPOSIT_DELEGATOR_REWARDS_ARGS_ALIGN alignof(fd_deposit_delegator_rewards_args_t)

/**********************************************************************/
/* Vote instruction (discriminated union)                             */
/**********************************************************************/

/* https://github.com/firedancer-io/solana/blob/53a4e5d6c58b2ffe89b09304e4437f8ca198dadd/programs/vote/src/vote_instruction.rs#L21 */
struct fd_vote_instruction {
  uint discriminant;
  union {
    fd_vote_init_t                             initialize_account;
    fd_vote_authorize_pubkey_t                 authorize;
    fd_vote_t                                  vote;
    ulong                                      withdraw;
    uchar                                      update_commission;
    fd_vote_switch_t                           vote_switch;
    fd_vote_authorize_t                        authorize_checked;
    fd_vote_state_update_t                     update_vote_state;
    fd_update_vote_state_switch_t              update_vote_state_switch;
    fd_vote_authorize_with_seed_args_t         authorize_with_seed;
    fd_vote_authorize_checked_with_seed_args_t authorize_checked_with_seed;
    fd_compact_vote_state_update_t             compact_update_vote_state;
    fd_compact_vote_state_update_switch_t      compact_update_vote_state_switch;
    fd_tower_sync_t                            tower_sync;
    fd_tower_sync_switch_t                     tower_sync_switch;
    fd_vote_init_v2_t                          initialize_account_v2;
    fd_commission_kind_t                       update_commission_collector;
    fd_update_commission_bps_args_t            update_commission_bps;
    fd_deposit_delegator_rewards_args_t        deposit_delegator_rewards;
  };
};
typedef struct fd_vote_instruction fd_vote_instruction_t;

enum {
  fd_vote_instruction_enum_initialize_account               = 0,
  fd_vote_instruction_enum_authorize                        = 1,
  fd_vote_instruction_enum_vote                             = 2,
  fd_vote_instruction_enum_withdraw                         = 3,
  fd_vote_instruction_enum_update_validator_identity        = 4,
  fd_vote_instruction_enum_update_commission                = 5,
  fd_vote_instruction_enum_vote_switch                      = 6,
  fd_vote_instruction_enum_authorize_checked                = 7,
  fd_vote_instruction_enum_update_vote_state                = 8,
  fd_vote_instruction_enum_update_vote_state_switch         = 9,
  fd_vote_instruction_enum_authorize_with_seed              = 10,
  fd_vote_instruction_enum_authorize_checked_with_seed      = 11,
  fd_vote_instruction_enum_compact_update_vote_state        = 12,
  fd_vote_instruction_enum_compact_update_vote_state_switch = 13,
  fd_vote_instruction_enum_tower_sync                       = 14,
  fd_vote_instruction_enum_tower_sync_switch                = 15,
  fd_vote_instruction_enum_initialize_account_v2            = 16,
  fd_vote_instruction_enum_update_commission_collector      = 17,
  fd_vote_instruction_enum_update_commission_bps            = 18,
  fd_vote_instruction_enum_deposit_delegator_rewards        = 19,
};

/**********************************************************************/
/* Function declarations                                              */
/**********************************************************************/

FD_PROTOTYPES_BEGIN

/* Initializes a fd_vote_state_versioned_t and its dynamic members
   (votes deque, epoch_credits deque, authorized_voters pool,
   authorized_voters treap).  Based on the discriminant, the appropriate
   version-specific struct is initialized.

   Returns a pointer to the initialized fd_vote_state_versioned_t, or
   NULL if mem is NULL or kind is an unsupported vote state version. */
fd_vote_state_versioned_t *
fd_vote_state_versioned_new( fd_vote_state_versioned_t * self,
                             uint                        kind );

/* Deserializes the vote state from a bincode-encoded buffer into the
   provided vote state versioned struct.  On success returns self.
   Returns NULL on failure (malformed data). */
fd_vote_state_versioned_t *
fd_vote_state_versioned_deserialize( fd_vote_state_versioned_t * self,
                                     uchar const *               payload,
                                     ulong                       payload_sz );

/* Serializes the vote state into a bincode-encoded buffer.  buf must
   have at least enough space for the encoded representation.  Returns
   0 on success, 1 on failure (e.g. buffer too small). */
int
fd_vote_state_versioned_serialize( fd_vote_state_versioned_t const * self,
                                   uchar *                           buf,
                                   ulong                             buf_sz );

/* Computes the serialized size of self arithmetically without
   writing.  Returns the size in bytes, or 0 if self has an unrecognized
   discriminant. */
ulong
fd_vote_state_versioned_serialized_size( fd_vote_state_versioned_t const * self );

/**********************************************************************/
/* Direct field accessors                                             */
/* Read fields directly from raw bincode-encoded vote account data    */
/* without full deserialization.                                       */
/**********************************************************************/

/* Reads the node_pubkey directly from raw bincode-encoded vote
   account data.  Returns 0 on success, 1 on error. */
int
fd_vote_account_node_pubkey( uchar const *  data,
                             ulong          data_sz,
                             fd_pubkey_t *  out );

/* Reads the commission value.  For v1_14_11/v3 returns the raw
   commission byte; for v4 returns inflation_rewards_commission_bps/100.
   Returns 0 on success, 1 on error. */
int
fd_vote_account_commission( uchar const * data,
                            ulong         data_sz,
                            uchar *       out );

/* Reads the last_timestamp directly from raw bincode-encoded vote
   account data.  Returns 0 on success, 1 on error. */
int
fd_vote_account_last_timestamp( uchar const *               data,
                                ulong                       data_sz,
                                fd_vote_block_timestamp_t * out );

/* Returns 1 if the vote account is v4 with has_bls_pubkey_compressed
   set, 0 otherwise. */
int
fd_vote_account_is_v4_with_bls_pubkey( uchar const * data,
                                       ulong         data_sz );

/* Seeks through variable-length fields and returns a zero-copy pointer
   to the epoch_credits entries inside the raw buffer.  *cnt is set to
   the number of entries.  Returns NULL on error. */
fd_vote_epoch_credits_t const *
fd_vote_account_epoch_credits( uchar const * data,
                               ulong         data_sz,
                               ulong *       cnt );

/* fd_vote_instruction_deserialize deserializes a vote instruction from
   bincode-encoded data into the provided instruction struct.  Dynamic
   data (deques, arrays) is placed in memory embedded within the
   sub-structs of instruction.

   On success returns instruction.  Returns NULL on failure (malformed
   data). */

fd_vote_instruction_t *
fd_vote_instruction_deserialize( fd_vote_instruction_t * instruction,
                                 uchar const *           data,
                                 ulong                   data_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_vote_fd_vote_codec_h */

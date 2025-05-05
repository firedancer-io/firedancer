/* fd_restore_manifest.c implements streaming decode of a Solana
   snapshot "manifest" file.  The "manifest" is an abomination of
   variable-length bincode structures.  When deserializing everything
   upfront, the scratch memory use is hard to control (potentially
   unbounded). */

#include "../../flamenco/types/fd_types.h"

/* Decode steps */

#define FD_MANIFEST_PT_1_1    0x01  /* bank / blockhash queue */
#define FD_MANIFEST_PT_1_2    0x02  /* bank / blockhash queue / last hash */
#define FD_MANIFEST_PT_1_3    0x03  /* bank / blockhash queue */
#define FD_MANIFEST_PT_3      0x05  /* bank */
#define FD_MANIFEST_PT_4      0x06  /* ancestors list */
#define FD_MANIFEST_PT_5      0x07  /* bank */
#define FD_MANIFEST_PT_6      0x08  /* hard forks list */
#define FD_MANIFEST_PT_7      0x09  /* bank */
#define FD_MANIFEST_PT_8      0x0a  /* "hashes per tick" */
#define FD_MANIFEST_PT_9      0x0b  /* bank */
#define FD_MANIFEST_PT_10_1   0x0c  /* vote account header */
#define FD_MANIFEST_PT_10_2   0x0d  /* vote account data */
#define FD_MANIFEST_PT_10_3   0x0e  /* vote account trailer */
#define FD_MANIFEST_PT_11     0x0f  /* bank / stakes */
#define FD_MANIFEST_PT_12     0x10  /* stake delegations */
#define FD_MANIFEST_PT_13     0x11  /* bank / stakes */
#define FD_MANIFEST_PT_14     0x12  /* stake history */
#define FD_MANIFEST_PT_15     0x13  /* bank */
#define FD_MANIFEST_PT_16     0x14  /* unused account */
#define FD_MANIFEST_PT_17     0x15  /* bank */
#define FD_MANIFEST_PT_18_1   0x16  /* epoch stakes */
#define FD_MANIFEST_PT_18_1_1 0x17  /* vote account header */
#define FD_MANIFEST_PT_18_1_2 0x18  /* vote account data */
#define FD_MANIFEST_PT_18_1_3 0x19  /* vote account trailer */
#define FD_MANIFEST_PT_18_2   0x1a  /* epoch stakes / stakes */
#define FD_MANIFEST_PT_18_3   0x1b  /* epoch stakes / stake delegations */
#define FD_MANIFEST_PT_18_4   0x1c  /* epoch stakes / stakes */
#define FD_MANIFEST_PT_18_5   0x1d  /* epoch stakes / stake history */
#define FD_MANIFEST_PT_18_6   0x1e  /* epoch stakes */
#define FD_MANIFEST_PT_18_7_1 0x1f  /* epoch stakes / node id mapping */
#define FD_MANIFEST_PT_18_7_2 0x20  /* epoch stakes / node id mapping */
#define FD_MANIFEST_PT_18_7_3 0x21  /* epoch stakes / node id mapping */
#define FD_MANIFEST_PT_18_8   0x22  /* epoch stakes */
#define FD_MANIFEST_PT_18_9   0x23  /* epoch stakes */
#define FD_MANIFEST_PT_19     0x24  /* bank, db */
#define FD_MANIFEST_PT_20     0x25  /* db / storages */

/* Data structures */

struct __attribute__((packed)) fd_manifest_pt1_1 {
  ulong bhq_last_hash_index;
  uchar bhq_last_hash_present;
};
typedef struct fd_manifest_pt1 fd_manifest_pt1_t;

struct __attribute__((packed)) fd_manifest_pt1_3 {
  ulong bhq_last_hash_index;
  uchar bhq_last_hash_present;
};
typedef struct fd_manifest_pt1 fd_manifest_pt1_t;

struct __attribute__((packed)) fd_manifest_pt1 {
  ulong bhq_last_hash_index;
  uchar bhq_last_hash_present;
};
typedef struct fd_manifest_pt1 fd_manifest_pt1_t;

struct __attribute__((packed)) fd_manifest_pt3 {
  ulong bhq_max_age;
  ulong ancestors_len;
};
typedef struct fd_manifest_pt3 fd_manifest_pt3_t;

struct __attribute__((packed)) fd_manifest_pt5 {
  fd_hash_t hash;
  fd_hash_t parent_hash;
  ulong     parent_slot;
  ulong     hard_forks_len;
};
typedef struct fd_manifest_pt5 fd_manifest_pt5_t;

struct __attribute__((packed)) fd_manifest_pt7 {
  ulong transaction_count;
  ulong tick_height;
  ulong signature_count;
  ulong capitalization;
  ulong max_tick_height;
  uchar hashes_per_tick_present;
};
typedef struct fd_manifest_pt7 fd_manifest_pt7_t;

struct __attribute__((packed)) fd_manifest_pt9 {
  ulong  ticks_per_slot;
  ulong  ns_per_slot_lo;
  ulong  ns_per_slot_hi;
  ulong  genesis_creation_time;
  double slots_per_year;
  ulong  accounts_data_len;

  ulong  slot;
  ulong  epoch;
  ulong  block_height;

  fd_pubkey_t            collector_id;
  ulong                  collector_fees;
  fd_fee_calculator_t    fee_calculator;
  fd_fee_rate_governor_t fee_rate_governor;
  ulong                  collected_rent;
  fd_rent_collector_t    rent_collector;
  fd_inflation_t         inflation;

  ulong vote_accounts_len;
};
typedef struct fd_manifest_pt9 fd_manifest_pt9_t;

struct __attribute__((packed)) fd_manifest_pt10_1 {
  fd_pubkey_t key;
  ulong stake;
  ulong lamports;
  ulong data_len;
};
typedef struct fd_manifest_pt10_1 fd_manifest_pt10_1_t;

struct __attribute__((packed)) fd_manifest_pt10_3 {
  uchar executable;
  ulong rent_epoch;
};
typedef struct fd_manifest_pt10_3 fd_manifest_pt10_3_t;

struct __attribute__((packed)) fd_manifest_pt13 {
  ulong unused;
  ulong epoch;
  ulong stake_history_len;
};
typedef struct fd_manifest_pt13 fd_manifest_pt13_t;

struct __attribute__((packed)) fd_manifest_pt15 {
  fd_pubkey_t unused1;
  fd_pubkey_t unused2;
  ulong unused3_len;
};
typedef struct fd_manifest_pt15 fd_manifest_pt15_t;

struct __attribute__((packed)) fd_manifest_pt18_1 {
  ulong key;
  ulong vote_accounts_len;
};
typedef struct fd_manifest_pt18_1 fd_manifest_pt18_1_t;

struct __attribute__((packed)) fd_manifest_pt18_6 {
  ulong total_stake;
  ulong node_id_mapping_len;
};
typedef struct fd_manifest_pt18_6 fd_manifest_pt18_6_t;

struct __attribute__((packed)) fd_manifest_pt18_7_1 {
  fd_pubkey_t pubkey;
  ulong       vote_accounts_len;
};
typedef struct fd_manifest_pt18_7_1 fd_manifest_pt18_7_1_t;

struct __attribute__((packed)) fd_manifest_pt19 {
  uchar is_delta;
  ulong storages_len;
};
typedef struct fd_manifest_pt19 fd_manifest_pt19_t;

struct __attribute__((packed)) fd_manifest_pt20 {

};
typedef struct fd_manifest_pt20 fd_manifest_pt20_t;

struct fd_restore_manifest_ctx {
  uint state;
  uchar * buf;
  ulong   buf_sz;
  ulong   buf_max;

  ulong statev[3];
};

typedef struct fd_restore_manifest_ctx fd_restore_manifest_ctx_t;

static void const *
buf_frag( fd_restore_manifest_ctx_t * ctx,
          void const * frag,
          ulong *      p_frag_sz,
          ulong        want_sz ) {
  FD_TEST( want_sz<=ctx->buf_max );
  ulong frag_sz = *p_frag_sz;
  if( FD_UNLIKELY( frag_sz<want_sz ) ) {
    FD_TEST( ctx->buf_sz < want_sz );
    ulong rem_sz = want_sz - ctx->buf_sz;
    frag_sz = fd_ulong_min( frag_sz, rem_sz );
    fd_memcpy( ctx->buf + ctx->buf_sz, frag, frag_sz );
    ctx->buf_sz += frag_sz;
    (*p_frag_sz) -= frag_sz;
    if( ctx->buf_sz == want_sz ) {
      ctx->buf_sz = 0UL;
      return ctx->buf;
    }
    return NULL;
  }
  (*p_frag_sz) -= want_sz;
  return frag;
}

static ushort const
manifest_node_len[] = {
  [ FD_MANIFEST_PT_1_1    ] = sizeof(fd_manifest_pt1_t),
  [ FD_MANIFEST_PT_1_2    ] = sizeof(fd_pubkey_t),
  [ FD_MANIFEST_PT_1_3    ] = FD_HASH_HASH_AGE_PAIR_FOOTPRINT,
  [ FD_MANIFEST_PT_3      ] = sizeof(fd_manifest_pt3_t),
  [ FD_MANIFEST_PT_4      ] = FD_SLOT_PAIR_FOOTPRINT,
  [ FD_MANIFEST_PT_5      ] = sizeof(fd_manifest_pt5_t),
  [ FD_MANIFEST_PT_6      ] = FD_SLOT_PAIR_FOOTPRINT,
  [ FD_MANIFEST_PT_7      ] = sizeof(fd_manifest_pt7_t),
  [ FD_MANIFEST_PT_8      ] = sizeof(uchar),
  [ FD_MANIFEST_PT_9      ] = sizeof(fd_manifest_pt9_t),
  [ FD_MANIFEST_PT_10_1   ] = sizeof(fd_manifest_pt10_1_t),
  [ FD_MANIFEST_PT_10_2   ] = 0,
  [ FD_MANIFEST_PT_10_3   ] = sizeof(fd_manifest_pt10_3_t),
  [ FD_MANIFEST_PT_11     ] = sizeof(ulong),
  [ FD_MANIFEST_PT_12     ] = FD_DELEGATION_PAIR_FOOTPRINT,
  [ FD_MANIFEST_PT_13     ] = sizeof(fd_manifest_pt13_t),
  [ FD_MANIFEST_PT_14     ] = FD_STAKE_HISTORY_ENTRY_FOOTPRINT,
  [ FD_MANIFEST_PT_15     ] = sizeof(fd_manifest_pt15_t),
  [ FD_MANIFEST_PT_16     ] = FD_PUBKEY_U64_PAIR_FOOTPRINT,
  [ FD_MANIFEST_PT_17     ] = sizeof(ulong),
  [ FD_MANIFEST_PT_18_1   ] = sizeof(fd_manifest_pt18_1_t),
  [ FD_MANIFEST_PT_18_1_1 ] = sizeof(fd_manifest_pt10_1_t),
  [ FD_MANIFEST_PT_18_1_2 ] = 0,
  [ FD_MANIFEST_PT_18_1_3 ] = sizeof(fd_manifest_pt10_3_t),
  [ FD_MANIFEST_PT_18_2   ] = sizeof(ulong),
  [ FD_MANIFEST_PT_18_3   ] = FD_DELEGATION_PAIR_FOOTPRINT,
  [ FD_MANIFEST_PT_18_4   ] = sizeof(fd_manifest_pt13_t),
  [ FD_MANIFEST_PT_18_5   ] = FD_STAKE_HISTORY_ENTRY_FOOTPRINT,
  [ FD_MANIFEST_PT_18_6   ] = sizeof(fd_manifest_pt18_6_t),
  [ FD_MANIFEST_PT_18_7_1 ] = sizeof(fd_manifest_pt18_7_1_t),
  [ FD_MANIFEST_PT_18_7_2 ] = sizeof(fd_pubkey_t),
  [ FD_MANIFEST_PT_18_7_3 ] = sizeof(ulong),
  [ FD_MANIFEST_PT_18_8   ] = sizeof(ulong),
  [ FD_MANIFEST_PT_18_9   ] = FD_PUBKEY_PUBKEY_PAIR_FOOTPRINT,
};

ulong
fd_restore_manifest_frag( fd_restore_manifest_ctx_t * ctx,
                          void const * restrict       frag,
                          ulong                       frag_sz ) {
  switch( ctx->state ) {
  case FD_MANIFEST_PT_1: {
    fd_manifest_pt1_t const * pt1 = buf_frag( ctx, frag, &frag_sz, sizeof(fd_manifest_pt1_t) );
    (void)pt1;
    ctx->state = FD_MANIFEST_PT_2;
    ctx->statev[0] = pt1->bhq_last_hash_present;
    return frag_sz;
  }
  case FD_MANIFEST_PT_2:
    break;
  }
}

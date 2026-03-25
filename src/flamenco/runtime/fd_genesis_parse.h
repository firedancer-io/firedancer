#ifndef HEADER_fd_src_flamenco_runtime_fd_genesis_parse_h
#define HEADER_fd_src_flamenco_runtime_fd_genesis_parse_h

#include "../../util/fd_util_base.h"
#include "../fd_flamenco_base.h"
#include "../types/fd_types_custom.h"

/* Hardcoded max serialized genesis blob size */
#define FD_GENESIS_MAX_MESSAGE_SIZE (1UL<<28) /* 256 MiB */

/* Hardcoded genesis array limits */
#define FD_GENESIS_ACCOUNT_MAX_COUNT (65536UL)
#define FD_GENESIS_BUILTIN_MAX_COUNT (16UL)

#define FD_GENESIS_TYPE_TESTNET     (0)
#define FD_GENESIS_TYPE_MAINNET     (1)
#define FD_GENESIS_TYPE_DEVNET      (2)
#define FD_GENESIS_TYPE_DEVELOPMENT (3)

struct fd_genesis_account_off {
  ulong pubkey_off;
  ulong owner_off;
};
typedef struct fd_genesis_account_off fd_genesis_account_off_t;

struct fd_genesis_builtin_off {
  ulong data_len_off;
  ulong pubkey_off;
};
typedef struct fd_genesis_builtin_off fd_genesis_builtin_off_t;

/* fd_genesis_t helps interpret a genesis blob.  Contains deserialized
   values and offsets to binary account data.  This is a very large
   struct (~1 MiB) so it should not be stack allocated. */

struct fd_genesis {
  ulong creation_time;
  uint  cluster_type;

  struct {
    ulong ticks_per_slot;
    ulong tick_duration_secs;
    ulong tick_duration_ns;
    ulong target_tick_count;
    ulong hashes_per_tick;
  } poh;

  struct {
    ulong target_lamports_per_signature;
    ulong target_signatures_per_slot;
    ulong min_lamports_per_signature;
    ulong max_lamports_per_signature;
    uchar burn_percent;
  } fee_rate_governor;

  struct {
    ulong  lamports_per_uint8_year;
    double exemption_threshold;
    uchar  burn_percent;
  } rent;

  struct {
    double initial;
    double terminal;
    double taper;
    double foundation;
    double foundation_term;
  } inflation;

  struct {
    ulong slots_per_epoch;
    ulong leader_schedule_slot_offset;
    uchar warmup;
    ulong first_normal_epoch;
    ulong first_normal_slot;
  } epoch_schedule;

  ulong builtin_cnt;
  ulong account_cnt;

  fd_genesis_builtin_off_t builtin[ FD_GENESIS_BUILTIN_MAX_COUNT ];
  fd_genesis_account_off_t account[ FD_GENESIS_ACCOUNT_MAX_COUNT ];
};

typedef struct fd_genesis fd_genesis_t;

struct fd_genesis_account {
  fd_pubkey_t       pubkey;
  fd_account_meta_t meta; /* do not use fd_account_data() */
  uchar const *     data;
};

typedef struct fd_genesis_account fd_genesis_account_t;

struct fd_genesis_builtin {
  fd_pubkey_t   pubkey;
  ulong         dlen;
  uchar const * data;
};

typedef struct fd_genesis_builtin fd_genesis_builtin_t;

FD_PROTOTYPES_BEGIN

/* fd_genesis_parse decodes a bincode-encoded 'GenesisConfig'.
   The genesis blob is found in the genesis archive, e.g.
   GET http://<rpc>/genesis.tar.bz2

   Agave type definition:
   https://github.com/anza-xyz/solana-sdk/blob/genesis-config%40v3.0.0/genesis-config/src/lib.rs#L59

   Decodes the message at bin of size bin_sz.  On success, populates
   and returns the fd_genesis_t object.  On failure, logs warning and
   returns NULL.  Reasons for failure include:
   - Deserialize failed (invalid bincode?)
   - Hardcoded limit exceeded (builtin/account count)
   - Garbage trailing data */

fd_genesis_t *
fd_genesis_parse( fd_genesis_t * genesis,
                  uchar const *  bin,
                  ulong          bin_sz );

/* Account/builtin getter */

fd_genesis_account_t *
fd_genesis_account( fd_genesis_t const *   genesis,
                    uchar const *          bin,
                    fd_genesis_account_t * out,
                    ulong                  idx );

fd_genesis_builtin_t *
fd_genesis_builtin( fd_genesis_t const *   genesis,
                    uchar const *          bin,
                    fd_genesis_builtin_t * out,
                    ulong                  idx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_genesis_parse_h */

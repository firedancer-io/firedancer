#ifndef HEADER_fd_src_flamenco_runtime_fd_genesis_parse_h
#define HEADER_fd_src_flamenco_runtime_fd_genesis_parse_h

#include "../../util/fd_util_base.h"
#include "../fd_flamenco_base.h"

/* These two constants are not defined at the Solana protocol level
   and are instead used to bound out the amount of memory that will be
   allocated for the genesis message. */
#define FD_GENESIS_ACCOUNT_MAX_COUNT (2048UL)
#define FD_GENESIS_BUILTIN_MAX_COUNT (16UL)
#define FD_GENESIS_MAX_MESSAGE_SIZE  (1024UL*1024UL*10UL) /* 10MiB */

#define FD_GENESIS_TYPE_TESTNET     (0)
#define FD_GENESIS_TYPE_MAINNET     (1)
#define FD_GENESIS_TYPE_DEVNET      (2)
#define FD_GENESIS_TYPE_DEVELOPMENT (3)

struct fd_genesis_account {
  uchar             pubkey[32];
  fd_account_meta_t meta;
  uchar             data[];
};
typedef struct fd_genesis_account fd_genesis_account_t;

struct fd_genesis {
  /* total_sz represents the total memory footprint taken up by
     fd_genesis_t and the variable length data that follows. */
  ulong total_sz;

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

  ulong accounts_len;
  uint  accounts_off[ FD_GENESIS_ACCOUNT_MAX_COUNT ];
  ulong builtin_len;
  uint  builtin_off[ FD_GENESIS_BUILTIN_MAX_COUNT ];

  /* variable length account data follows */
};
typedef struct fd_genesis fd_genesis_t;

FD_PROTOTYPES_BEGIN

/* fd_genesis_parse is a bincode parser for an encoded genesis type
   which outputs a pointer to a decoded struct (fd_genesis_t).
   A genesis_mem which is a region of memory assumed to be at minimum
   of footprint FD_GENESIS_MAX_MESSAGE_SIZE with alignment of
   alignof(fd_genesis_t) is passed in along with a binary blob (bin) of
   size (bin_sz).

   The data in the binary blob will be assumed to be a bincode encoded
   genesis type and will be decoded into a fd_genesis_t
   type using the memory in genesis_mem.  If the type is a valid bincode
   encoded genesis type and it doesn't violate any Solana cluster
   protocol limits as well as any Firedancer specific buffer limits
   (e.g. number of accounts, total accounts footprint, etc.) then a
   pointer to a valid fd_genesis_t will be returned.  If the decoding
   fails due to being an invalid input or violating aforementioned
   limits, then NULL will be returned.

   The bincode encoded type matches the Agave client GenesisConfig type.
   https://github.com/anza-xyz/solana-sdk/blob/genesis-config%40v3.0.0/genesis-config/src/lib.rs#L59 */

fd_genesis_t *
fd_genesis_parse( void *        genesis_mem,
                  uchar const * bin,
                  ulong         bin_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_genesis_parse_h */

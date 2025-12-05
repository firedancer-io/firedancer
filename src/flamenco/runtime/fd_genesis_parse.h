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

};
typedef struct fd_genesis fd_genesis_t;

FD_PROTOTYPES_BEGIN

fd_genesis_t *
fd_genesis_parse( uchar const * mem_in,
                  ulong         sz_in,
                  ulong *       sz_out,
                  uchar *       genesis_out );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_genesis_parse_h */

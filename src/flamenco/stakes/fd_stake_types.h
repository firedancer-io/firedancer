#ifndef HEADER_fd_src_flamenco_stakes_fd_stake_types_h
#define HEADER_fd_src_flamenco_stakes_fd_stake_types_h

#include "../types/fd_types_custom.h"

#define FD_STAKE_STATE_SZ (200UL)

#define FD_STAKE_STATE_UNINITIALIZED 0U
#define FD_STAKE_STATE_INITIALIZED   1U
#define FD_STAKE_STATE_STAKE         2U
#define FD_STAKE_STATE_REWARDS_POOL  3U

struct __attribute__((packed)) fd_stake_meta {
  ulong       rent_exempt_reserve;
  fd_pubkey_t staker;
  fd_pubkey_t withdrawer;
  long        unix_timestamp;
  ulong       epoch;
  fd_pubkey_t custodian;
};
typedef struct fd_stake_meta fd_stake_meta_t;

struct __attribute__((packed)) fd_delegation {
  fd_pubkey_t voter_pubkey;
  ulong       stake;
  ulong       activation_epoch;
  ulong       deactivation_epoch;
  union {
    double    warmup_cooldown_rate;
    ulong     warmup_cooldown_rate_bits;
  };
};
typedef struct fd_delegation fd_delegation_t;

struct __attribute__((packed)) fd_stake {
  fd_delegation_t delegation;
  ulong           credits_observed;
};
typedef struct fd_stake fd_stake_t;

struct __attribute__((packed)) fd_stake_state {
  uint stake_type;
  union {
    struct __attribute__((packed)) {
      fd_stake_meta_t meta;
    } initialized;

    struct __attribute__((packed)) {
      fd_stake_meta_t meta;
      fd_stake_t      stake;
      uchar           stake_flags;
    } stake;
  };
};
typedef struct fd_stake_state fd_stake_state_t;

FD_PROTOTYPES_BEGIN

/* fd_stake_state_view attempts to reinterpret the pointer to serialized
   stake state data as a pointer to a fd_stake_state_t struct.

   Runs various canonical bincode deserialization checks.  If they pass,
   returns a cast of data.  On deserialization failure, returns NULL.
   Note that trailing data is silently ignored. */

fd_stake_state_t const *
fd_stake_state_view( uchar const * data,
                     ulong         data_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_stake_types_h */

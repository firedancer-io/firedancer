#ifndef HEADER_fd_src_flamenco_genesis_fd_genesis_create_h
#define HEADER_fd_src_flamenco_genesis_fd_genesis_create_h

/* fd_genesis_create.h is a tool for creating Solana genesis blobs.
   A genesis blob is used to bootstrap a Solana ledger. */

#include "../fd_flamenco_base.h"


/* fd_genesis_options_t exists as a convenient way to specify options
   for genesis creation. */

struct fd_genesis_options {
  fd_pubkey_t identity_pubkey;
  fd_pubkey_t faucet_pubkey;
  fd_pubkey_t stake_pubkey;
  fd_pubkey_t vote_pubkey;

  ulong creation_time; /* unix time, i.e. seconds since the unix epoch */
  ulong faucet_balance; /* in lamports */

  ulong hashes_per_tick; /* 0 means unset */
  ulong ticks_per_slot;
  ulong target_tick_duration_micros;

  ulong fund_initial_accounts;
  ulong fund_initial_amount_lamports;
};

typedef struct fd_genesis_options fd_genesis_options_t;

FD_PROTOTYPES_BEGIN

/* fd_genesis_create creates a 'genesis.bin' compatible genesis blob.
   (Bincode encoded fd_genesis_solana_t)  [buf,bufsz) it the output
   memory region into which the genesis blob will be written.  options
   points to a struct containing the genesis configuration parameters.
   Additionally, the feature gates corresponding to the pubkeys
   feature_gates[ i ] for i in [0, feature_gate_cnt) will be active from
   genesis.  feature_gates==NULL is okay if feature_gate_cnt==0.

   Returns the number of bytes in the output memory region used on
   success.  On failure, returns 0UL and logs reason for error.

   Assumes that caller is attached to an fd_scratch with sufficient
   memory to buffer intermediate data (8192 + 128*n space, 2 frames).

   THIS METHOD IS NOT SAFE FOR PRODUCTION USE.
   It is intended for development only. */

ulong
fd_genesis_create( void *                       buf,
                   ulong                        bufsz,
                   fd_genesis_options_t const * options,
                   fd_pubkey_t          const * feature_gates,
                   ulong                        feature_gate_cnt );

/* TODO Add method to estimate the scratch and genesis blob size given a pod */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_genesis_fd_genesis_create_h */

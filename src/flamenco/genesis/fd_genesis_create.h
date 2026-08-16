#ifndef HEADER_fd_src_flamenco_genesis_fd_genesis_create_h
#define HEADER_fd_src_flamenco_genesis_fd_genesis_create_h

/* fd_genesis_create.h is a tool for creating Solana genesis blobs.
   A genesis blob is used to bootstrap a Solana ledger. */

#include "../fd_flamenco_base.h"
#include "../features/fd_features.h"
#include "../runtime/program/vote/fd_vote_codec.h"


/* fd_genesis_options_t exists as a convenient way to specify options
   for genesis creation. */

struct fd_genesis_options {
  fd_pubkey_t identity_pubkey;
  fd_pubkey_t faucet_pubkey;
  fd_pubkey_t stake_pubkey;
  fd_pubkey_t vote_pubkey;

  ulong creation_time;      /* unix time, i.e. seconds since the unix epoch */
  ulong faucet_balance;     /* in lamports */
  ulong vote_account_stake; /* in lamports */

  ulong hashes_per_tick; /* 0 means unset */
  ulong ticks_per_slot;
  ulong target_tick_duration_micros;

  ulong fund_initial_accounts;
  ulong fund_initial_amount_lamports;

  int   warmup_epochs;

  /* alpenglow creates a genesis for a cluster running alpenglow
     consensus from slot 0 rather than TowerBFT.  The vote account is
     written as a VoteStateV4 carrying identity_bls_pubkey and funded
     for the validator admission ticket, and the alpenglow feature gate,
     genesis certificate and epoch inflation accounts are added.

     The caller is responsible for enabling the alpenglow dependency
     feature gates in features (bls_pubkey_management_in_vote_account
     and validator_admission_ticket) and for leaving hashes_per_tick
     unset.  The alpenglow gate itself is not in Firedancer's feature
     map -- Firedancer decides alpenglow from its topology, not from a
     feature -- so this writes that one account directly. */

  int   alpenglow;

  /* identity_bls_pubkey is the compressed BLS12-381 pubkey the
     validator signs alpenglow votes with, derived from the authorized
     voter key with fd_bls12_381_kdf.  Only read when alpenglow is set,
     and it must be a real key: epoch_stakes gives no weight to a vote
     account without one, so a zero here means the validator cannot
     vote. */

  uchar identity_bls_pubkey[ FD_BLS_PUBKEY_COMPRESSED_SZ ];

  /* features points to an externally owned feature map.
     Adds a feature account to the genesis blob for feature enabled at
     slot 0.  If features==NULL, creates no feature accounts. */
  fd_features_t const * features;
};

typedef struct fd_genesis_options fd_genesis_options_t;

FD_PROTOTYPES_BEGIN

/* fd_genesis_create creates a 'genesis.bin' compatible genesis blob.
   (Bincode encoded Solana GenesisConfig)  [buf,bufsz) is the output
   memory region into which the genesis blob will be written.  options
   points to a struct containing the genesis configuration parameters.

   Returns the number of bytes in the output memory region used on
   success.  On failure, returns 0UL and logs reason for error.

   Assumes that caller is attached to an fd_scratch with sufficient
   memory to buffer intermediate data (16384 + 128*n space, 2 frames).
   TODO: Replace with spad

   THIS METHOD IS NOT SAFE FOR PRODUCTION USE.
   It is intended for development only. */

ulong
fd_genesis_create( void *                       buf,
                   ulong                        bufsz,
                   fd_genesis_options_t const * options );

/* TODO Add method to estimate the scratch and genesis blob size given options */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_genesis_fd_genesis_create_h */

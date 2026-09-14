#ifndef HEADER_fd_src_flamenco_genesis_fd_genesis_create_h
#define HEADER_fd_src_flamenco_genesis_fd_genesis_create_h

/* fd_genesis_create.h is a tool for creating Solana genesis blobs.
   A genesis blob is used to bootstrap a Solana ledger. */

#include "../fd_flamenco_base.h"
#include "../features/fd_features.h"


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

  uchar const * token_program_elf;
  ulong         token_program_elf_sz;

  int   warmup_epochs;

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
   memory to buffer intermediate data.  Without token accounts, allow
   16384 + 128*n bytes for n funded accounts.  With token accounts,
   allow 16384 + 704*n + token_program_elf_sz bytes.  Requires 2
   frames.

   THIS METHOD IS NOT SAFE FOR PRODUCTION USE.
   It is intended for development only. */

ulong
fd_genesis_create( void *                       buf,
                   ulong                        bufsz,
                   fd_genesis_options_t const * options );

/* The number of token accounts created for each primordial account, and
   the token balance each of them holds, when token_program_elf is
   set. */

#define FD_GENESIS_TOKEN_ACCOUNTS_PER_ACCOUNT (2UL)
#define FD_GENESIS_TOKEN_AMOUNT               (1UL<<40)

/* fd_genesis_token_mint_address writes the address of the token mint to
   out.

   fd_genesis_token_account_address writes the address of a token
   account to out.  acct_idx is the index of the owning primordial
   account, in [0,fund_initial_accounts), and token_idx selects one of
   that owner's accounts, in
   [0,FD_GENESIS_TOKEN_ACCOUNTS_PER_ACCOUNT).

   Both are pure functions of their inputs, so callers can rediscover
   the addresses without parsing the genesis blob. */

void
fd_genesis_token_mint_address( fd_pubkey_t * out );

void
fd_genesis_token_account_address( fd_pubkey_t * out,
                                  ulong         acct_idx,
                                  ulong         token_idx );

/* TODO Add method to estimate the scratch and genesis blob size given options */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_genesis_fd_genesis_create_h */

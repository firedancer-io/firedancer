#ifndef HEADER_fd_src_flamenco_features_fd_feature_snoop_h
#define HEADER_fd_src_flamenco_features_fd_feature_snoop_h

#include "fd_features.h"
#include "../runtime/fd_system_ids.h"

/* fd_feature_snoop captures feature-gate account state observed while
   accounts stream by during snapshot/genesis load, so the bank's feature
   set can be populated without reading the accounts back from the
   accounts database afterwards. */

FD_PROTOTYPES_BEGIN

/* fd_feature_snoop_t accumulates, per known feature id, the decoded
   contents of any feature account seen during load.  present[index]
   records whether a feature account for that id appeared, and
   is_active[index]/activation_slot[index] record its decoded contents.
   Zero-initialize before use (present[*]==0 means "no account seen"). */

#define FD_FEATURE_SNOOP_CNT FD_FEATURE_ID_CNT

struct fd_feature_snoop {
  uchar present        [ FD_FEATURE_SNOOP_CNT ];
  uchar is_active      [ FD_FEATURE_SNOOP_CNT ];
  ulong activation_slot[ FD_FEATURE_SNOOP_CNT ];
};

typedef struct fd_feature_snoop fd_feature_snoop_t;

struct fd_epoch_schedule;
typedef struct fd_epoch_schedule fd_epoch_schedule_t;

/* fd_feature_snoop_account records one streamed account into snoop if
   it is a feature-gate account (owner==feature program) whose address
   is a known feature id.  owner/data/data_len point at the account's
   raw contents (e.g. snooped from the load stream); lamports==0
   accounts are ignored.  Non-feature accounts are a no-op. */

void
fd_feature_snoop_account_full( fd_feature_snoop_t * snoop,
                               fd_pubkey_t const *  pubkey,
                               ulong                lamports,
                               uchar const *        owner,
                               uchar const *        data,
                               ulong                data_len );

/* Inline pre-filter.  A snapshot load calls this once per account -- on
   mainnet roughly 1.1 G times -- and virtually none are owned by the feature
   program, so the out-of-line call was mostly frame setup for an immediate
   reject (measured: 4.6% of the snapin tile, half of it prologue/epilogue).

   This can only skip calls that _full would itself have rejected on its owner
   compare; anything matching the prefix takes the unchanged full path. */

static inline void
fd_feature_snoop_account( fd_feature_snoop_t * snoop,
                          fd_pubkey_t const *  pubkey,
                          ulong                lamports,
                          uchar const *        owner,
                          uchar const *        data,
                          ulong                data_len ) {
  if( FD_LIKELY( !lamports ) ) return;
  if( FD_LIKELY( fd_ulong_load_8( owner )!=
                 fd_ulong_load_8( fd_solana_feature_program_id.uc ) ) ) return;
  fd_feature_snoop_account_full( snoop, pubkey, lamports, owner, data, data_len );
}

/* fd_feature_snoop_finalize populates the feature set from snoop,
   applying the same per-feature logic as fd_features_restore but using
   only the snooped account state: cleaned-up features are set to 0,
   reverted features skipped, every other feature defaults to
   FD_FEATURE_DISABLED and is then set to its activation slot if its
   account was present and active, or pre-populated at slot+1 if its
   account was present but inactive and we are at the last slot before
   an epoch boundary. */

void
fd_feature_snoop_finalize( fd_features_t *             features,
                           ulong                       slot,
                           fd_epoch_schedule_t const * epoch_schedule,
                           fd_feature_snoop_t const *  snoop );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_features_fd_feature_snoop_h */

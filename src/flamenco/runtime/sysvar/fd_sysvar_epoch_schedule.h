#ifndef HEADER_fd_src_flamenco_runtime_sysvar_epoch_schedule_h
#define HEADER_fd_src_flamenco_runtime_sysvar_epoch_schedule_h

/* fd_sysvar_epoch_schedule provides methods for epoch numbers, a native
   concept of the Solana runtime.

   Address: SysvarEpochSchedu1e111111111111111111111111

   Every Solana slot is assigned an epoch number (ulong), starting with
   epoch 0.  The epoch number either stays constant or increments by one
   between two slots.

   The length of an epoch is the count of consecutive slots that have
   the same epoch number.  The series of epochs consists of two parts:
   The warmup period (which may span zero epochs), and the constant
   period (which is infinite).

   In the warmup period, the length of an epoch starts small and
   exponentially increases.  The length of each epoch in the warmup
   period is 2^x where x is (epoch_number - min_exp).  min_exp is
   ceil(log2(FD_EPOCH_LEN_MIN)).

   In the constant period, the length of each epoch stays the same.
   Note that the Solana protocol may introduce a breaking change in the
   future that changes the epoch length.  The code does not yet account
   for that.

   The epoch schedule is used to derive the epoch number of each slot.
   It does this by specifying at which slots the epoch number increments
   (epoch boundary).

   The epoch schedule sysvar contains epoch scheduling constants used to
   make various epoch-related calculations. */

#include "../../fd_flamenco_base.h"
#include "../context/fd_exec_slot_ctx.h"

/* FD_EPOCH_LEN_MIN is a protocol constant specifying the smallest
   permitted epoch length.  This value is chosen to match
   MAX_LOCKOUT_HISTORY, which is the minimum slot count needed to reach
   finality in Tower BFT.

   https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/sdk/program/src/epoch_schedule.rs#L21 */

#define FD_EPOCH_LEN_MIN (32UL)

/* FD_EPOCH_LEN_MIN_TRAILING_ZERO stores the number of trailing zeroes of FD_EPOCH_LEN_MIN */
#define FD_EPOCH_LEN_MIN_TRAILING_ZERO (5UL)

/* FD_EPOCH_LEN_MAX is an implementation-defined epoch size limit.
   Technically, there is no epoch length limit (other than the max slot
   number ULONG_MAX).  We enforce a limit regardless to prevent overflow
   in math operations. */

#define FD_EPOCH_LEN_MAX (0xFFFFFFFFUL)

FD_PROTOTYPES_BEGIN

/* fd_epoch_schedule_derive derives an epoch schedule config from the
   given parameters.  New epoch schedule configurations should only be
   created using this function.  Returns schedule on success.
   On failure, returns NULL and logs reason.

   - schedule points to the epoch schedule struct to be initialized.
   - epoch_len configures the target slot count per epoch (>0)
   - leader_schedule_slot_offset configures when to generate the leader
     schedule for an epoch, measured in number of slots before the start
     of that epoch.
   - warmup controls whether to set a warmup period  (0 if disabled,
     1 if enabled). */

fd_epoch_schedule_t *
fd_epoch_schedule_derive( fd_epoch_schedule_t * schedule,
                          ulong                 epoch_len,
                          ulong                 leader_schedule_slot_offset,
                          int                   warmup );

/* fd_epoch_slot_cnt returns the number of slots in an epoch given an
   epoch schedule config and an epoch number.  Return value > 0 */

FD_FN_PURE ulong
fd_epoch_slot_cnt( fd_epoch_schedule_t const * schedule,
                   ulong                       epoch );

/* fd_epoch_slot0 returns the absolute slot number of the first slot
   in an epoch. */

FD_FN_PURE ulong
fd_epoch_slot0( fd_epoch_schedule_t const * schedule,
                ulong                       epoch );

/* fd_slot_to_epoch returns the epoch number of the epoch containing
   the given slot number. If out_offset_opt != NULL, on return
   *out_offset_opt contains the number of slots that precede the given
   slot in the same epoch.  U.B. if schedule->slots_per_epoch is zero. */

ulong
fd_slot_to_epoch( fd_epoch_schedule_t const * schedule,
                  ulong                       slot,
                  ulong *                     out_offset_opt );

ulong
fd_slot_to_leader_schedule_epoch( fd_epoch_schedule_t const * schedule,
                                  ulong                       slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_epoch_schedule_h */

#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_slot_history_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_slot_history_h

/* fd_sysvar_slot_history.h manages the "slot history" sysvar account
   (address SysvarS1otHistory11111111111111111111111111).

   This sysvar is a ring buffer of bits indicating which slots contained
   blocks.  Slots without blocks are called "skipped slots".  Updated
   during "slot freeze" (at the end of a slot). */

#include "fd_sysvar_base.h"

/* Forward declaration */
typedef struct fd_slot_history_global fd_slot_history_global_t;

/* FD_SYSVAR_SLOT_HISTORY_MAX_ENTRIES specifies the number of bits
   tracked by a slot history sysvar account.  (static/hardcoded)

   Agave v2.2.1: https://github.com/anza-xyz/solana-sdk/blob/slot-history%40v2.2.1/slot-history/src/lib.rs#L51 */

#define FD_SYSVAR_SLOT_HISTORY_MAX_ENTRIES 1048576UL

/* Slot Freeze ********************************************************/

/* fd_sysvar_slot_history_init creates a "slot history" sysvar account
   (overwrites an existing one).  Formats the slot history sysvar to
   have a bit vector with FD_SYSVAR_SLOT_HISTORY_MAX_ENTRIES bits all
   set to zero.  The "next slot" field is set to one.

   Agave v2.2.1: https://github.com/anza-xyz/solana-sdk/blob/slot-history%40v2.2.1/slot-history/src/lib.rs#L29 */

void
fd_sysvar_slot_history_init( fd_exec_slot_ctx_t * slot_ctx,
                             fd_spad_t *          spad );

/* fd_sysvar_slot_history_update updates the "slot history" sysvar after
   processing a block.  Called during "slot freeze".  Does not run for
   skipped slots.

   Has the following behavior:
   - Account does not exist
     => account is created (see fd_sysvar_slot_history_init)
   - Account exists, deserialize fails
     => process is terminated with FD_LOG_ERR
   - Account exists, deserialize succeeds
     => advance ring buffer, clear bits of evicted slots
     => set bit for current slot
     => set "next slot" field to current slot + 1

   https://github.com/anza-xyz/agave/blob/v2.3.2/runtime/src/bank.rs#L2276 */

void
fd_sysvar_slot_history_update( fd_exec_slot_ctx_t * slot_ctx,
                               fd_spad_t *          runtime_spad );

/* Ring buffer API ****************************************************/

/* fd_sysvar_slot_history_add sets the bit for the given slot number.
   If the slot number exceeds the current slot range of the sysvar's
   ring buffer, the ring buffer is advanced, and old bits are evicted.

   This function has a bug where an arbitrary other slot's bit is set if
   the given slot number is below the ring buffer's window.  Firedancer
   reproduces this bug since this is consensus-enshrined logic. */

void
fd_sysvar_slot_history_add( fd_slot_history_global_t * history,
                            ulong                      slot );

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_slot_history_h */

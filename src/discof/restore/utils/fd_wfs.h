#ifndef HEADER_fd_src_discof_restore_utils_fd_wfs_h
#define HEADER_fd_src_discof_restore_utils_fd_wfs_h

#include "../../../util/fd_util_base.h"

/* Wait-for-supermajority (WFS) is the coordinated-restart boot mode.
   Given a target (slot S, bank hash H) and a nonzero expected shred
   version V, the validator attempts to load full or full+incremental
   snapshot(s) reaching slot S.  It then verifies the bank hash, and
   refuses to replay or lead until a supermajority (>=80%) of stake is
   observed back online.  This lets every validator agree on the fork
   before resuming after a hard fork.

   All tiles that participate in WFS must invoke fd_wfs_mode() and
   obey the per-mode contract below.

   The classification has one input tuple (S, H, V) from config and
   one runtime input (boot_slot): the latter is the effective slot the
   validator booted at, i.e. the resulting bank slot after loading the
   snapshot(s).  WFS is configured when (S!=0 && H!=0 && V!=0).
   The classifier is a pure function of its inputs and yields exactly
   one mode:

     DISABLED   : not configured, behave as a normal boot.
     UNRESOLVED : configured but boot_slot not yet known.
     MATCH      : configured and boot_slot==S.  The bank is verified,
                  and tiles must wait until a supermajority of stake
                  is observed back online.
     NOOP       : configured but boot_slot>S (network has moved on).
                  Treated as a normal boot.
     ERROR      : configured but boot_slot<S and no snapshot bridged
                  the gap.  The operator must supply a snapshot at S.

   Contract:
     - Booting from genesis with WFS configured is not allowed (ERROR).
     - WFS completion is signalled once.  Consumers MUST be idempotent:
       a repeat signal after completion is dropped.
     - In MATCH mode the leader gate (the requirement that the
       validator's vote account is rooted before it may lead) should
       be suppressed until WFS completes.  Once complete, normal
       equivocation protection should resume.

    Regarding snapshot(s) (down)load:
     - A coordinated WFS restart implies moving backward in slots, and
       a change in V.  That means that any local snapshot on disk from
       V_old could correspond to slot>S, i.e. in the future.
     - When WFS uses full-only snapshot, the full snapshot's shred
       version must match V.  However, when full+incr is used, the full
       snapshot's shred version is V_old, whereas the incremental's
       shred version must be V.
     - At boot time, and especially around WFS, there is no trusted
       way to determine whether the network has moved past slot S.
       The validator needs to boot to observe the network, but it
       needs to know the network state to decide how to boot.
       The alternatives are to treat WFS configuration as:
         - strict:
             - if WFS is configured, the validator only boots at slot
               S, otherwise it crashes.  Only MATCH is supported.
             - Guarantees: (S, H, V) are verified.
             - Operational nuances: the operator must remove the WFS
               config right after the network restarts.
         - relaxed (Agave's behavior):
             - if WFS is configured, the validator has the option to
               treat it as a NOOP.
             - Guarantees: only (V) is verified;  (S, H) are skipped!
             - Operational nuances: during WFS, the operator must
               carefully choose "trusted" download sources (or none)
               and delete obsolete local snapshots.
       Firedancer chooses to follow Agave's behavior (relaxed).
     - The validator will choose the snapshot(s) with the highest
       effective slot (boot_slot), by inspecting download sources and
       local files.
     - When WFS is configured and the full snapshot is behind slot S,
       the snapct tile overrides [snapshots.incremental_snapshots] to
       true, enabling incremental snapshot loading to reach S.  When the
       full snapshot is at or past S (MATCH or NOOP), the config flag is
       respected as-is. */

#define FD_WFS_MODE_DISABLED   (0)
#define FD_WFS_MODE_UNRESOLVED (1)
#define FD_WFS_MODE_MATCH      (2)
#define FD_WFS_MODE_NOOP       (3)
#define FD_WFS_MODE_ERROR      (4)

FD_PROTOTYPES_BEGIN

/* fd_wfs_configured returns 1 iff the config enables WFS.  Arguments
   slot, hash_is_zero, and shred_version come from consensus config.
   All three conditions must hold together for WFS to be enabled. */

FD_FN_UNUSED static inline int
fd_wfs_configured( ulong slot,
                   int   hash_is_zero,
                   ulong shred_version ) {
  return slot!=0UL && !hash_is_zero && shred_version!=0UL;
}

/* fd_wfs_mode classifies WFS given the config triple and boot_slot,
   the effective boot slot (bank slot after any incremental is applied,
   not the full snapshot base slot).  Pass boot_slot==ULONG_MAX before
   the boot snapshot is known (yields UNRESOLVED when configured). */

FD_FN_UNUSED static inline int
fd_wfs_mode( ulong slot,
             int   hash_is_zero,
             ulong shred_version,
             ulong boot_slot ) {
  if( !fd_wfs_configured( slot, hash_is_zero, shred_version ) ) return FD_WFS_MODE_DISABLED;
  if( boot_slot==ULONG_MAX ) return FD_WFS_MODE_UNRESOLVED;
  if( boot_slot==slot      ) return FD_WFS_MODE_MATCH;
  if( boot_slot>slot       ) return FD_WFS_MODE_NOOP;
  return FD_WFS_MODE_ERROR;
}

FD_FN_UNUSED static inline char const *
fd_wfs_mode_str( int mode ) {
  switch( mode ) {
    case FD_WFS_MODE_DISABLED:   return "disabled";
    case FD_WFS_MODE_UNRESOLVED: return "unresolved";
    case FD_WFS_MODE_MATCH:      return "match";
    case FD_WFS_MODE_NOOP:       return "no-op";
    case FD_WFS_MODE_ERROR:      return "error";
    default:                     return "unknown";
  }
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_wfs_h */

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

   Tiles that classify a boot must invoke fd_wfs_mode() and obey the
   per-mode contract below; the snapshot selection path only needs to
   know whether WFS is configured.

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

   Specific rules:
     - boot_slot is the last manifest before FD_SSMSG_DONE, which
       ssload makes the boot bank.  Take the latest, never the
       maximum: a reset can legitimately lower the slot.
     - Booting from genesis with WFS configured is not allowed (ERROR).
     - WFS completion is signalled once.  Consumers MUST be idempotent:
       a repeat signal after completion is dropped.
     - In MATCH mode the leader gate (the requirement that the
       validator's vote account is rooted before it may lead) is
       suppressed, otherwise a coordinated restart deadlocks: no
       validator may lead, so no vote can ever root.  The suppression
       is permanent for the lifetime of the process; it is not undone
       when WFS completes.

    Regarding snapshot(s) (down)load:
     - A coordinated WFS restart implies moving backward in slots, and
       a change in V.  That means that any local snapshot on disk from
       V_old could correspond to slot>S, i.e. it would appear to be in
       the future.
     - When WFS uses a full-only snapshot, the full snapshot's shred
       version is V.  However, when full+incr is used, the full
       snapshot's shred version might be V_old, and only the
       incremental's is V.  This is why the shred version is verified
       once on the boot bank after the last manifest, never
       per-snapshot.
     - At boot time, and especially around WFS, there is no trusted
       way to determine whether the network has moved past slot S.
       The validator needs to boot to observe the network, but it
       needs to know the network state to decide how to boot.
       The alternatives are to treat WFS configuration as:
         - strict:
             - if WFS is configured, the validator only boots at slot
               S, otherwise it crashes.  Only mode MATCH is supported.
             - Guarantees: (S, H, V) are verified.
             - Operational nuances: the operator must remove the WFS
               config right after the network moves past WFS, otherwise
               a subsequent validator restart will fail.
         - relaxed (Agave's behavior):
             - if WFS is configured, the validator has the option to
               treat it as a NOOP if it believes that the network has
               already moved forward.
             - Guarantees:
                 - in MATCH: (S, H, V) are verified.
                 - in NOOP: only (V) is verified;  (S, H) are skipped!
             - Operational nuances: during WFS, the operator must
               carefully choose "trusted" download sources (or copy
               the snapshots) and delete obsolete local snapshots.
       Firedancer chooses to follow Agave's behavior (relaxed).
     - The validator chooses between the local snapshot(s) and what it
       could download, keeping the local ones while they are recent
       enough.  WFS adds two constraints: a local snapshot short of S
       is not kept when downloading reaches S, and a local incremental
       short of S is never kept, because it would be the boot.
     - When WFS is configured and a candidate full snapshot is behind
       slot S, [snapshots.incremental_snapshots] is overridden to true
       so an incremental can reach S.  Every candidate is weighed, not
       only the one finally used: selection maximizes the reachable
       slot, and the flag only gates whether an incremental is
       considered.  That is selection; provisioning is separate and
       always reserves for incrementals, since it runs before the mode
       is knowable (fd_wfs_needs_incr).

   In short: selection is WFS-agnostic, classification is WFS-aware.
   WFS contributes a constraint, never an objective; the mode above is
   a verdict on whatever slot selection landed on. */

#define FD_WFS_MODE_DISABLED   (0)
#define FD_WFS_MODE_UNRESOLVED (1)
#define FD_WFS_MODE_MATCH      (2)
#define FD_WFS_MODE_NOOP       (3)
#define FD_WFS_MODE_ERROR      (4)

FD_PROTOTYPES_BEGIN

/* fd_wfs_configured returns 1 iff the config enables WFS.  Arguments
   slot, hash_is_zero, and shred_version come from consensus config.
   All three conditions must hold together for WFS to be enabled.

   hash_is_zero is derived via string-empty check in topology.c and via
   byte-zero memcmp in tiles.  These are equivalent because config
   rejects the all-zeros base58 encoding. */

FD_FN_CONST static inline int
fd_wfs_configured( ulong slot,
                   int   hash_is_zero,
                   ulong shred_version ) {
  return slot!=0UL && !hash_is_zero && shred_version!=0UL;
}

/* fd_wfs_needs_incr returns whether to provision for incrementals;
   WFS forces it on, as the mode is unknowable before any load. */

FD_FN_CONST static inline int
fd_wfs_needs_incr( int   incremental_snapshots,
                   ulong slot,
                   int   hash_is_zero,
                   ulong shred_version ) {
  return incremental_snapshots || fd_wfs_configured( slot, hash_is_zero, shred_version );
}

/* fd_wfs_mode classifies WFS given the config triple and boot_slot,
   the effective boot slot (the bank slot of the last snapshot loaded).
   Pass boot_slot==ULONG_MAX until the boot snapshot is known
   (yields UNRESOLVED when configured). */

FD_FN_CONST static inline int
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

FD_FN_CONST static inline char const *
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

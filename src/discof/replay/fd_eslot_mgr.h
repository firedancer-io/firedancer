#ifndef HEADER_fd_src_discof_replay_fd_eslot_mgr_h
#define HEADER_fd_src_discof_replay_fd_eslot_mgr_h

#include "../../util/fd_util_base.h"
#include "../../disco/fd_disco_base.h"

FD_PROTOTYPES_BEGIN

#define FD_ESLOT_MGR_MAGIC (0xF17EDA2CE7E51070UL) /* FIREDANCER ESLOT MGR V0 */

/* fd_eslot_mgr_t is a manager/tracker for block equivocation.  It is
   able to handle both leader and non-leader slots.  It supports a
   dual-key mechanism both by fd_eslot_t (a 64-bit bitfield representing
   the slot and prime count) and by the merkle root.  The struct serves
   as a translation layer between FEC set merkle roots and eslot entries
   while also detecting equivocation.

   The eslot manager is implented as two maps (one keyed by fd_eslot_t
   and the other keyed by the latest merkle root) backed by a pool. */

struct fd_eslot_ele {
  fd_eslot_t eslot;
  fd_eslot_t parent_eslot;
  fd_hash_t  merkle_root;
  ulong      highest_fec_idx_observed;
  int        is_leader;

  ulong      next_;
  ulong      next_mr_;
};
typedef struct fd_eslot_ele fd_eslot_ele_t;

struct fd_eslot_mgr;
typedef struct fd_eslot_mgr fd_eslot_mgr_t;

/* fd_eslot_mgr_align() returns the alignment of an fd_eslot_mgr_t. */

ulong
fd_eslot_mgr_align( void );

/* fd_eslot_mgr_footprint returns the footprint of a fd_eslot_mgr_t
   given a number of eslots. */

ulong
fd_eslot_mgr_footprint( ulong eslot_cnt );

/* fd_eslot_mgr_new() creates a new fd_eslot_mgr_t.  It takes a pointer
   to shared memory, the max number of eslots, and a seed. */

uchar *
fd_eslot_mgr_new( void * shmem,
                  ulong  eslot_cnt,
                  ulong  seed );

/* fd_eslot_mgr_join() joins an fd_eslot_mgr_t from shared memory. */

fd_eslot_mgr_t *
fd_eslot_mgr_join( void * shmem );

/* fd_eslot_mgr_ele_insert_fec() processes the information for a new
   FEC set (merkle root, chained merkle root, slot, and FEC set index).
   It will either return an existing eslot entry or create a new entry
   depending on the current state of the eslot manager.  Each entry will
   correspond to a unique fd_eslot_t.  If equivocation is detected, the
   is_equiv_out parameter will be set to 1, otherwise it will be set to
   0.

   If the chained merkle root is equal to a merkle root in the eslot
   manager, then we can successfully link the eslot to an existing
   entry.  If we can't link the eslot to an existing entry, it is still
   possible for us to process the FEC set.

   If we have linked the FEC to an existing eslot entry, then we have
   a few cases to consider:
   1. If the eslot mgr entry has the same slot as the FEC set.  Then all
      we need to do is increment the entry's merkle root and highest
      observed fec set idx.  This means that we have not equivocated.
   2. If the eslot mgr entry has a different slot than the FEC set.
      Then we need to create a new eslot mgr entry corresponding to the
      merkle hash and FEC idx of the FEC set.  If we already have a
      entry for the FEC's slot, that means we have equivocated.

   If we have not linked the FEC to an existing eslot entry, this means
   that we have received an equivocating FEC or there is corruption in
   the eslot manager.  If we already have an entry for the FEC's slot
   and the entry's highest fec idx observed is >= the fec set idx this
   means that we have received an equivocating FEC and the equivocation
   occured mid-slot.  A new eslot mgr entry will be created.  */

fd_eslot_ele_t *
fd_eslot_mgr_ele_insert_fec( fd_eslot_mgr_t *  mgr,
                             ulong             slot,
                             fd_hash_t const * merkle_root,
                             fd_hash_t const * chained_merkle_root,
                             ulong             fec_set_idx,
                             int *             is_equiv_out );

/* fd_eslot_mgr_ele_insert_leader inserts an eslot entry for a leader
   slot.  We know that slots that we are leader for will never be
   equivocated, so we can safely insert an eslot entry corresponding to
   the leader slot and prime count ==0 into the map.  We have to case
   this differently than FECs that we replay because we don't have
   merkle roots for the leader slot until we are done executing it. */

fd_eslot_ele_t *
fd_eslot_mgr_ele_insert_leader( fd_eslot_mgr_t * mgr,
                                ulong            slot,
                                fd_eslot_t       parent_eslot );

/* fd_eslot_mgr_ele_insert_initial inserts an eslot entry for the
   initial slot.  This assumes that the initial entry will not be
   equivocated and that the actual block id is unknown (it will be set
   to a default value). */

fd_eslot_ele_t *
fd_eslot_mgr_ele_insert_initial( fd_eslot_mgr_t * mgr,
                                 ulong            slot );

/* fd_eslot_mgr_is_leader() returns 1 if the eslot manager has an entry
   for the given slot which corresponds to a leader slot and 0
   otherwise. */

int
fd_eslot_mgr_is_leader( fd_eslot_mgr_t * mgr,
                        ulong            slot );

/* fd_eslot_mgr_ele_query_eslot() returns the eslot entry for the given
   eslot. */

fd_eslot_ele_t *
fd_eslot_mgr_ele_query_eslot( fd_eslot_mgr_t * mgr,
                              fd_eslot_t       eslot );

/* fd_eslot_mgr_ele_query_merkle_root() returns the eslot entry for the
   given merkle root. */

fd_eslot_ele_t *
fd_eslot_mgr_ele_query_merkle_root( fd_eslot_mgr_t *  mgr,
                                    fd_hash_t const * merkle_root );

/* fd_eslot_mgr_rekey_merkle_root updates the merkle root for the given
   eslot entry.  This should only be used for leader slot entries. */

void
fd_eslot_mgr_rekey_merkle_root( fd_eslot_mgr_t *  mgr,
                                fd_eslot_ele_t *  ele,
                                fd_hash_t const * merkle_root );

/* fd_eslot_mgr_publish will purge all entries for all slots
   monotonically increasing from old_root_slot inclusive to
   new_root_slot exclusive.  This includes all prime count for each
   slot that is purged.  After this function is called, some parent
   eslot entries may not have entries in the map in the case the parent
   eslot entries were pruned away. */

void
fd_eslot_mgr_publish( fd_eslot_mgr_t * mgr,
                      ulong            old_root_slot,
                      ulong            new_root_slot );

/* TODO: Add a printing function for the eslot manager. */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_replay_fd_eslot_mgr_h */

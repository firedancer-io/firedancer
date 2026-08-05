#ifndef HEADER_fd_src_alpenglow_types_ag_slot_h
#define HEADER_fd_src_alpenglow_types_ag_slot_h

/* Slot and the leader window arithmetic over it (types/slot.rs).

   The reference impl wraps a slot in a newtype and hangs these off it as
   methods; here a slot is a plain ulong and they are free functions
   carrying the Rust method names. */

#include "../../util/fd_util_base.h"

#define AG_SLOTS_PER_WINDOW (4UL)
#define AG_SLOTS_PER_EPOCH  (18000UL)

FD_PROTOTYPES_BEGIN

/* Slot::first_slot_in_window */

FD_FN_CONST static inline ulong
ag_slot_first_slot_in_window( ulong slot ) {
  return ( slot / AG_SLOTS_PER_WINDOW ) * AG_SLOTS_PER_WINDOW;
}

/* Slot::last_slot_in_window */

FD_FN_CONST static inline ulong
ag_slot_last_slot_in_window( ulong slot ) {
  return ag_slot_first_slot_in_window( slot ) + AG_SLOTS_PER_WINDOW - 1UL;
}

/* Slot::is_start_of_window */

FD_FN_CONST static inline int
ag_slot_is_start_of_window( ulong slot ) {
  return ( slot % AG_SLOTS_PER_WINDOW )==0UL;
}

/* Slot::is_genesis_window */

FD_FN_CONST static inline int
ag_slot_is_genesis_window( ulong slot ) {
  return slot < AG_SLOTS_PER_WINDOW;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_alpenglow_types_ag_slot_h */

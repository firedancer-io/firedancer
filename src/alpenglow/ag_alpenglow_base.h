#ifndef HEADER_fd_src_alpenglow_ag_alpenglow_base_h
#define HEADER_fd_src_alpenglow_ag_alpenglow_base_h

#include "../flamenco/fd_flamenco_base.h"

#define AG_ALPENGLOW_SLOTS_PER_WINDOW (4UL)
#define AG_ALPENGLOW_SLOTS_PER_EPOCH  (18000UL)

/* VAT caps the number of validators */
#define AG_ALPENGLOW_VALIDATOR_MAX (2000UL)

#define AG_ALPENGLOW_DELTA_NS             (250000000L)
#define AG_ALPENGLOW_DELTA_BLOCK_NS       (400000000L)
#define AG_ALPENGLOW_DELTA_FIRST_SLICE_NS (10000000L)
#define AG_ALPENGLOW_DELTA_TIMEOUT_NS     (3L*AG_ALPENGLOW_DELTA_NS)
#define AG_ALPENGLOW_DELTA_STANDSTILL_NS  (10000000000L)

#define AG_ALPENGLOW_WEAKEST_QUORUM_NUMER (1UL)
#define AG_ALPENGLOW_WEAK_QUORUM_NUMER    (2UL)
#define AG_ALPENGLOW_QUORUM_NUMER         (3UL)
#define AG_ALPENGLOW_STRONG_QUORUM_NUMER  (4UL)
#define AG_ALPENGLOW_QUORUM_DENOM         (5UL)

struct ag_block_id {
  ulong     slot;
  fd_hash_t hash;
};
typedef struct ag_block_id ag_block_id_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline int
ag_alpenglow_fraction_is_met( ulong stake,
                              ulong total,
                              ulong numer,
                              ulong denom ) {
  return (uint128)stake*(uint128)denom >= (uint128)total*(uint128)numer;
}

FD_FN_CONST static inline int
ag_alpenglow_is_weakest_quorum( ulong stake,
                                ulong total ) {
  return ag_alpenglow_fraction_is_met( stake, total, AG_ALPENGLOW_WEAKEST_QUORUM_NUMER, AG_ALPENGLOW_QUORUM_DENOM );
}

FD_FN_CONST static inline int
ag_alpenglow_is_weak_quorum( ulong stake,
                             ulong total ) {
  return ag_alpenglow_fraction_is_met( stake, total, AG_ALPENGLOW_WEAK_QUORUM_NUMER, AG_ALPENGLOW_QUORUM_DENOM );
}

FD_FN_CONST static inline int
ag_alpenglow_is_quorum( ulong stake,
                        ulong total ) {
  return ag_alpenglow_fraction_is_met( stake, total, AG_ALPENGLOW_QUORUM_NUMER, AG_ALPENGLOW_QUORUM_DENOM );
}

FD_FN_CONST static inline int
ag_alpenglow_is_strong_quorum( ulong stake,
                               ulong total ) {
  return ag_alpenglow_fraction_is_met( stake, total, AG_ALPENGLOW_STRONG_QUORUM_NUMER, AG_ALPENGLOW_QUORUM_DENOM );
}

FD_FN_CONST static inline ulong
ag_alpenglow_first_slot_in_window( ulong slot ) {
  return ( slot / AG_ALPENGLOW_SLOTS_PER_WINDOW ) * AG_ALPENGLOW_SLOTS_PER_WINDOW;
}

FD_FN_CONST static inline ulong
ag_alpenglow_last_slot_in_window( ulong slot ) {
  return ag_alpenglow_first_slot_in_window( slot ) + AG_ALPENGLOW_SLOTS_PER_WINDOW - 1UL;
}

FD_FN_CONST static inline int
ag_alpenglow_is_start_of_window( ulong slot ) {
  return ( slot % AG_ALPENGLOW_SLOTS_PER_WINDOW )==0UL;
}

FD_FN_CONST static inline int
ag_alpenglow_is_genesis_window( ulong slot ) {
  return slot < AG_ALPENGLOW_SLOTS_PER_WINDOW;
}

FD_FN_PURE static inline int
ag_block_id_eq( ag_block_id_t const * a,
                ag_block_id_t const * b ) {
  return a->slot==b->slot && !memcmp( a->hash.uc, b->hash.uc, sizeof(fd_hash_t) );
}

FD_PROTOTYPES_END

#endif

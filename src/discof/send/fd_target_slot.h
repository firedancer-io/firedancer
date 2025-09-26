#ifndef HEADER_fd_src_discof_send_fd_target_slot_h
#define HEADER_fd_src_discof_send_fd_target_slot_h

#include "../../util/fd_util.h"


/* Slot types */
#define FD_TARGET_SLOT_TYPE_POH     (0UL)
#define FD_TARGET_SLOT_TYPE_VOTE    (1UL)
#define FD_TARGET_SLOT_TYPE_TURBINE (2UL)
#define FD_TARGET_SLOT_TYPE_CNT     (3UL)

#define FD_TARGET_SLOT_MAX_SLOTS (8UL)
struct fd_target_slot {
  ulong slots[FD_TARGET_SLOT_MAX_SLOTS];  /* Static allocation for 8 slot numbers */
  struct {
    ulong last_slot[FD_TARGET_SLOT_TYPE_CNT];
    ulong max_turbine_slot; /* max turbine slot we've seen */
    int   caught_up; /* have we ever caught up? Just an estimate */
  } private;
};

typedef struct fd_target_slot fd_target_slot_t;

FD_PROTOTYPES_BEGIN

/* Memory layout, supports compile-time static alloc */
#define FD_TARGET_SLOT_ALIGN     ( alignof(fd_target_slot_t) )
#define FD_TARGET_SLOT_FOOTPRINT ( sizeof(fd_target_slot_t) )

FD_FN_CONST static inline ulong
fd_target_slot_align( void ) {
  return alignof(fd_target_slot_t);
}

FD_FN_CONST static inline ulong
fd_target_slot_footprint( void ) {
  return sizeof(fd_target_slot_t);
}

/* Object lifecycle */
fd_target_slot_t *
fd_target_slot_new( void * mem );

/* Core API */

/* fd_target_slot_push_type informs tracker that the source 'slot_type' (one of FD_TARGET_SLOT_TYPE_*)
   has a data point indicating the last completed slot was 'slot'. */
void
fd_target_slot_push( fd_target_slot_t * tracker,
                     uint               slot_type,
                     ulong              slot );

/* fd_target_slot_predict populates tracker->slots with its notion of the highest
   likelihood slots. It returns the number of slots it populated, up to FD_TARGET_SLOT_MAX_SLOTS.
   Will only return 0 if it has no data. */
ulong
fd_target_slot_predict( fd_target_slot_t * tracker );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_send_fd_target_slot_h */

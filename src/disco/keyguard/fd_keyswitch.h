#ifndef HEADER_fd_src_disco_keyguard_fd_keyswitch_h
#define HEADER_fd_src_disco_keyguard_fd_keyswitch_h

#include "../fd_disco_base.h"

/* A fd_keyswitch_public_t provides APIs for out-of-band switching of
   the key of a validator. */

#define FD_KEYSWITCH_ALIGN (128UL)
#define FD_KEYSWITCH_FOOTPRINT (128UL)

#define FD_KEYSWITCH_MAGIC (0xf17eda2c37830000UL) /* firedancer ks ver 0 */

#define FD_KEYSWITCH_STATE_UNLOCKED       (0UL)
#define FD_KEYSWITCH_STATE_LOCKED         (1UL)
#define FD_KEYSWITCH_STATE_SWITCH_PENDING (2UL)
#define FD_KEYSWITCH_STATE_UNHALT_PENDING (3UL)
#define FD_KEYSWITCH_STATE_FAILED         (4UL)
#define FD_KEYSWITCH_STATE_COMPLETED      (5UL)


struct __attribute__((aligned(FD_KEYSWITCH_ALIGN))) fd_keyswitch_private {
  ulong magic;     /* ==FD_KEYSWITCH_MAGIC */
  ulong state;
  ulong result;
  ulong param;
  uchar bytes[ 64UL ];
  /* Padding to FD_KEYSWITCH_ALIGN here */
};

typedef struct fd_keyswitch_private fd_keyswitch_t;

FD_PROTOTYPES_BEGIN

/* fd_keyswitch_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as a keyswitch.
   fd_keyswitch_align returns FD_KEYSWITCH_ALIGN.  */

FD_FN_CONST ulong
fd_keyswitch_align( void );

FD_FN_CONST ulong
fd_keyswitch_footprint( void );

/* fd_keyswitch_new formats an unused memory region for use as a
   keyswitch.  Assumes shmem is a non-NULL pointer to this region in the
   local address space with the required footprint and alignment.  The
   keyswitch will be initialized to have the given state (should be in
   [0,UINT_MAX]).  Returns shmem (and the memory region it points to
   will be formatted as a keyswitch, caller is not joined) and NULL on
   failure (logs details).  Reasons for failure include an obviously bad
   shmem region. */

void *
fd_keyswitch_new( void * shmem,
                  ulong  state );

/* fd_keyswitch_join joins the caller to the keyswitch.  shks points to
   the first byte of the memory region backing the keyswitch in the
   caller's address space.  Returns a pointer in the local address space
   to the keyswitch on success (this should not be assumed to be just a
   cast of shkc) or NULL on failure (logs details).  Reasons for failure
   include the shkc is obviously not a local pointer to a memory region
   holding a keyswitch.  Every successful join should have a matching
   leave.  The lifetime of the join is until the matching leave or
   caller's thread group is terminated. */

fd_keyswitch_t *
fd_keyswitch_join( void * shks );

/* fd_keyswitch_leave leaves a current local join.  Returns a pointer to
   the underlying shared memory region on success (this should not be
   assumed to be just a cast of ks) and NULL on failure (logs details).
   Reasons for failure include ks is NULL. */

void *
fd_keyswitch_leave( fd_keyswitch_t const * ks );

/* fd_keyswitch_delete unformats a memory region used as a keyswitch.
   Assumes nobody is joined to the region.  Returns a pointer to the
   underlying shared memory region or NULL if used obviously in error
   (e.g. shks obviously does not point to a keyswitch ... logs details).
   The ownership of the memory region is transferred to the caller on
   success. */

void *
fd_keyswitch_delete( void * shkc );

/* fd_keyswitch_state_query observes the current signal posted to the
   keyswitch. Assumes ks is a current local join.  This is a compiler
   fence. Returns the current state on the ks at some point in time
   between when this was called and this returned. */

static inline ulong
fd_keyswitch_state_query( fd_keyswitch_t const * ks ) {
  FD_COMPILER_MFENCE();
  ulong s = FD_VOLATILE_CONST( ks->state );
  FD_COMPILER_MFENCE();
  return s;
}

/* fd_keyswitch_state_query observes the current param posted to the
   keyswitch. Assumes ks is a current local join.  This is a compiler
   fence. Returns the current param on the ks at some point in time
   between when this was called and this returned. */

static inline ulong
fd_keyswitch_param_query( fd_keyswitch_t const * ks ) {
  FD_COMPILER_MFENCE();
  ulong s = FD_VOLATILE_CONST( ks->param );
  FD_COMPILER_MFENCE();
  return s;
}

/* fd_keyswitch_state atomically attempts to transition the ks from
   state before to state after.  Assumes ks is a current local join and
   the caller is currently allowed to do a transition from before to
   after.  Returns 0 if the transition succeeded, or 1 if it failed*/

static inline void
fd_keyswitch_state( fd_keyswitch_t * ks,
                    ulong            s ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( ks->state ) = s;
  FD_COMPILER_MFENCE();
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_keyguard_fd_keyswitch_h */

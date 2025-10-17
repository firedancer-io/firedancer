#ifndef HEADER_fd_src_ballet_sbpf_fd_sbpf_calldests_h
#define HEADER_fd_src_ballet_sbpf_fd_sbpf_calldests_h

/* fd_sbpf_calldests.h provides a bit vector of valid call destinations.
   Should be configured to fit any possible program counter.  The max
   program counter is <size of text section> divided by 8. */

#define SET_NAME fd_sbpf_calldests1
#include "../../util/tmpl/fd_set_dynamic.c"

/* Unfortunately, fd_set_dynamic.c has UB if the set size is zero.
   So, wrap set definition to support zero size.  Also handle OOB jumps
   from malicious programs. */

typedef fd_sbpf_calldests1_t fd_sbpf_calldests_t;

#define fd_sbpf_calldests_align  fd_sbpf_calldests1_align
#define fd_sbpf_calldests_join   fd_sbpf_calldests1_join
#define fd_sbpf_calldests_leave  fd_sbpf_calldests1_leave
#define fd_sbpf_calldests_delete fd_sbpf_calldests1_delete

FD_PROTOTYPES_BEGIN

static inline ulong
fd_sbpf_calldests_footprint( ulong pc_max ) {
  return fd_sbpf_calldests1_footprint( fd_ulong_max( pc_max, 1UL ) );
}

static inline void *
fd_sbpf_calldests_new( void * mem,
                       ulong  pc_max ) {
  return fd_sbpf_calldests1_new( mem, fd_ulong_max( pc_max, 1UL ) );
}

static inline void
fd_sbpf_calldests_insert( fd_sbpf_calldests_t * calldests,
                          ulong                 pc ) {
  if( FD_UNLIKELY( !fd_sbpf_calldests1_valid_idx( calldests, pc ) ) ) return;
  fd_sbpf_calldests1_insert( calldests, pc );
}

static inline int
fd_sbpf_calldests_test( fd_sbpf_calldests_t const * calldests,
                        ulong                       pc ) {
  if( FD_UNLIKELY( !fd_sbpf_calldests1_valid_idx( calldests, pc ) ) ) return 0;
  return fd_sbpf_calldests1_test( calldests, pc );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_sbpf_fd_sbpf_calldests_h */

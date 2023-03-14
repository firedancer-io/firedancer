#ifndef HEADER_fd_src_util_gossip_fd_gossip_validation_h
#define HEADER_fd_src_util_gossip_fd_gossip_validation_h

/* Macros for sanity checking fields in gossip messages and CRDS objects */

#define FD_GOSSIP_MTU                                  (1232UL)
#define FD_GOSSIP_CRDS_MAX_WALLCLOCK                   (1000000000000000UL)
#define FD_GOSSIP_CRDS_MAX_VOTES                       (32UL)
#define FD_GOSSIP_CRDS_MAX_EPOCH_SLOTS                 (255UL)
#define FD_GOSSIP_CRDS_MAX_DUPLICATE_SHREDS            (512UL)
#define FD_GOSSIP_CRDS_MAX_SLOT                        (1000000000000000UL)
#define FD_GOSSIP_CRDS_MAX_SLOTS_PER_ENTRY             (2048*8)

#define CHECK_WALLCLOCK( wallclock )  do {                                 \
  if( FD_UNLIKELY( wallclock>FD_GOSSIP_CRDS_MAX_WALLCLOCK ) ) {            \
    FD_LOG_WARNING(( "wallclock exceeds max value" ));                     \
    return 0;                                                              \
  }                                                                        \
} while(0)

#define CHECK_LOWEST_SLOT_INDEX( index )  do {                             \
  if( FD_UNLIKELY( index>=1 ) ) {                                          \
    FD_LOG_WARNING(( "invalid slot_index value" ));                        \
    return 0;                                                              \
  }                                                                        \
} while(0)

#define CHECK_VOTE_INDEX( index )  do {                                    \
  if( FD_UNLIKELY( index>=FD_GOSSIP_CRDS_MAX_VOTES ) ) {                   \
    FD_LOG_WARNING(( "invalid vote index value" ));                        \
    return 0;                                                              \
  }                                                                        \
} while(0)

#define CHECK_EPOCH_SLOTS_INDEX( index )  do {                             \
  if( FD_UNLIKELY( index>=FD_GOSSIP_CRDS_MAX_EPOCH_SLOTS ) ) {             \
    FD_LOG_WARNING(( "invalid epoch slots index value" ));                 \
    return 0;                                                              \
  }                                                                        \
} while(0)

#define CHECK_DUPLICATE_SHRED_INDEX( index )  do {                         \
  if( FD_UNLIKELY( index>=FD_GOSSIP_CRDS_MAX_DUPLICATE_SHREDS ) ) {        \
    FD_LOG_WARNING(( "invalid epoch slots index value" ));                 \
    return 0;                                                              \
  }                                                                        \
} while( 0 )

#define CHECK_SLOT( slot ) do {                                            \
  if( FD_UNLIKELY( slot>=FD_GOSSIP_CRDS_MAX_SLOT ) ) {                     \
       FD_LOG_WARNING(( "invalid slot" ));                                 \
       return 0;                                                           \
  }                                                                        \
} while(0)

/* check for integer overflow when calculating vector size in bytes.
   returns error and bails out if the multiplication overflows. */
#define CHECK_VECTOR_SIZE_OVERFLOW( vector_sz, type_sz )  do {             \
  if( FD_UNLIKELY( (vector_sz*type_sz)<vector_sz ) ) {                     \
    FD_LOG_WARNING(( "vector size calculation integer overflow wrap" ));   \
    return 0;                                                              \
  }                                                                        \
} while( 0 )

#endif

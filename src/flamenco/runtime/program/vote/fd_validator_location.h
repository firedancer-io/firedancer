#ifndef HEADER_fd_src_flamenco_runtime_program_vote_fd_validator_location_h
#define HEADER_fd_src_flamenco_runtime_program_vote_fd_validator_location_h

#include "../../../fd_flamenco_base.h"

#define FD_VALIDATOR_LOCATION_COORD_MAX (6378138)
#define FD_VALIDATOR_LOCATION_A2        (40680631590769UL)
#define FD_VALIDATOR_LOCATION_K         (442UL)
#define FD_VALIDATOR_LOCATION_TOL       (12756274000UL)

struct fd_validator_location {
  int x;
  int y;
  int z;
};
typedef struct fd_validator_location fd_validator_location_t;

FD_PROTOTYPES_BEGIN

FD_FN_PURE static inline int
fd_validator_location_in_bounds( fd_validator_location_t const * loc ) {
  return loc->x>=-FD_VALIDATOR_LOCATION_COORD_MAX && loc->x<=FD_VALIDATOR_LOCATION_COORD_MAX &&
         loc->y>=-FD_VALIDATOR_LOCATION_COORD_MAX && loc->y<=FD_VALIDATOR_LOCATION_COORD_MAX &&
         loc->z>=-FD_VALIDATOR_LOCATION_COORD_MAX && loc->z<=FD_VALIDATOR_LOCATION_COORD_MAX;
}

FD_FN_PURE static inline ulong
fd_validator_location_q( fd_validator_location_t const * loc ) {
  ulong x2 = (ulong)( (long)loc->x*(long)loc->x );
  ulong y2 = (ulong)( (long)loc->y*(long)loc->y );
  ulong z2 = (ulong)( (long)loc->z*(long)loc->z );
  return x2 + y2 + z2 + ( ( FD_VALIDATOR_LOCATION_K*z2 )>>16 );
}

FD_FN_PURE static inline int
fd_validator_location_is_valid( fd_validator_location_t const * loc ) {
  if( FD_UNLIKELY( !fd_validator_location_in_bounds( loc ) ) ) return 0;
  ulong q = fd_validator_location_q( loc );
  ulong d = fd_ulong_if( q>FD_VALIDATOR_LOCATION_A2, q-FD_VALIDATOR_LOCATION_A2, FD_VALIDATOR_LOCATION_A2-q );
  return d<=FD_VALIDATOR_LOCATION_TOL;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_vote_fd_validator_location_h */

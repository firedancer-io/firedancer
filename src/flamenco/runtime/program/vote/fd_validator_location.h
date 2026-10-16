#ifndef HEADER_fd_src_flamenco_runtime_program_vote_fd_validator_location_h
#define HEADER_fd_src_flamenco_runtime_program_vote_fd_validator_location_h

#include "../../../fd_flamenco_base.h"

#define FD_VALIDATOR_LOCATION_COORD_MAX (6378138)

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

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_vote_fd_validator_location_h */

extern "C" {
#include "../fd_util.h"
}
#include <stdlib.h>
#include <assert.h>

struct my_list_elem {
    ulong key;
    ulong val;
};
typedef struct my_list_elem my_list_elem_t;
#define SORTLIST_T my_list_elem_t
#define SORTLIST_KEY_T ulong
#define SORTLIST_NAME my_list

#include "fd_sorted_list.c"

#define SCRATCH_ALIGN     (128UL)
#define SCRATCH_FOOTPRINT (1UL<<16)
uchar scratch[ SCRATCH_FOOTPRINT ] __attribute__((aligned(SCRATCH_ALIGN)));

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong max = my_list_max_for_footprint(SCRATCH_FOOTPRINT);
  if (my_list_footprint(max) > SCRATCH_FOOTPRINT)
    FD_LOG_ERR(("footprint confusion"));
  my_list_joined list = my_list_join( my_list_new( scratch, max ), max );
  if (my_list_max(list) != max)
    FD_LOG_ERR(("footprint confusion"));

  (void) my_list_delete( my_list_leave( list ));

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

extern "C" {
#include "../fd_util.h"
}
#include <stdlib.h>
#include <assert.h>
#include <map>

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
#define SCRATCH_FOOTPRINT (1UL<<12)
uchar scratch[ SCRATCH_FOOTPRINT ] __attribute__((aligned(SCRATCH_ALIGN)));

int
my_list_compare( ulong const * a, ulong const * b ) {
  return (*a == *b ? 0 : (*a < *b ? -1 : 1));
}

static void
verify( std::map<ulong,ulong> const & map, my_list_joined list ) {
  my_list_verify( list );
  my_list_resort( list );
  my_list_verify( list );
  for( auto it : map ) {
    my_list_elem_t * elem = my_list_query( list, &it.first );
    FD_TEST( elem != NULL );
    FD_TEST( it.second == elem->val );
  }
}

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

  std::map<ulong,ulong> map;

  for( ulong iter = 0; iter < 1000; ++iter ) {
    for( ulong i = 0; i < 30; ++i ) {
      if( my_list_is_full( list ) ) break;
      ulong key = fd_rng_ulong( rng )%256;
      if( map.count(key) > 0 ) continue;
      my_list_elem_t * elem = my_list_add( list, &key);
      map[key] = elem->val = fd_rng_ulong( rng );
    }
    verify( map, list );

    for( ulong i = 0; i < 30; ++i ) {
      ulong key = fd_rng_ulong( rng )%256;
      if( map.count(key) == 0 ) continue;
      FD_TEST( my_list_erase( list, &key) == 0 );
      map.erase(key);
    }
    verify( map, list );
  }

  (void) my_list_delete( my_list_leave( list ));

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

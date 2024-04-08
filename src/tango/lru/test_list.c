#include "fd_list.h"

#define MAX 4

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  static uchar list_mem[ 16384 ] __attribute__((aligned(FD_LIST_ALIGN)));
  FD_TEST( FD_LIST_ALIGN == fd_list_align() );
  FD_TEST( fd_list_footprint( 4 ) <= sizeof(list_mem) );

  fd_list_t * list = fd_list_join( fd_list_new( list_mem, MAX ) );
  fd_list_t * sentinel = fd_list_sentinel( list );

  fd_list_t * curr = fd_list_head( list );
  for ( ulong i = 1; i <= MAX; i++ ) {
    curr->tag = i;
    curr      = fd_list_next(curr);
  }

  ulong n = 0;
  curr    = fd_list_head( list );
  while ( curr->tag != 0 ) {
    n++;
    curr = fd_list_next(curr);
  }
  FD_TEST( n == MAX );

  /* 1 -> 2 -> 3 -> 4 => 2 -> 3 -> 4 */
  fd_list_t * pop = fd_list_pop_front( list );
  FD_TEST( pop->tag == 1 );
  FD_TEST( fd_list_head( list )->tag == 2 );

  ulong i = 1;
  curr    = fd_list_head( list );
  while ( curr != sentinel ) {
    FD_TEST( curr->tag == i + 1 );
    curr = fd_list_next(curr);
    i++;
  }

  /* 2 -> 3 -> 4 => 2 -> 3 -> 4 -> 1 */
  fd_list_push_back( list, pop );
  FD_TEST( fd_list_head( list )->tag == 2 );
  FD_TEST( fd_list_tail( list )->tag == 1 );

  /* 2 -> 3 -> 4 -> 1 => 2 -> 3 -> 1 -> 4 */
  fd_list_t * remove = fd_list_remove( fd_list_prev(fd_list_tail( list )) );
  fd_list_insert( fd_list_tail( list ), remove );

  /* 2 -> 3 -> 1 -> 4 => 1 -> 2 -> 3 -> 4 */
  remove = fd_list_remove( fd_list_next(fd_list_next(fd_list_head( list ))) );
  fd_list_insert( sentinel, remove );

  /* 1 -> 2 -> 3 -> 4 => NULL  */
  i = 1;
  while ( ( curr = fd_list_pop_front( list ) ) != NULL ) {
    FD_TEST( curr->tag == i );
    i++;
  }
  FD_TEST( i == MAX+1 );

  FD_LOG_NOTICE( ( "pass" ) );
  fd_halt();
  return 0;
}

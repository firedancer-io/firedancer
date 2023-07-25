#include "../fd_util.h"
#include "fd_list.h"

#define LG_MAX_SZ 2
#define MAX_SZ    ( 1UL << LG_MAX_SZ )

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  if ( FD_UNLIKELY( argc > 1 ) ) FD_LOG_ERR( ( "unrecognized argument: %s", argv[1] ) );

  fd_wksp_t * wksp = fd_wksp_new_anonymous(
      FD_SHMEM_HUGE_PAGE_SZ, 1, fd_shmem_cpu_idx( fd_shmem_numa_idx( 0 ) ), "wksp", 0UL );
  FD_TEST( wksp );

  void *      mem  = fd_wksp_alloc_laddr( wksp, fd_list_align(), fd_list_footprint( 2 ), 42UL );
  fd_list_t * list = fd_list_join( fd_list_new( mem, 2 ) );

  ulong       nums[MAX_SZ];
  fd_list_t * curr = fd_list_head( list );
  for ( ulong i = 0; i < MAX_SZ; i++ ) {
    nums[i]   = i;
    curr->ele = &nums[i];
    curr      = curr->next;
  }

  ulong n = 0;
  curr    = fd_list_head( list );
  while ( curr->ele != NULL ) {
    n++;
    curr = curr->next;
  }
  FD_TEST( n == MAX_SZ );

  /* 0 -> 1 -> 2 -> 3 => 1 -> 2 -> 3 */
  fd_list_t * pop      = fd_list_pop_front( list );
  ulong       old_head = *(ulong *)pop->ele;
  FD_TEST( old_head == 0 );
  ulong new_head = *(ulong *)fd_list_head( list )->ele;
  FD_TEST( new_head == 1 );

  ulong i = 1;
  curr    = fd_list_head( list );
  while ( curr != curr->sentinel ) {
    ulong num = *(ulong *)curr->ele;
    FD_TEST( num == i );
    curr = curr->next;
    i++;
  }

  /* 1 -> 2 -> 3 => 1 -> 2 -> 3 -> 0 */
  fd_list_push_back( list, pop );
  ulong tail = *(ulong *)fd_list_tail( list )->ele;
  FD_TEST( tail == 0 );
  new_head = *(ulong *)fd_list_head( list )->ele;
  FD_TEST( new_head == 1 );

  /* 1 -> 2 -> 3 -> 0 => 1 -> 2 -> 0 -> 3 */
  fd_list_t * remove = fd_list_remove( fd_list_tail( list )->prev );
  fd_list_insert( fd_list_tail( list ), remove );

  /* 1 -> 2 -> 0 -> 3 => 0 -> 1 -> 2 -> 3 */
  remove = fd_list_remove( fd_list_head( list )->next->next );
  fd_list_insert( list->sentinel, remove );

  /* 0 -> 1 -> 2 -> 3 => NULL  */
  i = 0;
  fd_list_t * ele;
  while ( ( ele = fd_list_pop_front( list ) ) != NULL ) {
    ulong num = *(ulong *)ele->ele;
    FD_TEST( num == i );
    i++;
  }
  FD_TEST( i == MAX_SZ );

  FD_LOG_NOTICE( ( "pass" ) );
  fd_halt();
  return 0;
}

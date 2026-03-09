#include "fd_tower_serdes.h"

FD_IMPORT_BINARY( vote_acc_v2, "src/choreo/tower/fixtures/vote_acc_v2.bin" );
FD_IMPORT_BINARY( vote_acc_v3, "src/choreo/tower/fixtures/vote_acc_v3.bin" );
FD_IMPORT_BINARY( vote_acc_v4, "src/choreo/tower/fixtures/vote_acc_v4.bin" );

void
test_voter_v1_14_11( void ) {
  fd_vote_acc_t const * voter = (fd_vote_acc_t const *)fd_type_pun_const( vote_acc_v2 );
  FD_TEST( voter->kind == FD_VOTE_ACC_V2 );
  FD_TEST( fd_vote_acc_vote_cnt( vote_acc_v2 ) == 31 );
  FD_TEST( fd_vote_acc_vote_slot( vote_acc_v2 ) != ULONG_MAX );
  FD_TEST( fd_vote_acc_root_slot( vote_acc_v2 ) != ULONG_MAX );
}

void
test_voter_current( void ) {
  fd_vote_acc_t const * voter = (fd_vote_acc_t const *)fd_type_pun_const( vote_acc_v3 );
  FD_TEST( voter->kind == FD_VOTE_ACC_V3 );
  FD_TEST( fd_vote_acc_vote_cnt( vote_acc_v3 ) == 31 );
  FD_TEST( fd_vote_acc_vote_slot( vote_acc_v3 ) != ULONG_MAX );
  FD_TEST( fd_vote_acc_root_slot( vote_acc_v3 ) != ULONG_MAX );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  fd_vote_acc_t const * voter = (fd_vote_acc_t const *)fd_type_pun_const( vote_acc_v4 );
  FD_TEST( voter );
  FD_TEST( voter->kind==FD_VOTE_ACC_V4 );
  FD_TEST( fd_vote_acc_vote_slot( vote_acc_v4 )==699 );
  FD_TEST( fd_vote_acc_root_slot( vote_acc_v4 )==668 );

  test_voter_v1_14_11();
  test_voter_current();
  fd_halt();
}

#include "fd_vote_timestamps.h"

int main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  char const * name     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL, NULL            );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"      );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 1UL             );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );
  ulong        wksp_tag = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag",  NULL, 1234UL          );

  fd_pubkey_t pubkey_A = {.ul = {0}};
  fd_pubkey_t pubkey_B = {.ul = {1}};
  fd_pubkey_t pubkey_C = {.ul = {2}};
  fd_pubkey_t pubkey_D = {.ul = {3}};
  fd_pubkey_t pubkey_E = {.ul = {4}};
  fd_pubkey_t pubkey_F = {.ul = {5}}; (void)pubkey_F;
  fd_pubkey_t pubkey_G = {.ul = {6}}; (void)pubkey_G;
  fd_pubkey_t pubkey_H = {.ul = {7}}; (void)pubkey_H;

  fd_wksp_t * wksp;
  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    wksp = fd_wksp_attach( name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }

  ulong footprint = fd_vote_timestamps_footprint( 16UL, 4, 128UL );
  FD_LOG_NOTICE(( "footprint: %lu", footprint ));

  uchar * mem = fd_wksp_alloc_laddr( wksp, fd_vote_timestamps_align(), footprint, wksp_tag );
  FD_TEST( mem );


  fd_vote_timestamps_t * vote_timestamps = fd_vote_timestamps_join( fd_vote_timestamps_new( mem, 16UL, 4, 128UL, 0UL ) );
  FD_TEST( vote_timestamps );

  ushort fork_idx = fd_vote_timestamps_init( vote_timestamps, 0UL );
  FD_TEST( fork_idx==0 );

  fd_vote_timestamps_insert_root( vote_timestamps, pubkey_A, 10 );
  fd_vote_timestamps_insert_root( vote_timestamps, pubkey_B, 11 );
  fd_vote_timestamps_insert_root( vote_timestamps, pubkey_C, 10 );
  fd_vote_timestamps_insert_root( vote_timestamps, pubkey_D, 10 );
  fd_vote_timestamps_insert_root( vote_timestamps, pubkey_E, 10 );

  FD_TEST( 5U==fd_vote_timestamps_index_cnt( vote_timestamps ) );
  FD_TEST( 0==fd_vote_timestamps_slot_votes_cnt( vote_timestamps, fork_idx ) );


  ushort child_idx = fd_vote_timestamps_attach_child( vote_timestamps, fork_idx, 1UL );
  (void)child_idx;

  fd_vote_timestamps_insert( vote_timestamps, child_idx, pubkey_A, 11 );
  fd_vote_timestamps_insert( vote_timestamps, child_idx, pubkey_B, 11 );
  fd_vote_timestamps_insert( vote_timestamps, child_idx, pubkey_C, 11 );
  fd_vote_timestamps_insert( vote_timestamps, child_idx, pubkey_D, 11 );
  FD_TEST( 5U==fd_vote_timestamps_index_cnt( vote_timestamps ) );
  FD_TEST( 4==fd_vote_timestamps_slot_votes_cnt( vote_timestamps, child_idx ) );

  FD_LOG_NOTICE(( "pass" ));

}

#include "fd_new_votes.h"

int main( int argc, char * argv[] ) {
  fd_boot( &argc, &argv );

  char const * name     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL, NULL            );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"      );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 1UL             );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );
  ulong        wksp_tag = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag",  NULL, 1234UL          );

  fd_wksp_t * wksp;
  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    wksp = fd_wksp_attach( name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }

  ulong max_accounts   = 64UL;
  ulong exp_accounts   = 64UL;
  ulong max_live_forks = 16UL;

  ulong footprint = fd_new_votes_footprint( max_accounts, exp_accounts, max_live_forks );
  FD_TEST( footprint );

  uchar * mem = fd_wksp_alloc_laddr( wksp, fd_new_votes_align(), footprint, wksp_tag );
  FD_TEST( mem );

  fd_new_votes_t * nv = fd_new_votes_join(
      fd_new_votes_new( mem, 0UL, max_accounts, exp_accounts, max_live_forks ) );
  FD_TEST( nv );
  FD_TEST( nv->magic==FD_NEW_VOTES_MAGIC );
  FD_TEST( fd_new_votes_cnt( nv )==0UL );

  /* Allocate a few forks and evict them. */
  ushort f0 = fd_new_votes_new_fork( nv );
  ushort f1 = fd_new_votes_new_fork( nv );
  FD_TEST( f0!=f1 );

  fd_new_votes_evict_fork( nv, f0 );
  fd_new_votes_evict_fork( nv, f1 );

  /* Evicting USHORT_MAX should be a safe no-op. */
  fd_new_votes_evict_fork( nv, USHORT_MAX );

  /* After reset, count should still be zero. */
  fd_new_votes_reset( nv );
  FD_TEST( fd_new_votes_cnt( nv )==0UL );

  /* Re-join from raw memory should succeed. */
  fd_new_votes_t * nv2 = fd_new_votes_join( mem );
  FD_TEST( nv2==nv );

  /* Bad joins should return NULL. */
  FD_TEST( !fd_new_votes_join( NULL ) );

  /* Insert into a fork's delta dlist and verify pool usage grows. */
  fd_pubkey_t pk_a = {.ul = {1}};
  fd_pubkey_t pk_b = {.ul = {2}};
  fd_pubkey_t pk_c = {.ul = {3}};

  ushort fi = fd_new_votes_new_fork( nv );

  fd_new_votes_insert( nv, fi, &pk_a );
  FD_TEST( fd_new_votes_cnt( nv )==1UL );

  fd_new_votes_insert( nv, fi, &pk_b );
  FD_TEST( fd_new_votes_cnt( nv )==2UL );

  fd_new_votes_insert( nv, fi, &pk_c );
  FD_TEST( fd_new_votes_cnt( nv )==3UL );

  /* Duplicate pubkey in the same fork appends another delta element. */
  fd_new_votes_insert( nv, fi, &pk_a );
  FD_TEST( fd_new_votes_cnt( nv )==4UL );

  /* Evicting the fork releases all its delta elements. */
  fd_new_votes_evict_fork( nv, fi );
  FD_TEST( fd_new_votes_cnt( nv )==0UL );

  /* Insert across two forks. */
  ushort fa = fd_new_votes_new_fork( nv );
  ushort fb = fd_new_votes_new_fork( nv );

  fd_new_votes_insert( nv, fa, &pk_a );
  fd_new_votes_insert( nv, fb, &pk_b );
  FD_TEST( fd_new_votes_cnt( nv )==2UL );

  fd_new_votes_evict_fork( nv, fa );
  FD_TEST( fd_new_votes_cnt( nv )==1UL );

  fd_new_votes_evict_fork( nv, fb );
  FD_TEST( fd_new_votes_cnt( nv )==0UL );

  /* Reset clears everything. */
  fd_new_votes_reset( nv );
  FD_TEST( fd_new_votes_cnt( nv )==0UL );

  /* apply_delta merges fork deltas into the root map. */
  ushort fd = fd_new_votes_new_fork( nv );
  fd_new_votes_insert( nv, fd, &pk_a );
  fd_new_votes_insert( nv, fd, &pk_b );
  fd_new_votes_insert( nv, fd, &pk_a );
  FD_TEST( fd_new_votes_cnt( nv )==3UL );

  fd_new_votes_apply_delta( nv, fd );

  /* Delta elements freed, root map gained 2 distinct pubkeys.
     Pool usage = 2 (root map entries only, delta drained). */
  FD_TEST( fd_new_votes_cnt( nv )==2UL );

  /* Applying a second fork with overlapping + new pubkeys. */
  ushort fd2 = fd_new_votes_new_fork( nv );
  fd_new_votes_insert( nv, fd2, &pk_b );
  fd_new_votes_insert( nv, fd2, &pk_c );
  FD_TEST( fd_new_votes_cnt( nv )==4UL );

  fd_new_votes_apply_delta( nv, fd2 );

  /* pk_b already in root (deduped), pk_c newly added.
     Pool usage = 3 root entries, delta drained. */
  FD_TEST( fd_new_votes_cnt( nv )==3UL );

  /* Reset clears root + everything. */
  fd_new_votes_reset( nv );
  FD_TEST( fd_new_votes_cnt( nv )==0UL );

  FD_LOG_NOTICE(( "pass" ));

  fd_halt();
  return 0;
}

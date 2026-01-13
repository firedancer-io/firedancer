#include "fd_runtime.h"
#include "../../funk/fd_funk.h"
#include "../accdb/fd_accdb_impl_v0.h"
#include "../accdb/fd_accdb_sync.h"


static void
create_test_account( fd_accdb_user_t *   user,
                     fd_pubkey_t *       pubkey,
                     ulong               lamports,
                     uint                dlen,
                     uchar *             data,
                     ulong               slot ) {
  fd_account_meta_t meta = { .lamports = lamports, .dlen = dlen, .executable = 0, .slot = slot };
  fd_accdb_rw_t rw[1];
  fd_accdb_open_rw( user, rw, NULL, pubkey, dlen, FD_ACCDB_FLAG_CREATE );
  FD_TEST( rw->ref->accdb_type==FD_ACCDB_TYPE_V0 );
  rw->ref->user_data = sizeof(fd_account_meta_t) + dlen;
  rw->meta = &meta;
  fd_accdb_ref_data_set( user, rw, data, dlen );
  fd_accdb_close_rw( user, rw );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  char const * name     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",     NULL, NULL           );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"     );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 6UL            );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu", NULL, fd_log_cpu_id());
  ulong        wksp_tag = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag", NULL, 1234UL         );

  fd_wksp_t * wksp;
  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    wksp = fd_wksp_attach( name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }

  // fd_runtime_t * runtime = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_t), sizeof(fd_runtime_t), wksp_tag );
  // fd_txn_in_t *  txn_in  = fd_wksp_alloc_laddr( wksp, alignof(fd_txn_in_t),  sizeof(fd_txn_in_t),  wksp_tag );
  // fd_txn_out_t * txn_out = fd_wksp_alloc_laddr( wksp, alignof(fd_txn_out_t), sizeof(fd_txn_out_t), wksp_tag );

  // uchar txn_1[2048] __attribute__((aligned(32UL)));
  // uchar txn_2[2048] __attribute__((aligned(32UL)));
  // uchar txn_3[2048] __attribute__((aligned(32UL)));
  // uchar txn_4[2048] __attribute__((aligned(32UL)));
  // uchar txn_5[2048] __attribute__((aligned(32UL)));

  uchar * funk_mem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint( 2UL, 2048UL ), wksp_tag );
  fd_funk_t funk_[1];
  fd_funk_t * funk = fd_funk_join( funk_, fd_funk_new( funk_mem, wksp_tag, 0UL, 2UL, 2048UL ));
  FD_TEST( funk );

  /* Construct db_v0 object */

  ulong const rec_max = 64UL;
  ulong db_fp = fd_accdb_v0_footprint( rec_max );
  FD_TEST( db_fp );
  void * db_mem;
  FD_TEST( (db_mem = fd_wksp_alloc_laddr( wksp, fd_accdb_v0_align(), db_fp, wksp_tag )) );
  fd_accdb_v0_t * db = fd_accdb_v0_join( fd_accdb_v0_new( db_mem, rec_max ) );
  FD_TEST( db );

  fd_accdb_user_t user_[1];
  fd_accdb_user_t * user = fd_accdb_user_v0_init( user_, db );
  FD_TEST( user );


  fd_pubkey_t pubkey1 = { .ul[0] = 1UL };
  uchar data1[5] = {1, 2, 3, 4, 5};
  create_test_account( user, &pubkey1, 1000000UL, 5UL, data1, 10UL );

  fd_pubkey_t pubkey2 = { .ul[0] = 2UL };
  uchar data2[5] = {2, 2, 3, 4, 5};
  create_test_account( user, &pubkey2, 1000000UL, 5UL, data2, 10UL );

  fd_pubkey_t pubkey3 = { .ul[0] = 3UL };
  uchar data3[5] = {3, 2, 3, 4, 5};
  create_test_account( user, &pubkey3, 1000000UL, 5UL, data3, 10UL );

  fd_pubkey_t pubkey4 = { .ul[0] = 4UL };
  uchar data4[5] = {4, 2, 3, 4, 5};
  create_test_account( user, &pubkey4, 1000000UL, 5UL, data4, 10UL );

  fd_pubkey_t pubkey5 = { .ul[0] = 5UL };
  uchar data5[5] = {5, 2, 3, 4, 5};
  create_test_account( user, &pubkey5, 1000000UL, 5UL, data5, 10UL );

  FD_LOG_NOTICE(( "pass" ));



  fd_halt();
  return 0;

}

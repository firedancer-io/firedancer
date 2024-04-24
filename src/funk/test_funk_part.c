#include "fd_funk.h"
#include <stdio.h>

#if FD_HAS_HOSTED

static fd_funk_txn_xid_t *
fd_funk_txn_xid_set_unique( fd_funk_txn_xid_t * xid ) {
  static FD_TL ulong tag = 0UL;
  xid->ul[0] = fd_log_app_id();
  xid->ul[1] = fd_log_thread_id();
  xid->ul[2] = ++tag;
# if FD_HAS_X86
  xid->ul[3] = (ulong)fd_tickcount();
# else
  xid->ul[3] = 0UL;
# endif
  return xid;
}

static fd_funk_rec_key_t *
fd_funk_rec_key_set_unique( fd_funk_rec_key_t * key ) {
  static FD_TL ulong tag = 0UL;
  key->ul[0] = fd_log_app_id();
  key->ul[1] = fd_log_thread_id();
  key->ul[2] = ++tag;
# if FD_HAS_X86
  key->ul[3] = (ulong)fd_tickcount();
# else
  key->ul[3] = 0UL;
# endif
  key->ul[4] = 0UL;
  key->ul[5] = 0UL;
  key->ul[6] = 0UL;
  key->ul[7] = 0UL;
  return key;
}

static uint
random_part(fd_funk_rec_t * rec, uint num_part, void * cb_arg) {
  (void)rec;
  uint i = fd_rng_uint( (fd_rng_t*)cb_arg ) % ( num_part+2 );
  return (i >= num_part ? FD_FUNK_PART_NULL : i);
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * name     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL,            NULL );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL,      "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL,             1UL );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );
  ulong        wksp_tag = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag",  NULL,          1234UL );
  ulong        seed     = fd_env_strip_cmdline_ulong( &argc, &argv, "--seed",      NULL,          5678UL );
  ulong        txn_max  = fd_env_strip_cmdline_ulong( &argc, &argv, "--txn-max",   NULL,            32UL );
  ulong        rec_max  = fd_env_strip_cmdline_ulong( &argc, &argv, "--rec-max",   NULL,           128UL );
  ulong        iter_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--iter-max",  NULL,         1UL<<22 );
  int          verbose  = fd_env_strip_cmdline_int  ( &argc, &argv, "--verbose",   NULL,               0 );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  fd_wksp_t * wksp;
  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    wksp = fd_wksp_attach( name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }

  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "Unable to attach to wksp" ));

  FD_LOG_NOTICE(( "Testing with --wksp-tag %lu --seed %lu --txn-max %lu --rxn-max %lu --iter-max %lu --verbose %i",
                  wksp_tag, seed, txn_max, rec_max, iter_max, verbose ));

  fd_funk_t * funk = fd_funk_join( fd_funk_new( fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint(), wksp_tag ),
                                                wksp_tag, seed, txn_max, rec_max ) );
  if( FD_UNLIKELY( !funk ) ) FD_LOG_ERR(( "Unable to create funk" ));

  fd_funk_txn_t * txn = NULL;
#define MAX_TEST_REC 16U
  fd_funk_rec_key_t recs[MAX_TEST_REC];
  for (uint i = 0; i < MAX_TEST_REC; ++i)
    fd_funk_rec_key_set_unique(recs + i);

#define NUM_PART 8
  fd_funk_repartition(funk, NUM_PART, random_part, rng);

  fd_funk_start_write(funk);
  
  for( ulong iter=0UL; iter<iter_max; iter++ ) {
    uint r = fd_rng_uint( rng );
    int op = (int)(r & 7U); r >>= 3;
    switch( op ) {

    case 0: { /* commit/create a transaction */
      if ( txn == NULL || (r&3) ) {
        fd_funk_txn_xid_t xid[1];
        txn = fd_funk_txn_prepare(funk, txn, fd_funk_txn_xid_set_unique(xid), 0);
        FD_TEST(txn);
      } else {
        fd_funk_txn_publish(funk, txn, 0);
        txn = NULL;
      }
      break;
    }

    case 1: { /* cancel/create a transaction */
      if ( txn != NULL ) {
        fd_funk_txn_t * parent = fd_funk_txn_parent( txn, fd_funk_txn_map(funk, wksp) );
        fd_funk_txn_cancel(funk, txn, 0);
        txn = parent;;
      }
      break;
    }

    case 2: case 3: { /* create a record */
      uint i = r % MAX_TEST_REC;
      fd_funk_rec_key_t * key = &recs[i];
      fd_funk_rec_t * rec = fd_funk_rec_write_prepare(funk, txn, key, 0, 1, NULL, NULL);
      FD_TEST(rec);
      break;
    }

    case 4: { /* erase a record */
      uint i = r % MAX_TEST_REC;
      fd_funk_rec_key_t * key = &recs[i];
      fd_funk_rec_t * rec = fd_funk_rec_write_prepare(funk, txn, key, 0, 0, NULL, NULL);
      if (rec && !(rec->flags & FD_FUNK_REC_FLAG_ERASE)) {
        int err = fd_funk_rec_remove(funk, rec, 1);
        FD_TEST(!err);
      }
      break;
    }

    case 5: { /* repartition */
      fd_funk_repartition(funk, NUM_PART, random_part, rng);
      break;
    }

    case 6: case 7: { /* move one record */
      uint i = r % MAX_TEST_REC;
      fd_funk_rec_key_t * key = &recs[i];
      fd_funk_rec_t * rec = fd_funk_rec_write_prepare(funk, txn, key, 0, 0, NULL, NULL);
      if (rec && !(rec->flags & FD_FUNK_REC_FLAG_ERASE)) {
        int err = fd_funk_part_set(funk, rec, random_part(rec, NUM_PART, rng));
        FD_TEST(!err);
      }
      break;
    }
    }

    FD_TEST( !fd_funk_verify( funk ) );
  }

  fd_funk_end_write(funk);

  fd_wksp_free_laddr( fd_funk_delete( fd_funk_leave( funk ) ) );
  if( name ) fd_wksp_detach( wksp );
  else       fd_wksp_delete_anonymous( wksp );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_HOSTED capabilities" ));
  fd_halt();
  return 0;
}

#endif

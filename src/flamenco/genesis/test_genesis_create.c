#include "fd_genesis_create.h"
#include "../types/fd_types.h"

#define BUFSZ (32768UL)

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Suppress warning logs */

  int log_level = fd_log_level_logfile();
  fd_log_level_logfile_set( fd_int_max( log_level, 4 ) );

  static uchar scratch_smem[ 8192 ];
         ulong scratch_fmem[ 4 ];
  fd_scratch_attach( scratch_smem, scratch_fmem,
                     sizeof(scratch_smem), sizeof(scratch_fmem)/sizeof(ulong) );

  static uchar pod_mem[ 8192 ];
  uchar * pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );

  /* Minimal configuration */

  FD_TEST( !fd_genesis_create( NULL, 0UL, pod ) );
  fd_pubkey_t identity_pubkey = { .ul = { 0, 0, 0, 1 } };
  fd_pod_insert_pubkey( pod, "identity.pubkey", &identity_pubkey );

  FD_TEST( !fd_genesis_create( NULL, 0UL, pod ) );
  fd_pubkey_t faucet_pubkey = { .ul = { 0, 0, 0, 2 } };
  fd_pod_insert_pubkey( pod, "faucet.pubkey", &faucet_pubkey );

  FD_TEST( !fd_genesis_create( NULL, 0UL, pod ) );
  fd_pubkey_t stake_pubkey = { .ul = { 0, 0, 0, 3 } };
  fd_pod_insert_pubkey( pod, "stake.pubkey", &stake_pubkey );

  FD_TEST( !fd_genesis_create( NULL, 0UL, pod ) );
  fd_pubkey_t vote_pubkey = { .ul = { 0, 0, 0, 4 } };
  fd_pod_insert_pubkey( pod, "vote.pubkey", &vote_pubkey );

  FD_TEST( !fd_genesis_create( NULL, 0UL, pod ) );
  fd_pod_insert_ulong( pod, "creation_time",  123UL );
  fd_pod_insert_ulong( pod, "ticks_per_slot",  64UL );

  FD_TEST( !fd_genesis_create( NULL, 0UL, pod ) );
  fd_pod_insert_ulong( pod, "target_tick_µs", 6250UL );

  /* Buffer too small */

  FD_TEST( !fd_genesis_create( NULL, 0UL, pod ) );

  /* No more warnings expected */

  fd_log_level_logfile_set( log_level );

  /* Serialize to buffer */

  static uchar result_mem[ BUFSZ ];
  ulong result_sz = fd_genesis_create( result_mem, sizeof(result_mem), pod );
  FD_TEST( result_sz );

  /* Now try adding a few accounts */

  fd_pod_insert_ulong( pod, "default_funded.cnt", 16UL );
  result_sz = fd_genesis_create( result_mem, sizeof(result_mem), pod );
  FD_TEST( result_sz );

  /* TODO load this into a Firedancer runtime and verify the resulting slot context */

  FD_TEST( fd_pod_delete( fd_pod_leave ( pod ) )==pod_mem );

  FD_LOG_NOTICE(( "pass" ));

  fd_scratch_detach( NULL );
  fd_halt();
  return 0;
}

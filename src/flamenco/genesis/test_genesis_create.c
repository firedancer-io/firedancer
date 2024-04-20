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


  /* Minimal configuration */
  fd_genesis_options_t options[1] = {{
    .identity_pubkey             = { .ul = { 0, 0, 0, 1 } },
    .faucet_pubkey               = { .ul = { 0, 0, 0, 2 } },
    .stake_pubkey                = { .ul = { 0, 0, 0, 3 } },
    .vote_pubkey                 = { .ul = { 0, 0, 0, 4 } },
    .creation_time               = 123UL,
    .ticks_per_slot              = 64UL,
    .target_tick_duration_micros = 6250UL
  }};

  /* Buffer too small */

  FD_TEST( !fd_genesis_create( NULL, 0UL, options, NULL, 0UL ) );

  /* No more warnings expected */

  fd_log_level_logfile_set( log_level );

  /* Serialize to buffer */

  static uchar result_mem[ BUFSZ ];
  ulong result_sz = fd_genesis_create( result_mem, sizeof(result_mem), options, NULL, 0UL );
  FD_TEST( result_sz );

  /* Now try adding a few accounts */

  options->fund_initial_accounts = 16UL;
  result_sz = fd_genesis_create( result_mem, sizeof(result_mem), options, NULL, 0UL );
  FD_TEST( result_sz );

  /* TODO load this into a Firedancer runtime and verify the resulting slot context */

  FD_LOG_NOTICE(( "pass" ));

  fd_scratch_detach( NULL );
  fd_halt();
  return 0;
}

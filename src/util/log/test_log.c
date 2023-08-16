#include "../fd_util.h"

FD_STATIC_ASSERT( FD_LOG_NAME_MAX==40UL, unit_test );

FD_STATIC_ASSERT( FD_LOG_WALLCLOCK_CSTR_BUF_SZ==37UL, unit_test );

FD_STATIC_ASSERT( FD_LOG_GROUP_ID_QUERY_LIVE == 1, unit_test );
FD_STATIC_ASSERT( FD_LOG_GROUP_ID_QUERY_DEAD == 0, unit_test );
FD_STATIC_ASSERT( FD_LOG_GROUP_ID_QUERY_INVAL==-1, unit_test );
FD_STATIC_ASSERT( FD_LOG_GROUP_ID_QUERY_PERM ==-2, unit_test );
FD_STATIC_ASSERT( FD_LOG_GROUP_ID_QUERY_FAIL ==-3, unit_test );

int volatile volatile_yes = 1;

static void
backtrace_test( void ) {
  if( volatile_yes ) FD_LOG_CRIT((    "Test CRIT         (warning + backtrace and abort program)" ));
  if( volatile_yes ) FD_LOG_ALERT((   "Test ALERT        (warning + backtrace and abort program)" ));
  if( volatile_yes ) FD_LOG_EMERG((   "Test EMERG        (warning + backtrace and abort program)" ));
}

static char large_blob[ 50000 ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Non-cancelling log messages */
  FD_LOG_DEBUG((   "Test DEBUG        (silent)"                                ));
  FD_LOG_INFO((    "Test INFO         (log file only)"                         ));
  FD_LOG_NOTICE((  "Test NOTICE       (info+shortend to stderr)"               ));
  FD_LOG_WARNING(( "Test WARNING      (notice+flush log and stderr)"           ));

  /* Info about the calling thread */

  int cmode = fd_log_colorize();
  FD_LOG_NOTICE(( "fd_log_colorize      %i",  cmode                  ));
  FD_LOG_NOTICE(( "fd_log_level_logfile %i",  fd_log_level_logfile() ));
  FD_LOG_NOTICE(( "fd_log_level_stderr  %i",  fd_log_level_stderr()  ));
  FD_LOG_NOTICE(( "fd_log_level_flush   %i",  fd_log_level_flush()   ));
  FD_LOG_NOTICE(( "fd_log_level_core    %i",  fd_log_level_core()    ));
  FD_LOG_NOTICE(( "fd_log_app_id        %lu", fd_log_app_id()        ));
  FD_LOG_NOTICE(( "fd_log_thread_id     %lu", fd_log_thread_id()     ));
  FD_LOG_NOTICE(( "fd_log_host_id       %lu", fd_log_host_id()       ));
  FD_LOG_NOTICE(( "fd_log_cpu_id        %lu", fd_log_cpu_id()        ));
  FD_LOG_NOTICE(( "fd_log_group_id      %lu", fd_log_group_id()      ));
  FD_LOG_NOTICE(( "fd_log_tid           %lu", fd_log_tid()           ));
  FD_LOG_NOTICE(( "fd_log_user_id       %lu", fd_log_user_id()       ));
  FD_LOG_NOTICE(( "fd_log_app           %s",  fd_log_app()           ));
  FD_LOG_NOTICE(( "fd_log_thread        %s",  fd_log_thread()        ));
  FD_LOG_NOTICE(( "fd_log_host          %s",  fd_log_host()          ));
  FD_LOG_NOTICE(( "fd_log_cpu           %s",  fd_log_cpu()           ));
  FD_LOG_NOTICE(( "fd_log_group         %s",  fd_log_group()         ));
  FD_LOG_NOTICE(( "fd_log_user          %s",  fd_log_user()          ));

  /* Make sure build info is a proper cstr */
  FD_TEST( fd_log_build_info_sz>0UL                              );
  FD_TEST( !fd_log_build_info[ fd_log_build_info_sz-1UL ]        );
  FD_TEST( (strlen(fd_log_build_info)+1UL)==fd_log_build_info_sz );

  if( FD_LIKELY( fd_log_build_info_sz>1UL ) ) FD_LOG_NOTICE(( "fd_log_build_info:\n%s", fd_log_build_info ));
  else                                        FD_LOG_NOTICE(( "fd_log_build_info not available" ));

  if( cmode ) {
    fd_log_colorize_set( 0 );
    FD_LOG_NOTICE(( "disabled colorize" ));
    fd_log_colorize_set( cmode );
    FD_LOG_NOTICE(( "reenabled colorize" ));
  }

  FD_TEST( fd_log_group_id_query( 0UL               )==FD_LOG_GROUP_ID_QUERY_INVAL );
  FD_TEST( fd_log_group_id_query( ULONG_MAX         )==FD_LOG_GROUP_ID_QUERY_INVAL );
  FD_TEST( fd_log_group_id_query( fd_log_group_id() )==FD_LOG_GROUP_ID_QUERY_LIVE  );

  FD_LOG_NOTICE( ( "Testing hexdump logging API: " ) );

  /* Exercise edge cases.  Covers permutations of {NOTICE,WARNING}
     levels x {NULL,empty,normal,long} descriptions x {NULL,non-NULL}
     mem x {0,non-zero} sz.  The mem itself in cases should be entirely
     printable characters and thus should exercise printable characters. */

  char const * test_cstr    = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz ~!@#$%^&*()_+`-=[]\\;',./{}|:\"<>?";
  ulong        test_cstr_sz = strlen( test_cstr ) + 1UL;

  FD_LOG_HEXDUMP_NOTICE (( NULL,                                                  NULL,      0UL          ));
  FD_LOG_HEXDUMP_NOTICE (( NULL,                                                  NULL,      test_cstr_sz ));
  FD_LOG_HEXDUMP_NOTICE (( NULL,                                                  test_cstr, 0UL          ));
  FD_LOG_HEXDUMP_NOTICE (( NULL,                                                  test_cstr, test_cstr_sz ));
  FD_LOG_HEXDUMP_NOTICE (( "",                                                    NULL,      0UL          ));
  FD_LOG_HEXDUMP_NOTICE (( "",                                                    NULL,      test_cstr_sz ));
  FD_LOG_HEXDUMP_NOTICE (( "",                                                    test_cstr, 0UL          ));
  FD_LOG_HEXDUMP_NOTICE (( "",                                                    test_cstr, test_cstr_sz ));
  FD_LOG_HEXDUMP_NOTICE (( "notice_mem_null_sz_zero",                             NULL,      0UL          ));
  FD_LOG_HEXDUMP_NOTICE (( "notice_mem_null_sz_nonzero",                          NULL,      test_cstr_sz ));
  FD_LOG_HEXDUMP_NOTICE (( "notice_mem_nonnull_sz_zero",                          test_cstr, 0UL          ));
  FD_LOG_HEXDUMP_NOTICE (( "notice_mem_nonnull_sz_nonzero",                       test_cstr, test_cstr_sz ));
  FD_LOG_HEXDUMP_NOTICE (( "notice_long_description_that_needs_to_be_truncated",  NULL,      0UL          ));
  FD_LOG_HEXDUMP_NOTICE (( "notice_long_description_that_needs_to_be_truncated",  NULL,      test_cstr_sz ));
  FD_LOG_HEXDUMP_NOTICE (( "notice_long_description_that_needs_to_be_truncated",  test_cstr, 0UL          ));
  FD_LOG_HEXDUMP_NOTICE (( "notice_long_description_that_needs_to_be_truncated",  test_cstr, test_cstr_sz ));
  FD_LOG_HEXDUMP_WARNING(( NULL,                                                  NULL,      0UL          ));
  FD_LOG_HEXDUMP_WARNING(( NULL,                                                  NULL,      test_cstr_sz ));
  FD_LOG_HEXDUMP_WARNING(( NULL,                                                  test_cstr, 0UL          ));
  FD_LOG_HEXDUMP_WARNING(( NULL,                                                  test_cstr, test_cstr_sz ));
  FD_LOG_HEXDUMP_WARNING(( "",                                                    NULL,      0UL          ));
  FD_LOG_HEXDUMP_WARNING(( "",                                                    NULL,      test_cstr_sz ));
  FD_LOG_HEXDUMP_WARNING(( "",                                                    test_cstr, 0UL          ));
  FD_LOG_HEXDUMP_WARNING(( "",                                                    test_cstr, test_cstr_sz ));
  FD_LOG_HEXDUMP_WARNING(( "warning_mem_null_sz_zero",                            NULL,      0UL          ));
  FD_LOG_HEXDUMP_WARNING(( "warning_mem_null_sz_nonzero",                         NULL,      test_cstr_sz ));
  FD_LOG_HEXDUMP_WARNING(( "warning_mem_nonnull_sz_zero",                         test_cstr, 0UL          ));
  FD_LOG_HEXDUMP_WARNING(( "warning_mem_nonnull_sz_nonzero",                      test_cstr, test_cstr_sz ));
  FD_LOG_HEXDUMP_WARNING(( "warning_long_description_that_needs_to_be_truncated", NULL,      0UL          ));
  FD_LOG_HEXDUMP_WARNING(( "warning_long_description_that_needs_to_be_truncated", NULL,      test_cstr_sz ));
  FD_LOG_HEXDUMP_WARNING(( "warning_long_description_that_needs_to_be_truncated", test_cstr, 0UL          ));
  FD_LOG_HEXDUMP_WARNING(( "warning_long_description_that_needs_to_be_truncated", test_cstr, test_cstr_sz ));

  /* Exercise line wrapping and different length straggler lines */
  for( ulong sz=0UL; sz<32UL; sz++ ) FD_LOG_HEXDUMP_NOTICE(( "small_sz", test_cstr, sz ));

  /* Exercise too large blobs */
  memset( large_blob, 0x62, 50000UL );
  FD_LOG_HEXDUMP_NOTICE(( "very_large_blob", large_blob, 50000UL ));

  /* Exercise unprintable characters */
  char unprintable_blob[] = "\xff\x00\xff\x82\x90\x02\x05\x09\xff\x00\xff\x82\x90\x02\x05\x09"
                            "\xff\x00\xff\x82\x90\x02\x05\x09\xff\x00\xff\x82\x90\x02\x05\x09"
                            "\xff\x00\xff\x82\x90\x02\x05\x09\xff\x00\xff\x82\x90\x02\x05\x09"
                            "\xff\x00\xff\x82\x90\x02\x05\x09\xff\x00\xff\x82\x90\x02\x05\x09";
  FD_LOG_HEXDUMP_NOTICE(( "hex_unprintable_blob", unprintable_blob, 64UL ));

  /* Exercise mixtures of printable and unprintable characters */
  char mixed_blob[] = "\xff\x00\xff\x82\x90\x02\x05\x09\xff\x00\xff\x82\x90\x02\x05\x09"
                      "\xff\x00\xff\x82\x90\x02\x61\x09\xff\x00\xff\x82\x90\x02\x05\x09"
                      "\x66\x90\x69\x05\x72\xff\x65\xff\x64\x90\x61\x05\x6e\x00\x63\x08"
                      "\x65\x00\x72\x82\x90\x02\x05\x09\xff\x78\xff\x72\x90\x02\x05\x09"
                      "\xff\x00\x41\x82\x45\x02\x05\x09\xff\x78\xff\x72\x90\x02\x05\x09"
                      "\xff\x00\xff\x82\x90\x02\x05\x09\xff\x78\xff\x72\x90\x02\x05\x09"
                      "\xff\x00\xff\x82\x90\x55\x05\x09\xff\x78\xff\x72\x90\x02\x05\x09"
                      "\x50\x00\x44\x82\x90\x02\x05\x09\xff\x78\xff\x72\x90\x02\x05\x09";
  FD_LOG_HEXDUMP_NOTICE(( "mixed_blob", mixed_blob, 128UL ));

  FD_LOG_NOTICE(( "Testing log levels" ));
  int i;
  i = fd_log_level_logfile(); fd_log_level_logfile_set(i-1); FD_TEST( fd_log_level_logfile()==i-1 ); fd_log_level_logfile_set(i);
  i = fd_log_level_stderr();  fd_log_level_stderr_set (i-1); FD_TEST( fd_log_level_stderr() ==i-1 ); fd_log_level_stderr_set (i);
  i = fd_log_level_flush();   fd_log_level_flush_set  (i-1); FD_TEST( fd_log_level_flush()  ==i-1 ); fd_log_level_flush_set  (i);
  i = fd_log_level_core();    fd_log_level_core_set   (i-1); FD_TEST( fd_log_level_core()   ==i-1 ); fd_log_level_core_set   (i);

  FD_LOG_NOTICE(( "Setting thread name" ));
  fd_log_thread_set( "main-thread" );
  if( strcmp( fd_log_thread(), "main-thread" ) ) FD_LOG_ERR(( "FAIL: fd_log_thread_set" ));

  FD_LOG_NOTICE(( "Setting cpu name" ));
  fd_log_cpu_set( "main-cpu" );
  if( strcmp( fd_log_cpu(), "main-cpu" ) ) FD_LOG_ERR(( "FAIL: fd_log_cpu_set" ));

  /* Rudimentary wallclock tests */
  long tic;
  long toc = fd_log_wallclock();
  for( int i=0; i<10; i++ ) { tic = toc; toc = fd_log_wallclock(); }
  FD_LOG_NOTICE((  "Test wallclock overhead %li ns", toc-tic ));

  tic = fd_log_wallclock();
  toc = (long)1e9; do toc = fd_log_sleep( toc ); while( toc );
  tic = fd_log_wallclock() - (tic+(long)1e9);
  FD_LOG_NOTICE(( "Test fd_log_sleep delta %li ns", tic ));
  FD_TEST( fd_long_abs( tic ) < (ulong)25e6 );

  tic = fd_log_wallclock();
  tic = fd_log_wait_until( tic+(long)1e9 ) - (tic+(long)1e9);
  FD_LOG_NOTICE(( "Test fd_log_wait_until delta %li ns", tic ));
  FD_TEST( fd_long_abs( tic ) < (ulong)25e3 );

  /* Debugging helpers */
  static uchar const hex[16] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
  FD_LOG_NOTICE((  "Test hex          " FD_LOG_HEX16_FMT, FD_LOG_HEX16_FMT_ARGS( hex ) ));

  if( volatile_yes ) for( int i=0; i<20000000; i++ ) FD_LOG_NOTICE(( "dup" ));

  FD_LOG_NOTICE((  "Test fd_log_flush" ));
  fd_log_flush();

  /* Ensure FD_TEST doesn't interpret line as a format string.  Note
     strict clang compiles don't permit implicit conversion of a cstr to
     a logical so we avoid those tests if FD_USING_CLANG.  Arguably, we
     could do !!"foo" here instead but that in some sense defeats the
     point of these tests. */

# if !FD_USING_CLANG
  FD_TEST( "%n %n %n %n %n %n %n %n %n %n %n %n %n" );
  FD_TEST( "\"\\\"" );
# endif

  /* Cancelling log messages */
  if( !volatile_yes ) FD_LOG_ERR((     "Test ERR          (warning+exit program with error 1)"     ));
  if( !volatile_yes ) backtrace_test();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

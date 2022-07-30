#include "../fd_util.h"

int volatile volatile_yes = 1;

static void
backtrace_test( void ) {
  if( volatile_yes ) FD_LOG_CRIT((    "Test CRIT         (warning + backtrace and abort program)" ));
  if( volatile_yes ) FD_LOG_ALERT((   "Test ALERT        (warning + backtrace and abort program)" ));
  if( volatile_yes ) FD_LOG_EMERG((   "Test EMERG        (warning + backtrace and abort program)" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

# define TEST(c) do if( !(c) ) { FD_LOG_WARNING(( "FAIL: " #c )); return 1; } while(0)

  /* Non-cancelling log messages */
  FD_LOG_DEBUG((   "Test DEBUG        (silent)"                                ));
  FD_LOG_INFO((    "Test INFO         (log file only)"                         ));
  FD_LOG_NOTICE((  "Test NOTICE       (info+shortend to stderr)"               ));
  FD_LOG_WARNING(( "Test WARNING      (notice+flush log and stderr)"           ));
  
  /* Info about the calling thread */
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
  FD_LOG_NOTICE(( "fd_log_app           %s",  fd_log_app()           ));
  FD_LOG_NOTICE(( "fd_log_thread        %s",  fd_log_thread()        ));
  FD_LOG_NOTICE(( "fd_log_host          %s",  fd_log_host()          ));
  FD_LOG_NOTICE(( "fd_log_cpu           %s",  fd_log_cpu()           ));
  FD_LOG_NOTICE(( "fd_log_group         %s",  fd_log_group()         ));
  FD_LOG_NOTICE(( "fd_log_user          %s",  fd_log_user()          ));

  FD_LOG_NOTICE(( "Testing log levels" ));
  int i;
  i = fd_log_level_logfile(); fd_log_level_logfile_set(i-1); TEST( fd_log_level_logfile()==i-1 ); fd_log_level_logfile_set(i);
  i = fd_log_level_stderr();  fd_log_level_stderr_set (i-1); TEST( fd_log_level_stderr() ==i-1 ); fd_log_level_stderr_set (i);
  i = fd_log_level_flush();   fd_log_level_flush_set  (i-1); TEST( fd_log_level_flush()  ==i-1 ); fd_log_level_flush_set  (i);
  i = fd_log_level_core();    fd_log_level_core_set   (i-1); TEST( fd_log_level_core()   ==i-1 ); fd_log_level_core_set   (i);

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
  FD_LOG_NOTICE((  "Test wallclock dt %li ns", toc-tic         ));

  tic = fd_log_wallclock();
  toc = (long)1e9; do toc = fd_log_sleep( toc ); while( toc );
  tic = fd_log_wallclock() - tic;
  TEST( ((long)0.9e9)<tic && tic<((long)1.1e9) );

  /* Debugging helpers */
  static uchar const hex[16] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
  FD_LOG_NOTICE((  "Test hex          " FD_LOG_HEX16_FMT, FD_LOG_HEX16_FMT_ARGS( hex ) ));

  if( volatile_yes ) for( int i=0; i<20000000; i++ ) FD_LOG_NOTICE(( "dup" ));

  FD_LOG_NOTICE((  "Test fd_log_flush" ));
  fd_log_flush();

  /* Cancelling log messages */
  if( volatile_yes ) FD_LOG_ERR((     "Test ERR          (warning+exit program with error 1)"     ));
  /* Never get to this point */
  backtrace_test();

# undef TEST

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}


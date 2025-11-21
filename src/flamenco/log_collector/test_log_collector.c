#include "./fd_log_collector.h"

/* This is Agave's test, that logs 20k instances of "x".
   This is not a particularly realistic test, because user logs (via
   BPF programs) start with "Program log: ", thus they are at least
   13 chars long.
   In our implementation, each log entry has a 2-3 bytes overhead, so
   this test would require a lot of extra memory that's completely
   unnecessary in real situations.
   For this reason this test is not run. We run instead a more realistic
   version: test_log_messages_bytes_limit().
   To run this, set FD_LOG_COLLECTOR_EXTRA to 20008+. */
void
test_log_messages_bytes_limit_agave( fd_runtime_t * runtime ) {
  fd_exec_instr_ctx_t ctx[1];
  fd_log_collector_t  log[1];
  ctx->runtime = runtime;
  runtime->log.log_collector = log;
  fd_log_collector_init( log, 1 );

  for( ulong i=0; i<20000; i++ ) {
    fd_log_collector_msg_literal( ctx, "x" );
  }

  FD_TEST( fd_log_collector_debug_len( log )==10000 );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 0, NULL, NULL ),    FD_EXEC_LITERAL("x") ) );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 1, NULL, NULL ),    FD_EXEC_LITERAL("x") ) );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 9998, NULL, NULL ), FD_EXEC_LITERAL("x") ) );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 9999, NULL, NULL ), FD_EXEC_LITERAL("Log truncated") ) );
}

static void
test_log_messages_bytes_limit( fd_runtime_t * runtime ) {
  fd_exec_instr_ctx_t ctx[1];
  fd_log_collector_t  log[1];
  ctx->runtime = runtime;
  runtime->log.log_collector = log;

  fd_log_collector_init( log, 1 );

  for( ulong i=0; i<10000; i++ ) {
    fd_log_collector_msg_literal( ctx, "Program log: " );
  }

  FD_TEST( fd_log_collector_debug_len( log )==770 );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 0, NULL, NULL ),   FD_EXEC_LITERAL("Program log: ") ) );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 1, NULL, NULL ),   FD_EXEC_LITERAL("Program log: ") ) );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 768, NULL, NULL ), FD_EXEC_LITERAL("Program log: ") ) );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 769, NULL, NULL ), FD_EXEC_LITERAL("Log truncated") ) );
}

static void
test_log_messages_single_log_limit( fd_runtime_t * runtime ) {
  fd_exec_instr_ctx_t ctx[1];
  fd_log_collector_t  log[1];
  ctx->runtime = runtime;
  runtime->log.log_collector = log;

  char msg10k[ 10000+1 ]; sprintf( msg10k, "%0*d", 10000, 0 );
  char msg9999[ 9999+1 ]; sprintf( msg9999, "%0*d", 9999, 0 );

  fd_log_collector_init( log, 1 );
  fd_log_collector_msg( ctx, msg10k, 10000 );

  FD_TEST( fd_log_collector_debug_len( log )==1 );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 0, NULL, NULL ), FD_EXEC_LITERAL("Log truncated") ) );

  fd_log_collector_init( log, 1 );
  fd_log_collector_msg( ctx, msg9999, 9999 );
  fd_log_collector_msg( ctx, msg9999, 9999 );

  FD_TEST( fd_log_collector_debug_len( log )==2 );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 0, NULL, NULL ), msg9999, 9999 ) );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 1, NULL, NULL ), FD_EXEC_LITERAL("Log truncated") ) );
}

static void
test_log_messages_weird_behavior( fd_runtime_t * runtime ) {
  fd_exec_instr_ctx_t ctx[1];
  fd_log_collector_t  log[1];
  ctx->runtime = runtime;
  runtime->log.log_collector = log;

  char msg9999[ 9999+1 ]; sprintf( msg9999, "%0*d", 9999, 0 );

  fd_log_collector_init( log, 1 );
  fd_log_collector_msg_literal( ctx, "x" );
  fd_log_collector_msg        ( ctx, msg9999, 9999 );
  fd_log_collector_msg_literal( ctx, "x" );
  fd_log_collector_msg_literal( ctx, "x" );

  FD_TEST( fd_log_collector_debug_len( log )==4 );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 0, NULL, NULL ), FD_EXEC_LITERAL("x") ) );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 1, NULL, NULL ), FD_EXEC_LITERAL("Log truncated") ) );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 2, NULL, NULL ), FD_EXEC_LITERAL("x") ) );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 3, NULL, NULL ), FD_EXEC_LITERAL("x") ) );
}

static void
test_log_messages_equivalences( fd_runtime_t * runtime ) {
  fd_exec_instr_ctx_t ctx[1];
  fd_log_collector_t  log[1];
  ctx->runtime = runtime;
  runtime->log.log_collector = log;

  uchar msg[17] = { 0x67, 0x72, 0xc3, 0xbc, 0x65, 0x7a, 0x69, 0x00, 0x0a, 0xf0, 0x9f, 0x94, 0xa5, 0xf0, 0x9f, 0x92, 0x83 };

  fd_log_collector_init( log, 1 );
  for( ulong i=0; i<1000; i++ ) {
    fd_log_collector_msg        ( ctx, (char *)msg, sizeof(msg) );
    fd_log_collector_msg_literal( ctx, "hello 12345, world!" );
  }

  FD_TEST( fd_log_collector_debug_len( log )==556 );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 0, NULL, NULL ),   msg, sizeof(msg) ) );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 1, NULL, NULL ),   FD_EXEC_LITERAL("hello 12345, world!") ) );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 553, NULL, NULL ), FD_EXEC_LITERAL("hello 12345, world!") ) );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 554, NULL, NULL ), msg, sizeof(msg) ) );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 555, NULL, NULL ), FD_EXEC_LITERAL("Log truncated") ) );

  fd_log_collector_init( log, 1 );
  for( ulong i=0; i<1000; i++ ) {
    fd_log_collector_msg( ctx, (char *)msg, sizeof(msg) );
    fd_log_collector_printf_dangerous_max_127( ctx, "hello %d, %s!", 12345, "world" );
  }

  FD_TEST( fd_log_collector_debug_len( log )==556 );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 0, NULL, NULL ),   msg, sizeof(msg) ) );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 1, NULL, NULL ),   FD_EXEC_LITERAL("hello 12345, world!") ) );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 553, NULL, NULL ), FD_EXEC_LITERAL("hello 12345, world!") ) );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 554, NULL, NULL ), msg, sizeof(msg) ) );
  FD_TEST( fd_memeq( fd_log_collector_debug_get( log, 555, NULL, NULL ), FD_EXEC_LITERAL("Log truncated") ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * name     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL, NULL            );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"      );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 4UL             );
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

  fd_runtime_t * runtime = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_t), sizeof(fd_runtime_t), wksp_tag );
  FD_TEST( runtime );

  // test_log_messages_bytes_limit_agave();
  test_log_messages_bytes_limit( runtime );
  test_log_messages_single_log_limit( runtime );
  test_log_messages_weird_behavior( runtime );
  test_log_messages_equivalences( runtime );
  FD_LOG_NOTICE(( "pass" ));

  fd_halt();
  return 0;
}

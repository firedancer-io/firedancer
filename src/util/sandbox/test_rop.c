#define _GNU_SOURCE
#include "../fd_util.h"
#include "fd_shstk.h"

__attribute__((used,noinline,noreturn)) static void
rop_target( void ) {
  FD_LOG_ERR(( "ROP attack succeeded. IBT/SHSTK is not active" ));
}

__attribute__((naked,noinline,noreturn)) static void
rop_attack( void ) {
  __asm__(
    "leaq rop_target(%rip), %rax\n\t"
    "movq %rax, (%rsp)\n\t"
    "ret\n\t"
  );
}

static int
main1( int     argc,
       char ** argv ) {
  (void)argc; (void)argv;
  rop_attack();
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  int shstk = fd_env_strip_cmdline_contains( &argc, &argv, "--shstk" );
  if( shstk ) fd_shstk_enter( main1, argc, argv );
  else        return main1( argc, argv );
}

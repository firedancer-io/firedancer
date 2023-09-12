/* This is a pretty strange wrapper...

   We want to support "F5" debugging from, eg, VS code. To do that, VS
   code has an agent on our development box running as the user. It is
   not root and has no capabilities. That agent forks a child process
   that then exec's "gdb", which then loads and runs our program.

   We need to run our program as root sometimes. You might imagine a few
   ways to do that,

    (a) Run the agent as root? Not supported by VS code. It's probably
        feasible to make changes to the agent code itself to get this
        working but it seems difficult.
    (b) Run gdb as root? The agent won't launch it as root, but we
        could for example setuid the gdb binary itself. This doesn't
        work quite right because it prevents VS code from communicating
        with GDB, eg, to pause execution. See this bug
        https://github.com/microsoft/vscode-cpptools/issues/4243
    (c) Run the program as root, eg, using setuid? This isn't really
        possible. A non-root GDB will not attach to a root program for
        security reasons.

   So we can't really get the program running as root in any scenario.
   What else can we do? Just run it with all capabilities... that's what
   this program does.

   The sequence here is that, VS code sets this binary as it's "gdb"
   path, then, when launched this program,

    (1) Fork off a sudo process which `setcaps` the current binary to
        have all capabilities.
    (2) The parent waits for the sudo process, then reruns itself
        again to have all capabilities
    (3) Now running with capabilities, we do a `CAP_AMBIENT_RAISE` so
        that capabilities survive a `/bin/gdb` invocation which would
        normally strip them for security reasons.
    (4) Now we finally exec `/bin/gdb` with the arguments provided by
        the IDE. */
#define _GNU_SOURCE

#include "../../util/fd_util.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include <linux/capability.h>

static int
has_all_capabilities( void ) {
  struct __user_cap_header_struct capheader;
  struct __user_cap_data_struct capdata[2];

  capheader.version = _LINUX_CAPABILITY_VERSION_3;
  capheader.pid = 0;
  FD_TEST( syscall( SYS_capget, &capheader, &capdata ) >= 0 );
  return
    capdata[0].permitted == 0xFFFFFFFF &&
    ( capdata[1].permitted & 0x000001FF ) == 0x000001FF;
}

static void
raise_all_capabilities( void ) {
  struct __user_cap_header_struct capheader;
  struct __user_cap_data_struct capdata[2];

  capheader.version = _LINUX_CAPABILITY_VERSION_3;
  capheader.pid = 0;
  FD_TEST( syscall( SYS_capget, &capheader, &capdata ) >= 0 );

  capdata[0].effective = 0xFFFFFFFF;
  capdata[0].inheritable = 0xFFFFFFFF;
  capdata[1].effective = 0xFFFFFFFF;
  capdata[1].inheritable = 0xFFFFFFFF;
  FD_TEST( syscall(SYS_capset, &capheader, &capdata) >= 0 );

  for ( int cap = 0; cap <= CAP_LAST_CAP; cap++ )
    FD_TEST( !prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0) );
}

static void
self_exe( char * path ) {
  long count = readlink( "/proc/self/exe", path, PATH_MAX );
  FD_TEST( count >= 0 && count < PATH_MAX );
  path[ count ] = '\0';
}

int
main( int argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  if( FD_UNLIKELY( argc > 1 && !strcmp( argv[1], "--setcap" ) ) ) {
    struct vfs_cap_data {
        __le32 magic_etc;
        struct {
            __le32 permitted;
            __le32 inheritable;
        } data[2];
    } cap_data;

    cap_data.magic_etc = VFS_CAP_REVISION_2;
    cap_data.data[0].permitted = 0xFFFFFFFF;
    cap_data.data[0].inheritable = 0xFFFFFFFF;
    cap_data.data[1].permitted = 0xFFFFFFFF;
    cap_data.data[1].inheritable = 0xFFFFFFFF;

    char self_path[ PATH_MAX ];
    self_exe( self_path );
    FD_TEST( !setxattr( self_path, "security.capability", &cap_data, sizeof(cap_data), 0) );
  } else {
    if( FD_UNLIKELY( !has_all_capabilities() ) ) {
      if ( FD_UNLIKELY( argc > 1 && !strcmp( argv[1], "--withcap" ) ) ) FD_LOG_ERR(( "missing capabilities" ));

      char self_path[ PATH_MAX ];
      self_exe( self_path );

      pid_t child = fork();
      FD_TEST( child >= 0 );
      if( child == 0 ) execv( "/bin/sudo", (char *[]){ "sudo", self_path, "--setcap", NULL } );
      else {
        int wstatus;
        FD_TEST( waitpid( child, &wstatus, 0 ) >= 0 );
        FD_TEST( WIFEXITED( wstatus ) && !WEXITSTATUS( wstatus ) );
        char self_path[ PATH_MAX ];
        self_exe( self_path );
        FD_TEST( execv( self_path, (char *[]){ "fddbg", "--withcap", NULL } ) >= 0 );
      }
    } else {
      raise_all_capabilities();

      char * args[ 32 ];
      int start = argc > 1 && !strcmp( argv[1], "--withcap" ) ? 2 : 1;
      args[0] = "/bin/gdb";
      for( int i=start; i<argc; i++ ) args[i-start+1] = argv[i];
      args[ argc-start+1 ] = NULL;

      FD_TEST( execv( "/bin/gdb", args ) >= 0 );
    }
  }
}

#define _GNU_SOURCE
#include "fd_sys_util.h"

#include <pwd.h>
#include <errno.h>
#include <stdlib.h> /* getenv */
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/wait.h>

void __attribute__((noreturn))
fd_sys_util_exit_group( int code ) {
  syscall( SYS_exit_group, code );
  for(;;);
}

int
fd_sys_util_nanosleep( uint secs,
                       uint nanos ) {
  struct timespec ts = { .tv_sec = secs, .tv_nsec = nanos };
  struct timespec rem;
  while( FD_UNLIKELY( -1==nanosleep( &ts, &rem ) ) ) {
    if( FD_LIKELY( errno==EINTR ) ) ts = rem;
    else return -1;
  }
  return 0;
}

char const *
fd_sys_util_login_user( void ) {
  char * name = getenv( "SUDO_USER" );
  if( FD_UNLIKELY( name ) ) return name;

  name = getenv( "LOGNAME" );
  if( FD_LIKELY( name ) ) return name;

  name = getenv( "USER" );
  if( FD_LIKELY( name ) ) return name;

  name = getenv( "LNAME" );
  if( FD_LIKELY( name ) ) return name;

  name = getenv( "USERNAME" );
  if( FD_LIKELY( name ) ) return name;

  name = getlogin();
  if( FD_UNLIKELY( !name && (errno==ENXIO || errno==ENOTTY) ) ) return NULL;
  else if( FD_UNLIKELY( !name ) ) FD_LOG_ERR(( "getlogin failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  return name;
}

int
fd_sys_util_user_to_uid( char const * user,
                         uint *       uid,
                         uint *       gid ) {
  uint * results = mmap( NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0 );
  if( FD_UNLIKELY( results==MAP_FAILED ) ) return -1;

  results[ 0 ] = UINT_MAX;
  results[ 1 ] = UINT_MAX;

  /* This is extremely unfortunate.  We just want to call getpwnam but
     on various glibc it can open `/var/lib/sss/mc/passwd` and then not
     close it.  We could go and find this file descriptor and close it
     for the library, but that is a bit of a hack.  Instead we fork a
     new process to call getpwnam and then exit.

     We could try just reading /etc/passwd here instead, but the glibc
     getpwnam implementation does a lot of things we need, including
     potentially reading from NCSD or SSSD. */

  pid_t pid = fork();
  if( FD_UNLIKELY( -1==pid ) ) {
    munmap( results, 4096 );
    return -1;
  }

  if( FD_LIKELY( !pid ) ) {
    char buf[ 16384 ];
    struct passwd pwd;
    struct passwd * result;
    int error = getpwnam_r( user, &pwd, buf, sizeof(buf), &result );
    if( FD_UNLIKELY( error ) ) {
      if( FD_LIKELY( error==ENOENT || error==ESRCH ) ) {
        FD_LOG_WARNING(( "configuration file wants firedancer to run as user `%s` but it does not exist", user ));
        fd_sys_util_exit_group( 1 );
      } else {
        FD_LOG_WARNING(( "could not get user id for `%s` (%i-%s)", user, errno, fd_io_strerror( errno ) ));
        fd_sys_util_exit_group( 1 );
      }
    }
    if( FD_UNLIKELY( !result ) ) {
      FD_LOG_WARNING(( "configuration file wants firedancer to run as user `%s` but it does not exist", user ));
      fd_sys_util_exit_group( 1 );
    }

    results[ 0 ] = pwd.pw_uid;
    results[ 1 ] = pwd.pw_gid;
    fd_sys_util_exit_group( 0 );
  } else {
    int wstatus;
    if( FD_UNLIKELY( -1==waitpid( pid, &wstatus, 0 ) ) ) return -1;
    if( FD_UNLIKELY( WIFSIGNALED( wstatus ) ) ) {
      FD_LOG_WARNING(( "uid fetch process terminated by signal %i-%s", WTERMSIG( wstatus ), fd_io_strsignal( WTERMSIG( wstatus ) ) ));
      munmap( results, 4096 );
      errno = EINTR;
      return -1;
    }
    if( FD_UNLIKELY( WEXITSTATUS( wstatus ) ) ) {
      FD_LOG_WARNING(( "uid fetch process exited with status %i", WEXITSTATUS( wstatus ) ));
      munmap( results, 4096 );
      errno = EINTR;
      return -1;
    }
  }

  if( FD_UNLIKELY( results[ 0 ]==UINT_MAX || results[ 1 ]==UINT_MAX ) ) {
    munmap( results, 4096 );
    errno = ENOENT;
    return -1;
  }

  *uid = results[ 0 ];
  *gid = results[ 1 ];

  if( FD_UNLIKELY( -1==munmap( results, 4096 ) ) ) return -1;

  return 0;
}

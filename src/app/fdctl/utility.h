#ifndef HEADER_fd_src_app_fdctl_utility_h
#define HEADER_fd_src_app_fdctl_utility_h

#include "fdctl.h"

#include <stdlib.h>

/* Get the true PID of the process, as it appears in the root
   PID namespace of the system. */
int
getpid1( void );

/* mkdir_all() is like `mkdir -p`, it creates all directories
   needed as part of the path. Logs an error and exits the process
   if anything goes wrong.  Directories that did not already
   exist will be created with the given uid and gid. */
void
mkdir_all( const char * path,
           uid_t        uid,
           gid_t        gid );

void
exit_group( int status );

/* internet_routing_interface() returns the interface index which
   routes to the public internet (8.8.8.8). If multiple interfaces
   route there, the first one returned by rtnetlink is returned.

   If no interface routes to 8.8.8.8, -1 is returned. */
int internet_routing_interface( void );

/* nanosleep1() sleeps the calling thread for the provided number of
   nanoseconds, ensuring it continues to sleep if it is interrupted.
   The function will log error and exit() if the sleep cannot be
   performed. */
void nanosleep1( uint secs, uint nanos );

/* snprintf1() functions like snprintf except if the buffer is not
   large enough or there is some other error printing, it logs an
   error and exits the program. returns s. */
char *
snprintf1( char * s,
           ulong  maxlen,
           char * format,
           ... );

/* load_key_into_protected_memory() reads the key file from disk and
   stores the parsed contents in a specially mapped page in memory that
   will not appear in core dumps, will not be paged out to disk, is
   readonly, and is protected by guard pages that cannot be accessed.
   key_path must point to the first letter in a nul-terminated cstr that
   is the path on disk of the key file.  The key file must exist, be
   readable, and have the form of a Solana keypair (64 element JSON
   array of bytes).  If public_key_only is non-zero, zeros out the
   private part of the key and returns a pointer to the first byte (of
   32) of the public part of the key in binary format.  If
   public_key_only is zero, returns a pointer to the first byte (of 64)
   of the key in binary format.  Terminates the process by calling
   FD_LOG_ERR with details on any error, so from the perspective of the
   caller, it cannot fail. */
uchar const *
load_key_into_protected_memory( char const * key_path, int public_key_only );

/* current_executable_path() retrieves the full path of the current
   executable into the path.  Path should be a buffer with at least
   PATH_MAX elements or calling this is undefined behavior. Logs error
   and exits if the current executable cannot be determined. */
void
current_executable_path( char path[ PATH_MAX ] );

/* RUN() executes the given string and formatting arguments as a
   subprocess, and waits for the child to complete. If the child does
   not exit successfully with code 0, the calling program is aborted. */
#define RUN(...) do {                                                  \
    char cmd[ 4096 ];                                                  \
    snprintf1( cmd,                                                    \
               sizeof(cmd),                                            \
               __VA_ARGS__ );                                          \
    int ret = system( cmd );                                           \
    if( FD_UNLIKELY( ret ) )                                           \
      FD_LOG_ERR(( "running command `%s` failed exit code=%d (%i-%s)", \
                   cmd,                                                \
                   ret,                                                \
                   errno,                                              \
                   fd_io_strerror( errno ) ));                         \
  } while( 0 )

/* OUTPUT() executes the given string and formatting arguments as a
   subprocess, and waits for the child to complete. The output stdout of
   the child process is captured into the `output` argument. If the
   child does not exit successfully with code 0, or the output of the
   child would overflow the provided output buffer, the calling program
   is aborted. */
#define OUTPUT(output, ...) do {                              \
    char cmd[ 4096 ];                                         \
    snprintf1( cmd,                                           \
               sizeof(cmd),                                   \
               __VA_ARGS__ );                                 \
    FILE * process = popen( cmd, "r" );                       \
    if( FD_UNLIKELY( !process ) )                             \
      FD_LOG_ERR(( "popen of command `%s` failed (%i-%s)",    \
                   cmd,                                       \
                   errno,                                     \
                   fd_io_strerror( errno ) ));                \
    size_t output_len = sizeof( output );                     \
    size_t printed = fread( output,                           \
                            1,                                \
                            output_len,                       \
                            process );                        \
    if( FD_UNLIKELY( ferror( process ) ) )                    \
      FD_LOG_ERR(( "fread of command `%s` failed (%i-%s)",    \
                   cmd,                                       \
                   errno,                                     \
                   fd_io_strerror( errno ) ));                \
    if( FD_UNLIKELY( printed >= output_len ) )                \
      FD_LOG_ERR(( "fread of command `%s` truncated", cmd )); \
    output[ printed ] = '\0';                                 \
    if( FD_UNLIKELY( pclose( process ) == -1 ) )              \
      FD_LOG_ERR(( "pclose of command `%s` failed (%i-%s)",   \
                   cmd,                                       \
                   errno,                                     \
                   fd_io_strerror( errno ) ));                \
  } while( 0 )

#endif /* HEADER_fd_src_app_fdctl_utility_h */

#define _GNU_SOURCE
#include "utility.h"

#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h> /* for explicit_bzero */
#include <time.h>
#include <fcntl.h>
#include <sched.h>
#include <dirent.h>

#include <sys/mman.h> /* for mprotect */
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/unistd.h>

static int namespace_original_fd = 0;

void
enter_network_namespace( const char * interface ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/var/run/netns/%s", interface ) );

  if( FD_LIKELY( !namespace_original_fd ) ) {
    namespace_original_fd = open( "/proc/self/ns/net", O_RDONLY | O_CLOEXEC );
    if( FD_UNLIKELY( namespace_original_fd < 0 ) )
      FD_LOG_ERR(( "failed to open /proc/self/ns/net (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  int fd = open( path, O_RDONLY | O_CLOEXEC );
  if( FD_UNLIKELY( fd < 0 ) ) FD_LOG_ERR(( "failed to open `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( setns( fd, CLONE_NEWNET ) ) )
    FD_LOG_ERR(( "failed to enter network namespace `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  int ret = close( fd );
  if( FD_UNLIKELY( ret ) ) FD_LOG_ERR(( "enter_network_namespace %d (%i-%s)", ret, errno, fd_io_strerror( errno ) ));
}

void
close_network_namespace_original_fd( void ) {
  int ret = close( namespace_original_fd );
  if( FD_UNLIKELY( ret ) ) FD_LOG_ERR(( "leave_network_namespace %d (%i-%s)", ret, errno, fd_io_strerror( errno ) ));
}

void
leave_network_namespace( void ) {
  if( FD_UNLIKELY( !namespace_original_fd ) ) return;

  if( FD_UNLIKELY( setns( namespace_original_fd, CLONE_NEWNET ) ) )
    FD_LOG_ERR(( "failed to enter original network namespace `%d` (%i-%s)",
                 namespace_original_fd, errno, fd_io_strerror( errno ) ));

  int ret = close( namespace_original_fd );
  if( FD_UNLIKELY( ret ) ) FD_LOG_ERR(( "leave_network_namespace %d (%i-%s)", ret, errno, fd_io_strerror( errno ) ));
  namespace_original_fd = 0;
}

void
exit_group( int status ) {
  syscall( SYS_exit_group, status );
}

void
mkdir_all( const char * _path,
           uid_t        uid,
           gid_t        gid ) {
  char path[ PATH_MAX + 1 ] = {0};
  strncpy( path, _path, PATH_MAX );

  char * p = path;
  if( FD_LIKELY( *p == '/' ) ) p++;
  while( FD_LIKELY( *p ) ) {
    if( FD_UNLIKELY( *p == '/' ) ) {
      *p = '\0';
      int error = mkdir( path, 0777 );
      if( FD_UNLIKELY( error && errno != EEXIST ) )
        FD_LOG_ERR(( "mkdir( `%s` ) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ) );
      if( FD_LIKELY( !error ) ) {
        /* only take ownership if we succeeded in creating (did not exist) */
        if( FD_UNLIKELY( chown( path, uid, gid ) ) )
          FD_LOG_ERR(( "chown `%s` failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
        if( FD_UNLIKELY( chmod( path, S_IRUSR | S_IWUSR | S_IXUSR ) ) )
          FD_LOG_ERR(( "chmod `%s` failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
      }

      *p = '/';
    }
    p++;
  }

  int error = mkdir( path, 0777 );
  if( FD_UNLIKELY( error && errno != EEXIST ) )
    FD_LOG_ERR(( "mkdir( `%s` ) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ) );
  if( FD_LIKELY( !error ) ) {
    /* only take ownership if we succeeded in creating (did not exist) */
    if( FD_UNLIKELY( chown( path, uid, gid ) ) )
      FD_LOG_ERR(( "chown `%s` failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( chmod( path, S_IRUSR | S_IWUSR | S_IXUSR ) ) )
      FD_LOG_ERR(( "chmod `%s` failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }
}

void
rmtree( char const * path,
        int          remove_root ) {
  DIR * dir = opendir( path );
  if( FD_UNLIKELY( !dir ) ) {
    if( errno == ENOENT ) return;
    FD_LOG_ERR(( "opendir `%s` failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }

  struct dirent * entry;
  errno = 0;
  while(( entry = readdir( dir ) )) {
    if( FD_LIKELY( !strcmp( entry->d_name, "." ) || !strcmp( entry->d_name, ".." ) ) ) continue;

    char path1[ PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( path1, PATH_MAX, NULL, "%s/%s", path, entry->d_name ) );

    struct stat st;
    if( FD_UNLIKELY( lstat( path1, &st ) ) ) {
      if( FD_LIKELY( errno == ENOENT ) ) continue;
      FD_LOG_ERR(( "stat `%s` failed (%i-%s)", path1, errno, fd_io_strerror( errno ) ));
    }

    if( FD_UNLIKELY( S_ISDIR( st.st_mode ) ) ) {
      rmtree( path1, 1 );
    } else {
      if( FD_UNLIKELY( unlink( path1 ) && errno != ENOENT ) )
        FD_LOG_ERR(( "unlink `%s` failed (%i-%s)", path1, errno, fd_io_strerror( errno ) ));
    }
  }

  if( FD_UNLIKELY( errno && errno != ENOENT ) ) FD_LOG_ERR(( "readdir `%s` failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));

  if( FD_LIKELY( remove_root ) ) {
    if( FD_UNLIKELY( rmdir( path ) ) ) FD_LOG_ERR(( "rmdir `%s` failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( closedir( dir ) ) ) FD_LOG_ERR(( "closedir `%s` failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
}

uint
read_uint_file( char const * path,
                char const * errmsg_enoent ) {
  FILE * fp = fopen( path, "r" );
  if( FD_UNLIKELY( !fp ) ) {
    if( FD_LIKELY( errno==ENOENT ) ) FD_LOG_ERR(( "%s fopen failed `%s` (%i-%s)", errmsg_enoent, path, errno, fd_io_strerror( errno ) ));
    else                             FD_LOG_ERR(( "fopen failed `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }

  uint value = 0U;
  if( FD_UNLIKELY( 1!=fscanf( fp, "%u\n", &value ) ) ) FD_LOG_ERR(( "failed to read uint from `%s`", path ));
  if( FD_UNLIKELY( fclose( fp ) ) ) FD_LOG_ERR(( "fclose failed `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  return value;
}

void
write_uint_file( char const * path,
                 uint         value ) {
  FILE * fp = fopen( path, "w" );
  if( FD_UNLIKELY( !fp ) ) FD_LOG_ERR(( "fopen failed `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( fprintf( fp, "%u\n", value ) <= 0 ) ) FD_LOG_ERR(( "fprintf failed `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( fclose( fp ) ) ) FD_LOG_ERR(( "fclose failed `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
}

int
internet_routing_interface( void ) {
  int sock = socket( AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE );
  if( FD_UNLIKELY( sock < 0 ) )
    FD_LOG_ERR(( "error finding default interface, socket(AF_INET,SOCK_DGRAM,0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  struct {
    struct nlmsghdr nlh;
    struct rtmsg rt;
    char buf[8192];
  } request;

  memset(&request, 0, sizeof(request));
  request.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
  request.nlh.nlmsg_flags = NLM_F_REQUEST;
  request.nlh.nlmsg_type  = RTM_GETROUTE;
  request.rt.rtm_family   = AF_INET;
  request.rt.rtm_dst_len  = 32;

  struct rtattr *rta = (struct rtattr *)( ( (char *)&request ) + NLMSG_ALIGN( request.nlh.nlmsg_len ) );
  rta->rta_len          = RTA_LENGTH(4);
  rta->rta_type         = RTA_DST;
  request.nlh.nlmsg_len = NLMSG_ALIGN( request.nlh.nlmsg_len ) + (uint)RTA_LENGTH( 4 );

  unsigned int ip = (8 << 24) | (8 << 16) | (8 << 8) | 8;
  fd_memcpy( RTA_DATA( rta ), &ip, 4 );

  if( FD_UNLIKELY( send( sock, &request, request.nlh.nlmsg_len, 0 ) < 0 ) )
    FD_LOG_ERR(( "error finding default interface, send() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  char response[ 8192 ];
  long len = recv( sock, response, sizeof(response), 0 );
  if( FD_UNLIKELY( len == sizeof( response ) ) )
    FD_LOG_ERR(( "error finding default interface, response too large" ));

  struct nlmsghdr *nlh;
  int result = -1;
  for( nlh = (struct nlmsghdr *)response; NLMSG_OK( nlh, len ); nlh = NLMSG_NEXT( nlh, len ) ) {
      struct rtmsg *rt = NLMSG_DATA( nlh );

      struct rtattr *rta = RTM_RTA( rt );
      uint rtl = (uint)RTM_PAYLOAD( nlh );

      for (; RTA_OK( rta, rtl ); rta = RTA_NEXT( rta, rtl ) ) {
          if (rta->rta_type == RTA_OIF) {
            result = *(int *)RTA_DATA(rta);
          }
      }
  }

  if( FD_UNLIKELY( close( sock ) ) )
    FD_LOG_ERR(( "error finding default interface, close() socket failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  return result;
}

/* FIXME: USE FD_LOG_SLEEP / FD_LOG_WAIT_UNTIL */
void
nanosleep1( uint secs, uint nanos ) {
  struct timespec ts = { .tv_sec = secs, .tv_nsec = nanos };
  struct timespec rem;
  while( FD_UNLIKELY( nanosleep( &ts, &rem ) ) ) {
    if( FD_LIKELY( errno == EINTR ) ) ts = rem;
    else FD_LOG_ERR(( "nanosleep failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

void
current_executable_path( char path[ static PATH_MAX ] ) {
  long count = readlink( "/proc/self/exe", path, PATH_MAX );
  if( FD_UNLIKELY( count < 0 ) ) FD_LOG_ERR(( "readlink(/proc/self/exe) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( count >= PATH_MAX ) ) FD_LOG_ERR(( "readlink(/proc/self/exe) returned truncated path" ));
  path[ count ] = '\0';
}

/* Expects that key[i] is writable for i in [0, 1600). */
static inline uchar *
read_key( char const * key_path,
          uchar      * key       ) {
  int key_fd = open( key_path, O_RDONLY );
  if( FD_UNLIKELY( key_fd==-1 ) ) {
    if( FD_UNLIKELY( errno == ENOENT ) ) {
      FD_LOG_ERR((
          "The [consensus.identity_path] in your configuration expects a "
          "keyfile at `%s` but there is no such file. Either update the "
          "configuration file to point to your validator identity "
          "keypair, or generate a new validator identity key by running "
          "`fdctl keys new identity`", key_path ));
    } else
      FD_LOG_ERR(( "Opening key file (%s) failed (%i-%s)", key_path,  errno, fd_io_strerror( errno ) ));
  }
#define KEY_PARSE_ERR( ... ) \
  FD_LOG_ERR(( "Error while parsing the validator identity key at path " \
               "`%s` specified by [consensus.identity_path] in the "     \
               "configuration TOML file. Solana key files are "         \
               "formatted as a 64-element JSON array. " __VA_ARGS__ ))
#define KEY_SZ 64UL
  /* at least one digit per byte, commas in between each byte, opening and closing brackets */
#define MIN_KEY_FILE_SZ ((ssize_t)(KEY_SZ + KEY_SZ-1UL + 2UL))
#define MAX_KEY_FILE_SZ     1023UL /* Unless it has extraneous whitespace, max is 64*4+1 */


  char * json_key_file = (char *)key+KEY_SZ;
  ssize_t bytes_read = read( key_fd, key+KEY_SZ, MAX_KEY_FILE_SZ );
  if( FD_UNLIKELY( bytes_read==-1  ) ) FD_LOG_ERR(( "reading key file (%s) failed (%i-%s)", key_path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( key_fd ) ) ) FD_LOG_ERR(( "closing key file (%s) failed (%i-%s)", key_path, errno, fd_io_strerror( errno ) ));

  if( bytes_read<MIN_KEY_FILE_SZ    ) FD_LOG_ERR(( "the specified key file (%s) was too short", key_path ));
  json_key_file[ bytes_read ] = '\0';


  /* These pointers reveal information about the key, so store them in
     the protected page temporarily as well. */
  char ** tok = (char **)(key+KEY_SZ+1024UL);
  if( FD_UNLIKELY( fd_cstr_tokenize( tok, KEY_SZ, json_key_file, ',' ) != KEY_SZ ) ) KEY_PARSE_ERR( "", key_path );

  if( FD_UNLIKELY( 1!=sscanf( tok[ 0 ], "[ %hhu", &key[ 0 ] ) ) )
    KEY_PARSE_ERR( "The file should start with an opening `[` followed by a decimal integer.", key_path );
  for( ulong i=1UL; i<63UL; i++ ) {
    if( FD_UNLIKELY( 1!=sscanf( tok[ i ], "%hhu", &key[ i ] ) ) )
      KEY_PARSE_ERR( "Parsing failed near the %luth value.", key_path, i );
  }
  if( FD_UNLIKELY( 1!=sscanf( tok[ 63 ], "%hhu ]", &key[ 63 ] ) ) )
    KEY_PARSE_ERR( "Parsing failed near the 63rd value. Perhaps the file is missing a closing `]`", key_path );


  /* Clear out the buffer just in case it was actually used */
  explicit_bzero( json_key_file, MAX_KEY_FILE_SZ       );
  explicit_bzero( tok,           KEY_SZ*sizeof(char *) );
#undef MAX_KEY_FILE_SZ
#undef MIN_KEY_FILE_SZ
#undef KEY_SZ
#undef KEY_PARSE_ERR

  return key;
}

uchar const *
load_key_into_protected_memory( char const * key_path, int public_key_only ) {
  /* Load the signing key. Since this is key material, we load it into
     its own page that's non-dumpable, readonly, and protected by guard
     pages. */
  uchar * key_page = fd_sandbox_alloc_protected_pages( 1UL, 2UL );

  read_key( key_path, key_page );

  if( public_key_only ) explicit_bzero( key_page, 32UL );

  /* For good measure, make the key page read-only */
  if( FD_UNLIKELY( mprotect( key_page, 4096UL, PROT_READ ) ) )
    FD_LOG_ERR(( "mprotect failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( public_key_only ) return key_page+32UL;
  else                  return key_page;
}
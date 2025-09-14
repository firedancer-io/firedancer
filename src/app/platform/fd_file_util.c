#include "fd_file_util.h"

#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

int
fd_file_util_read_ulong( char const * path,
                         ulong *      value ) {
  int fd = open( path, O_RDONLY );
  if( FD_UNLIKELY( -1==fd ) ) return -1;

  char buf[ 32UL ];
  long bytes_read = read(fd, buf, sizeof(buf)-1UL );
  if( FD_UNLIKELY( -1==bytes_read ) ) {
    close(fd);
    return -1;
  }

  if( FD_UNLIKELY( !bytes_read || (ulong)bytes_read>=sizeof(buf)-1UL ) ) {
    errno = EINVAL;
    close(fd);
    return -1;
  }

  buf[ bytes_read ] = '\0';

  if( FD_UNLIKELY( -1==close( fd ) ) ) return -1;

  char *endptr;
  errno = 0;
  ulong _value = strtoul( buf, &endptr, 10 );
  if( FD_UNLIKELY( errno==ERANGE ) ) return -1;
  if( FD_UNLIKELY( *endptr!='\n' && *endptr!='\0' ) ) {
    errno = EINVAL;
    return -1;
  }

  *value = _value;
  return 0;
}

int
fd_file_util_read_uint( char const * path,
                        uint *       value ) {
  ulong _value;
  int rc = fd_file_util_read_ulong( path, &_value );
  if( FD_UNLIKELY( -1==rc ) ) return -1;
  if( FD_UNLIKELY( _value>UINT_MAX ) ) {
    errno = ERANGE;
    return -1;
  }
  *value = (uint)_value;
  return 0;
}

int
fd_file_util_write_ulong( char const * path,
                          ulong        value ) {
  int fd = open( path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR );
  if( FD_UNLIKELY( -1==fd ) ) return -1;

  char buf[ 32UL ];
  int len = snprintf( buf, sizeof(buf), "%lu\n", value );
  FD_TEST( len>=0 && (ulong)len<sizeof(buf) );

  long written = write( fd, buf, (ulong)len );
  if( FD_UNLIKELY( -1==written ) ) {
    close( fd );
    return -1;
  } else if( FD_UNLIKELY( written!=len ) ) {
    errno = EINTR;
    close( fd );
    return -1;
  }

  if( FD_UNLIKELY( -1==close( fd ) ) ) return -1;
  return 0;
}

int
fd_file_util_mkdir_all( const char * _path,
                        uint         uid,
                        uint         gid ) {
  char path[ PATH_MAX+1UL ] = {0};
  strncpy( path, _path, PATH_MAX );

  char * p = path;
  if( FD_LIKELY( *p == '/' ) ) p++;

  while( FD_LIKELY( *p ) ) {
    if( FD_UNLIKELY( *p == '/' ) ) {
      *p = '\0';

      int error = mkdir( path, 0777 );
      if( FD_UNLIKELY( -1==error && errno!=EEXIST ) ) return -1;
      if( FD_LIKELY( !error ) ) {
        /* Only take ownership of directories that we actually created
           (to avoid, for example, chowning the root directory). */
        if( FD_UNLIKELY( -1==chown( path, uid, gid ) ) ) return -1;
        if( FD_UNLIKELY( -1==chmod( path, S_IRUSR | S_IWUSR | S_IXUSR ) ) ) return -1;
      }

      *p = '/';
    }
    p++;
  }

  return 0;
}

int
fd_file_util_rmtree( char const * path,
                     int          remove_root ) {
  DIR * dir = opendir( path );
  if( FD_UNLIKELY( !dir ) ) {
    if( FD_LIKELY( errno==ENOENT ) ) return 0;
    return -1;
  }

  struct dirent * entry;
  errno = 0;
  while(( entry = readdir( dir ) )) {
    if( FD_LIKELY( !strcmp( entry->d_name, "." ) || !strcmp( entry->d_name, ".." ) ) ) continue;

    char path1[ PATH_MAX ];
    if( FD_UNLIKELY( !fd_cstr_printf_check( path1, PATH_MAX, NULL, "%s/%s", path, entry->d_name ) ) ) {
      errno = ERANGE;
      closedir( dir ); /* Ignore error code, fd is always closed */
      return -1;
    }

    struct stat st;
    if( FD_UNLIKELY( lstat( path1, &st ) ) ) {
      if( FD_LIKELY( errno==ENOENT ) ) continue;
      closedir( dir ); /* Ignore error code, fd is always closed */
      return -1;
    }

    if( FD_UNLIKELY( S_ISDIR( st.st_mode ) ) ) {
      fd_file_util_rmtree( path1, 1 );
    } else {
      if( FD_UNLIKELY( -1==unlink( path1 ) && errno!=ENOENT ) ) {
        closedir( dir ); /* Ignore error code, fd is always closed */
        return -1;
      }
    }
  }

  if( FD_UNLIKELY( errno && errno!=ENOENT ) )   return -1;
  if( FD_UNLIKELY( -1==closedir( dir ) ) )      return -1;
  if( FD_LIKELY( remove_root && -1==rmdir( path ) ) ) return -1;

  return 0;
}

int
fd_file_util_self_exe( char path[ static PATH_MAX ] ) {
  long count = readlink( "/proc/self/exe", path, PATH_MAX );
  if( FD_UNLIKELY( -1==count ) ) return -1;
  if( FD_UNLIKELY( count>=PATH_MAX ) ) {
    errno = ERANGE;
    return -1;
  }

  path[ count ] = '\0';
  return 0;
}

char *
fd_file_util_read_all( char const * path,
                       ulong *      out_sz ) {
  int fd = open( path, O_RDONLY );
  if( FD_UNLIKELY( -1==fd ) ) return MAP_FAILED;

  struct stat st;
  if( FD_UNLIKELY( fstat( fd, &st ) ) ) {
    if( FD_UNLIKELY( -1==close( fd ) ) ) FD_LOG_WARNING(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return MAP_FAILED;
  }

  ulong toml_sz = (ulong)st.st_size;
  if( FD_UNLIKELY( toml_sz==0UL ) ) {
    if( FD_UNLIKELY( -1==close( fd ) ) ) FD_LOG_WARNING(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    errno = EINVAL;
    return MAP_FAILED;
  }

  void * mem = mmap( NULL, toml_sz, PROT_READ, MAP_PRIVATE, fd, 0 );
  if( FD_UNLIKELY( mem==MAP_FAILED ) ) {
    if( FD_UNLIKELY( -1==close( fd ) ) ) FD_LOG_WARNING(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return MAP_FAILED;
  }

  if( FD_UNLIKELY( -1==close( fd ) ) ) FD_LOG_WARNING(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  *out_sz = toml_sz;
  return (char *)mem;
}

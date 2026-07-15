#include "fd_event_os.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define FD_EVENT_OS_RELEASE_FILE_MAX (16384UL)

static int
parse_normalized_value( char *       out,
                        ulong        out_sz,
                        char const * value,
                        ulong        value_sz ) {
  if( FD_UNLIKELY( !value_sz ) ) return 0;

  char quote = value[ 0 ];
  if( FD_UNLIKELY( quote=='\'' || quote=='"' ) ) {
    if( FD_UNLIKELY( value_sz<2UL || value[ value_sz-1UL ]!=quote ) ) return 0;
    value++;
    value_sz -= 2UL;
  }

  if( FD_UNLIKELY( !value_sz || value_sz>=out_sz ) ) return 0;

  for( ulong i=0UL; i<value_sz; i++ ) {
    uchar c = (uchar)value[ i ];
    if( c>='A' && c<='Z' ) c = (uchar)(c+('a'-'A'));
    if( FD_UNLIKELY( !( (c>='a' && c<='z') ||
                        (c>='0' && c<='9') ||
                        c=='.' || c=='_' || c=='-' ) ) ) return 0;
    out[ i ] = (char)c;
  }
  out[ value_sz ] = '\0';
  return 1;
}

void
fd_event_os_release_parse( fd_event_os_release_t * release,
                           char const *            data,
                           ulong                   data_sz ) {
  strcpy( release->id, "linux" );
  release->version_id[ 0 ] = '\0';

  for( ulong off=0UL; off<data_sz; ) {
    ulong line_end = off;
    while( line_end<data_sz && data[ line_end ]!='\n' ) line_end++;
    ulong line_sz = line_end-off;
    if( line_sz && data[ off+line_sz-1UL ]=='\r' ) line_sz--;

    char const * value    = NULL;
    ulong        value_sz = 0UL;
    char *       out      = NULL;
    ulong        out_sz   = 0UL;
    char const * fallback = NULL;

    if( line_sz>=3UL && !memcmp( data+off, "ID=", 3UL ) ) {
      value    = data+off+3UL;
      value_sz = line_sz-3UL;
      out      = release->id;
      out_sz   = sizeof(release->id);
      fallback = "linux";
    } else if( line_sz>=11UL && !memcmp( data+off, "VERSION_ID=", 11UL ) ) {
      value    = data+off+11UL;
      value_sz = line_sz-11UL;
      out      = release->version_id;
      out_sz   = sizeof(release->version_id);
      fallback = "";
    }

    if( out && FD_UNLIKELY( !parse_normalized_value( out, out_sz, value, value_sz ) ) )
      strcpy( out, fallback );

    off = line_end+(line_end<data_sz);
  }
}

void
fd_event_os_release_load( fd_event_os_release_t * release ) {
  fd_event_os_release_parse( release, NULL, 0UL );

  int fd = open( "/etc/os-release", O_RDONLY|O_CLOEXEC );
  if( FD_UNLIKELY( fd<0 && errno==ENOENT ) )
    fd = open( "/usr/lib/os-release", O_RDONLY|O_CLOEXEC );
  if( FD_UNLIKELY( fd<0 ) ) return;

  char  buf[ FD_EVENT_OS_RELEASE_FILE_MAX+1UL ];
  ulong buf_sz = 0UL;
  for(;;) {
    ssize_t read_sz = read( fd, buf+buf_sz, sizeof(buf)-buf_sz );
    if( FD_UNLIKELY( read_sz<0 ) ) {
      if( errno==EINTR ) continue;
      close( fd );
      return;
    }
    if( !read_sz ) break;
    buf_sz += (ulong)read_sz;
    if( FD_UNLIKELY( buf_sz==sizeof(buf) ) ) {
      close( fd );
      return;
    }
  }
  close( fd );

  fd_event_os_release_parse( release, buf, buf_sz );
}

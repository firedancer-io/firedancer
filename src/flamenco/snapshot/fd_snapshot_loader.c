#include "fd_snapshot_loader.h"
#include "fd_snapshot.h"
#include "fd_snapshot_restore.h"
#include "fd_snapshot_http.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <regex.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

struct fd_snapshot_loader {
  ulong magic;

  /* Source: HTTP */

  void *               http_mem;
  fd_snapshot_http_t * http;

  /* Source: File I/O */

  int                  snapshot_fd;
  fd_io_istream_file_t vfile[1];

  /* Source I/O abstraction */

  fd_io_istream_obj_t    vsrc;

  /* Zstandard decompressor */

  fd_zstd_dstream_t *  zstd;
  fd_io_istream_zstd_t vzstd[1];

  /* Tar reader */

  fd_tar_reader_t    tar[1];
  fd_tar_io_reader_t vtar[1];

  /* Downstream restore */

  fd_snapshot_restore_t * restore;

  /* Hash and slot numbers from filename */

  fd_snapshot_name_t name;
};

typedef struct fd_snapshot_loader fd_snapshot_loader_t;

#define FD_SNAPSHOT_LOADER_MAGIC (0xa78a73a69d33e6b1UL)

ulong
fd_snapshot_loader_align( void ) {
  return fd_ulong_max( alignof(fd_snapshot_loader_t), fd_zstd_dstream_align() );
}

ulong
fd_snapshot_loader_footprint( ulong zstd_window_sz ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapshot_loader_t), sizeof(fd_snapshot_loader_t) );
  l = FD_LAYOUT_APPEND( l, fd_zstd_dstream_align(),       fd_zstd_dstream_footprint( zstd_window_sz ) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapshot_http_t),   sizeof(fd_snapshot_http_t) );
  /* FIXME add test ensuring zstd dstream align > alignof loader */
  return FD_LAYOUT_FINI( l, fd_snapshot_loader_align() );
}

fd_snapshot_loader_t *
fd_snapshot_loader_new( void * mem,
                        ulong  zstd_window_sz ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_snapshot_loader_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_snapshot_loader_t * loader   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapshot_loader_t), sizeof(fd_snapshot_loader_t) );
  void *                 zstd_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_zstd_dstream_align(),       fd_zstd_dstream_footprint( zstd_window_sz ) );
  void *                 http_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapshot_http_t),   sizeof(fd_snapshot_http_t) );
  FD_SCRATCH_ALLOC_FINI( l, fd_snapshot_loader_align() );

  fd_memset( loader, 0, sizeof(fd_snapshot_loader_t) );
  loader->http_mem = http_mem;
  loader->zstd     = fd_zstd_dstream_new( zstd_mem, zstd_window_sz );

  FD_COMPILER_MFENCE();
  loader->magic = FD_SNAPSHOT_LOADER_MAGIC;
  FD_COMPILER_MFENCE();

  return loader;
}

void *
fd_snapshot_loader_delete( fd_snapshot_loader_t * loader ) {

  if( FD_UNLIKELY( !loader ) ) return NULL;

  if( FD_UNLIKELY( loader->magic != FD_SNAPSHOT_LOADER_MAGIC ) ) {
    FD_LOG_WARNING(( "invalid magic" ));
    return NULL;
  }

  fd_zstd_dstream_delete   ( loader->zstd  );
  fd_tar_io_reader_delete  ( loader->vtar  );
  fd_io_istream_zstd_delete( loader->vzstd );
  fd_io_istream_file_delete( loader->vfile );
  fd_snapshot_http_delete  ( loader->http  );
  fd_tar_reader_delete     ( loader->tar   );

  if( loader->snapshot_fd>=0 ) {
    if( FD_UNLIKELY( 0!=close( loader->snapshot_fd ) ) )
      FD_LOG_WARNING(( "close(%d) failed (%d-%s)", loader->snapshot_fd, errno, fd_io_strerror( errno ) ));
    loader->snapshot_fd = -1;
  }

  FD_COMPILER_MFENCE();
  loader->magic = 0UL;
  FD_COMPILER_MFENCE();

  return loader;
}

fd_snapshot_loader_t *
fd_snapshot_loader_init( fd_snapshot_loader_t *    d,
                         fd_snapshot_restore_t *   restore,
                         fd_snapshot_src_t const * src,
                         ulong                     base_slot ) {

  d->restore = restore;

  switch( src->type ) {
  case FD_SNAPSHOT_SRC_FILE:
    d->snapshot_fd = open( src->file.path, O_RDONLY );
    if( FD_UNLIKELY( d->snapshot_fd<0 ) ) {
      FD_LOG_WARNING(( "open(%s) failed (%d-%s)", src->file.path, errno, fd_io_strerror( errno ) ));
      return NULL;
    }

    if( FD_UNLIKELY( !fd_snapshot_name_from_cstr( &d->name, src->file.path, base_slot ) ) ) {
      return NULL;
    }

    if( FD_UNLIKELY( !fd_io_istream_file_new( d->vfile, d->snapshot_fd ) ) ) {
      FD_LOG_WARNING(( "Failed to create fd_io_istream_file_t" ));
      return NULL;
    }

    d->vsrc = fd_io_istream_file_virtual( d->vfile );
    break;
  case FD_SNAPSHOT_SRC_HTTP:
    d->http = fd_snapshot_http_new( d->http_mem, src->http.dest, src->http.ip4, src->http.port, &d->name );
    if( FD_UNLIKELY( !d->http ) ) {
      FD_LOG_WARNING(( "Failed to create fd_snapshot_http_t" ));
      return NULL;
    }
    fd_snapshot_http_set_path( d->http, src->http.path, src->http.path_len, base_slot );
    d->http->hops = (ushort)3;  /* TODO don't hardcode */

    d->vsrc = fd_io_istream_snapshot_http_virtual( d->http );
    break;
  default:
    __builtin_unreachable();
  }

  /* Set up the snapshot reader */

  if( FD_UNLIKELY( !fd_tar_reader_new( d->tar, &fd_snapshot_restore_tar_vt, d->restore ) ) ) {
    FD_LOG_WARNING(( "Failed to create fd_tar_reader_t" ));
    return NULL;
  }

  fd_zstd_dstream_reset( d->zstd );

  if( FD_UNLIKELY( !fd_io_istream_zstd_new( d->vzstd, d->zstd, d->vsrc ) ) ) {
    FD_LOG_WARNING(( "Failed to create fd_io_istream_zstd_t" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_tar_io_reader_new( d->vtar, d->tar, fd_io_istream_zstd_virtual( d->vzstd ) ) ) ) {
    FD_LOG_WARNING(( "Failed to create fd_tar_io_reader_t" ));
    return NULL;
  }

  return d;
}

int
fd_snapshot_loader_advance( fd_snapshot_loader_t * dumper ) {

  fd_tar_io_reader_t * vtar = dumper->vtar;

  int untar_err = fd_tar_io_reader_advance( vtar );
  if( untar_err==0 )     { /* ok */ }
  else if( untar_err<0 ) { /* EOF */ return -1; }
  else {
    FD_LOG_WARNING(( "Failed to load snapshot (%d-%s)", untar_err, fd_io_strerror( untar_err ) ));
    return untar_err;
  }

  return 0;
}

/* fd_snapshot_src_parse determines the source from the given cstr. */

fd_snapshot_src_t *
fd_snapshot_src_parse( fd_snapshot_src_t * src,
                       char *              cstr ) {

  fd_memset( src, 0, sizeof(fd_snapshot_src_t) );

  if( 0==strncmp( cstr, "http://", 7 ) ) {
    static char const url_regex[] = "^http://([^:/[:space:]]+)(:[[:digit:]]+)?(/.*)?$";
    regex_t url_re;
    FD_TEST( 0==regcomp( &url_re, url_regex, REG_EXTENDED ) );
    regmatch_t group[4] = {0};
    int url_re_res = regexec( &url_re, cstr, 4, group, 0 );
    regfree( &url_re );
    if( FD_UNLIKELY( url_re_res!=0 ) ) {
      FD_LOG_WARNING(( "Bad URL: %s", cstr ));
      return NULL;
    }

    regmatch_t * m_hostname = &group[1];
    regmatch_t * m_port     = &group[2];
    regmatch_t * m_path     = &group[3];

    src->type = FD_SNAPSHOT_SRC_HTTP;
    src->http.path     = cstr + m_path->rm_so;
    src->http.path_len = (ulong)m_path->rm_eo - (ulong)m_path->rm_so;

    /* Resolve port to IPv4 address */

    if( m_port->rm_so==m_port->rm_eo ) {
      src->http.port = 80;
    } else {
      char port_cstr[7] = {0};
      strncpy( port_cstr, cstr + m_port->rm_so,
               fd_ulong_min( 7, (ulong)m_port->rm_eo - (ulong)m_port->rm_so ) );
      char * port = port_cstr + 1;
      char * end;
      ulong port_ul = strtoul( port, &end, 10 );
      if( FD_UNLIKELY( *end!='\0' ) ) {
        FD_LOG_WARNING(( "Bad port: %s", port ));
        return NULL;
      }
      if( FD_UNLIKELY( port_ul>65535 ) ) {
        FD_LOG_WARNING(( "Port out of range: %lu", port_ul ));
        return NULL;
      }
      src->http.port = (ushort)port_ul;
    }

    /* Resolve host to IPv4 address */

    int sep = cstr[ m_hostname->rm_eo ];
    cstr[ m_hostname->rm_eo ] = '\0';
    char * hostname = cstr + m_hostname->rm_so;

    strncpy( src->http.dest, hostname, sizeof(src->http.dest)-1 );
    src->http.dest[ sizeof(src->http.dest)-1 ] = '\0';

    struct sockaddr_in default_addr = {
      .sin_family = AF_INET,
      .sin_port   = htons( 80 ),
      .sin_addr   = { .s_addr = htonl( INADDR_ANY ) }
    };
    struct addrinfo hints = {
      .ai_family   = AF_INET,
      .ai_socktype = SOCK_STREAM,
      .ai_addr     = fd_type_pun( &default_addr ),
      .ai_addrlen  = sizeof(struct sockaddr_in)
    };
    struct addrinfo * result = NULL;
    int lookup_res = getaddrinfo( hostname, NULL, &hints, &result );
    if( FD_UNLIKELY( lookup_res ) ) {
      FD_LOG_WARNING(( "getaddrinfo(%s) failed (%d-%s)", hostname, lookup_res, gai_strerror( lookup_res ) ));
      return NULL;
    }

    cstr[ m_hostname->rm_eo ] = (char)sep;

    for( struct addrinfo * rp = result; rp; rp = rp->ai_next ) {
      if( rp->ai_family==AF_INET ) {
        struct sockaddr_in * addr = (struct sockaddr_in *)rp->ai_addr;
        src->http.ip4 = addr->sin_addr.s_addr;
        freeaddrinfo( result );
        return src;
      }
    }

    FD_LOG_WARNING(( "Failed to resolve socket address for %s", hostname ));
    freeaddrinfo( result );
    return NULL;
  } else if( 0==strncmp( cstr, "archive:", sizeof("archive:")-1 ) ) {
    src->type = FD_SNAPSHOT_SRC_ARCHIVE;
    src->file.path = cstr + (sizeof("archive:")-1);
    return src;
  } else {
    src->type = FD_SNAPSHOT_SRC_FILE;
    src->file.path = cstr;
    return src;
  }

  __builtin_unreachable();
}

fd_snapshot_name_t const *  /* nullable */
fd_snapshot_loader_get_name( fd_snapshot_loader_t const * loader ) {
  return &loader->name;
}

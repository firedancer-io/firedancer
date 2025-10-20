#include "fd_trace_export.h"

#include <errno.h>

/* From generated/fd_trace_strings.c */
extern char const * fd_trace_strtab[];

static uint const fd_trace_fxt_provider_id = 0xcf380f66u; /* cool x86 instruction (bswap) */

fd_trace_fxt_o_t *
fd_trace_fxt_o_new( fd_trace_fxt_o_t * this,
                    int                fd ) {
  FILE * file = fdopen( fd, "w" );
  if( FD_UNLIKELY( !file ) ) {
    FD_LOG_WARNING(( "fdopen(fd=%d) failed (%i-%s)", fd, errno, fd_io_strerror( errno ) ));
  }
  *this = (fd_trace_fxt_o_t) {
    .file = file
  };
  return this;
}

void *
fd_trace_fxt_o_delete( fd_trace_fxt_o_t * this ) {
  if( this->file ) {
    if( FD_UNLIKELY( 0!=fclose( this->file ) ) ) {
      FD_LOG_WARNING(( "fclose() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    this->file = NULL;
  }
  return this;
}

static int
fxt_write( fd_trace_fxt_o_t * this,
           void const *       data,
           ulong              sz ) {
  if( FD_UNLIKELY( !sz ) ) return 0;
  ulong written = fwrite( data, 1, sz, this->file );
  return written==sz ? 0 : errno;
}

static int
fxt_write_magic( fd_trace_fxt_o_t * this ) {
  ulong hdr = fd_fxt_rec_magic_number_hdr();
  return fxt_write( this, &hdr, sizeof(hdr) );
}

static int
fxt_write_padding( fd_trace_fxt_o_t * this,
                   ulong              cur ) {
  uchar pad[8] = {0};
  ulong sz = fd_ulong_align_up( cur, 8UL ) - cur;
  return fxt_write( this, pad, sz );
}

static int
fxt_write_str( fd_trace_fxt_o_t * this,
               char const *       str,
               ulong              len ) {
  int err = fxt_write( this, str, len );
  if( FD_UNLIKELY( err ) ) return err;
  return fxt_write_padding( this, len );
}

static int
fxt_write_provider_info( fd_trace_fxt_o_t * this ) {
  static char const provider_name[] = "Firedancer";
  ulong             provider_len    = sizeof(provider_name)-1;

  ulong hdr = fd_fxt_rec_provider_info_hdr( fd_trace_fxt_provider_id, provider_len );
  int err = fxt_write( this, &hdr, sizeof(hdr) );
  if( FD_UNLIKELY( err ) ) return err;
  return fxt_write_str( this, provider_name, provider_len );
}

static int
fxt_write_tile( fd_trace_fxt_o_t *     this,
                fd_topo_tile_t const * tile ) {
  ulong koid = tile->id + 1024uL;

  /* Format tile name */
  char name[ 64 ];
  snprintf( name, sizeof(name), "%s:%lu", tile->name, tile->kind_id );

  /* Write fake KOID with name */
  ulong        name_len    = strlen( name );
  ulong        rec_kobj_sz = fd_fxt_rec_kobj_sz( name_len );
  ulong rec_kobj[ 2 ] = {
    fd_fxt_rec_kobj_hdr(
        rec_kobj_sz,
        FD_FXT_KOBJ_TYPE_THREAD,
        0x8000 | name_len,
        0UL ),
    koid
  };
  int err = fxt_write( this, rec_kobj, sizeof(rec_kobj) );
  if( FD_UNLIKELY( err ) ) return err;
  err = fxt_write_str( this, name, name_len );
  if( FD_UNLIKELY( err ) ) return err;

  /* Write thread record */
  ulong tidx = tile->id+1UL; /* Fuchsia thread refs 1-indexed */
  ulong rec[ 3 ] = {
    fd_fxt_rec_thread_hdr( tidx ),
    0UL,  /* placeholder: process KOID */
    koid  /* placeholder: thread KOID */
  };
  return fxt_write( this, rec, sizeof(rec) );
}

static int
fxt_write_tiles( fd_trace_fxt_o_t * this,
                 fd_topo_t const *  topo ) {
  ulong tile_cnt = fd_ulong_min( topo->tile_cnt, 254UL );
  for( ulong i=0UL; i<tile_cnt; i++ ) {
    int err = fxt_write_tile( this, &topo->tiles[ i ] );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return 0;
}

static int
fxt_write_dict_str( fd_trace_fxt_o_t * this,
                    ulong              str_id,
                    char const *       str,
                    ulong              len ) {
  ulong hdr = fd_fxt_rec_string_hdr( len, str_id );
  int err = fxt_write( this, &hdr, sizeof(hdr) );
  if( FD_UNLIKELY( err ) ) return err;
  return fxt_write_str( this, str, len );
}

static int
fxt_write_dict_strs( fd_trace_fxt_o_t * this ) {
  char const ** p = fd_trace_strtab;
  for( ulong i=0UL; *p; i++, p++ ) {
    char const * str = *p;
    ulong        len = strlen( str );
    int err = fxt_write_dict_str( this, i, str, len );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return 0;
}

int
fd_trace_fxt_o_start( fd_trace_fxt_o_t * this,
                      fd_topo_t const *  topo ) {
  int err;
  err = fxt_write_magic( this );
  if( FD_UNLIKELY( err ) ) return err;
  err = fxt_write_provider_info( this );
  if( FD_UNLIKELY( err ) ) return err;
  err = fxt_write_tiles( this, topo );
  if( FD_UNLIKELY( err ) ) return err;
  err = fxt_write_dict_strs( this );
  if( FD_UNLIKELY( err ) ) return err;
  if( FD_UNLIKELY( 0!=fflush( this->file ) ) ) return errno;
  return 0;
}

#include "fd_wksp_private.h"

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* fd_wksp_private_checkpt_v1_write writes size sz buffer buf to the
   output stream checkpt.  Assumes checkpt is valid and not in a
   prepare.  Returns 0 on success and non-zero on failure (will be an
   errno compat error code). */

static inline int
fd_wksp_private_checkpt_v1_write( fd_io_buffered_ostream_t * checkpt,
                                  void const *               buf,
                                  ulong                      sz ) {
  return fd_io_buffered_ostream_write( checkpt, buf, sz );
}

/* fd_wksp_private_checkpt_v1_prepare prepares to write at most max
   bytes to the output stream checkpt.  Assumes checkpt is valid and not
   in a prepare and max is at most checkpt's wbuf_sz.  Returns the
   location in the caller's address space for preparing the max bytes on
   success (*_err will be 0) and NULL on failure (*_err will be an errno
   compat error code). */

static inline void *
fd_wksp_private_checkpt_v1_prepare( fd_io_buffered_ostream_t * checkpt,
                                    ulong                      max,
                                    int *                      _err ) {
  if( FD_UNLIKELY( fd_io_buffered_ostream_peek_sz( checkpt )<max ) ) {
    int err = fd_io_buffered_ostream_flush( checkpt );
    if( FD_UNLIKELY( err ) ) {
      *_err = err;
      return NULL;
    }
    /* At this point, peek_sz==wbuf_sz and wbuf_sz>=max */
  }
  /* At this point, peek_sz>=max */
  *_err = 0;
  return fd_io_buffered_ostream_peek( checkpt );
}

/* fd_wksp_private_checkpt_v1_publish publishes prepared bytes
   [prepare,next) to checkpt.  Assumes checkpt is in a prepare and the
   number of bytes to publish is at most the prepare's max.  checkpt
   will not be in a prepare on return. */

static inline void
fd_wksp_private_checkpt_v1_publish( fd_io_buffered_ostream_t * checkpt,
                                    void *                     next ) {
  fd_io_buffered_ostream_seek( checkpt, (ulong)next - (ulong)fd_io_buffered_ostream_peek( checkpt ) );
}

/* fd_wksp_private_checkpt_v1_cancel cancels a prepare.  Assumes checkpt
   is valid and in a prepare.  checkpt will not be in a prepare on
   return. */

//static inline void fd_wksp_private_checkpt_v1_cancel( fd_io_buffered_ostream_t * checkpt ) { (void)checkpt; }

/* fd_wksp_private_checkpt_v1_ulong checkpoints the value v into a
   checkpt.  p points to the location in a prepare where v should be
   encoded.  Assumes this location has svw_enc_sz(v) available (at least
   1 and at most 9).  Returns the location of the first byte after the
   encoded value (will be prep+svw_enc_sz(val)). */

static inline void * fd_wksp_private_checkpt_v1_ulong( void * prep, ulong val ) { return fd_ulong_svw_enc( (uchar *)prep, val ); }

/* fd_wksp_private_checkpt_v1_buf checkpoints a variable length buffer buf
   of size sz into a checkpt.  p points to the location in a prepare
   region where buf should be encoded.  Assumes this location has
   svw_enc_sz(sz)+sz bytes available (at least 1+sz and at most 9+sz).
   Returns the location of the first byte after the encoded buffer (will
   be prep+svw_enc_sz(sz)+sz).  Zero sz is fine (and NULL buf is fine if
   sz is zero). */

static inline void *
fd_wksp_private_checkpt_v1_buf( void *       prep,
                                void const * buf,
                                ulong        sz ) {
  prep = fd_wksp_private_checkpt_v1_ulong( (uchar *)prep, sz );
  if( FD_LIKELY( sz ) ) fd_memcpy( prep, buf, sz );
  return (uchar *)prep + sz;
}

int
fd_wksp_private_checkpt_v1( fd_tpool_t * tpool,
                            ulong        t0,
                            ulong        t1,
                            fd_wksp_t *  wksp,
                            char const * path,
                            ulong        mode,
                            char const * uinfo ) {
  (void)tpool; (void)t0; (void)t1; /* Note: Thread parallel v1 checkpoint not supported */

  char const * binfo = fd_log_build_info;

//FD_LOG_INFO(( "Checkpt wksp \"%s\" to \"%s\" (mode 0%03lo), uinfo \"%s\"", wksp->name, path, mode, uinfo ));

  mode_t old_mask = umask( (mode_t)0 );
  int fd = open( path, O_CREAT|O_EXCL|O_WRONLY, (mode_t)mode );
  umask( old_mask );
  if( FD_UNLIKELY( fd==-1 ) ) {
    FD_LOG_WARNING(( "open(\"%s\",O_CREAT|O_EXCL|O_WRONLY,0%03lo) failed (%i-%s)", path, mode, errno, fd_io_strerror( errno ) ));
    return FD_WKSP_ERR_FAIL;
  }

# define WBUF_ALIGN     ( 4096UL)
# define WBUF_FOOTPRINT (65536UL)

  uchar                    wbuf[ WBUF_FOOTPRINT ] __attribute__((aligned(WBUF_ALIGN)));
  fd_io_buffered_ostream_t checkpt[ 1 ];
  fd_io_buffered_ostream_init( checkpt, fd, wbuf, WBUF_FOOTPRINT );

  int     err;
  uchar * prep;

  err = fd_wksp_private_lock( wksp ); if( FD_UNLIKELY( err ) ) goto fini; /* logs details */

  /* Do basic wksp checks */

  ulong data_lo = wksp->gaddr_lo;
  ulong data_hi = wksp->gaddr_hi;
  if( FD_UNLIKELY( !((0UL<data_lo) & (data_lo<=data_hi)) ) ) goto corrupt_wksp;

  //FD_LOG_INFO(( "Checkpt header and metadata" ));

  ulong binfo_len = fd_cstr_nlen( binfo, FD_WKSP_CHECKPT_V1_BINFO_MAX-1UL );
  ulong uinfo_len = fd_cstr_nlen( uinfo, FD_WKSP_CHECKPT_V1_UINFO_MAX-1UL );

  prep = fd_wksp_private_checkpt_v1_prepare( checkpt, WBUF_FOOTPRINT, &err ); if( FD_UNLIKELY( !prep ) ) goto io_err;
  prep = fd_wksp_private_checkpt_v1_ulong( prep, wksp->magic                                );
  prep = fd_wksp_private_checkpt_v1_ulong( prep, (ulong)FD_WKSP_CHECKPT_STYLE_V1            );
  prep = fd_wksp_private_checkpt_v1_ulong( prep, (ulong)wksp->seed                          );
  prep = fd_wksp_private_checkpt_v1_ulong( prep, wksp->part_max                             );
  prep = fd_wksp_private_checkpt_v1_ulong( prep, wksp->data_max                             );
  prep = fd_wksp_private_checkpt_v1_ulong( prep, (ulong)fd_log_wallclock()                  );
  prep = fd_wksp_private_checkpt_v1_ulong( prep, fd_log_app_id()                            );
  prep = fd_wksp_private_checkpt_v1_ulong( prep, fd_log_thread_id()                         );
  prep = fd_wksp_private_checkpt_v1_ulong( prep, fd_log_host_id()                           );
  prep = fd_wksp_private_checkpt_v1_ulong( prep, fd_log_cpu_id()                            );
  prep = fd_wksp_private_checkpt_v1_ulong( prep, fd_log_group_id()                          );
  prep = fd_wksp_private_checkpt_v1_ulong( prep, fd_log_tid()                               );
  prep = fd_wksp_private_checkpt_v1_ulong( prep, fd_log_user_id()                           );
  prep = fd_wksp_private_checkpt_v1_buf  ( prep, wksp->name,      strlen( wksp->name      ) );
  prep = fd_wksp_private_checkpt_v1_buf  ( prep, fd_log_app(),    strlen( fd_log_app()    ) );
  prep = fd_wksp_private_checkpt_v1_buf  ( prep, fd_log_thread(), strlen( fd_log_thread() ) );
  prep = fd_wksp_private_checkpt_v1_buf  ( prep, fd_log_host(),   strlen( fd_log_host()   ) );
  prep = fd_wksp_private_checkpt_v1_buf  ( prep, fd_log_cpu(),    strlen( fd_log_cpu()    ) );
  prep = fd_wksp_private_checkpt_v1_buf  ( prep, fd_log_group(),  strlen( fd_log_group()  ) );
  prep = fd_wksp_private_checkpt_v1_buf  ( prep, fd_log_user(),   strlen( fd_log_user()   ) );
  prep = fd_wksp_private_checkpt_v1_buf  ( prep, binfo,           binfo_len                 );
  prep = fd_wksp_private_checkpt_v1_buf  ( prep, uinfo,           uinfo_len                 );
  fd_wksp_private_checkpt_v1_publish( checkpt, prep );

//FD_LOG_INFO(( "Checkpt allocations" ));

  ulong part_max = wksp->part_max;
  fd_wksp_private_pinfo_t * pinfo = fd_wksp_private_pinfo( wksp );

  ulong cycle_tag = wksp->cycle_tag++;

  ulong gaddr_last = data_lo;

  ulong i = fd_wksp_private_pinfo_idx( wksp->part_head_cidx );
  while( !fd_wksp_private_pinfo_idx_is_null( i ) ) {
    if( FD_UNLIKELY( i>=part_max ) || FD_UNLIKELY( pinfo[ i ].cycle_tag==cycle_tag ) ) goto corrupt_wksp;
    pinfo[ i ].cycle_tag = cycle_tag; /* mark i as visited */

    /* Do basic partition checks */

    ulong gaddr_lo = pinfo[ i ].gaddr_lo;
    ulong gaddr_hi = pinfo[ i ].gaddr_hi;
    ulong tag      = pinfo[ i ].tag;

    if( FD_UNLIKELY( !((gaddr_last==gaddr_lo) & (gaddr_lo<gaddr_hi) & (gaddr_hi<=data_hi)) ) ) goto corrupt_wksp;

    gaddr_last = gaddr_hi;

    /* If an allocated partition, checkpt it */

    if( tag ) { /* ~50/50 */

      ulong sz = gaddr_hi - gaddr_lo;
      void * laddr_lo = fd_wksp_laddr_fast( wksp, gaddr_lo );

      /* Checkpt partition header */

      prep = fd_wksp_private_checkpt_v1_prepare( checkpt, 3UL*9UL, &err ); if( FD_UNLIKELY( !prep ) ) goto io_err;
      prep = fd_wksp_private_checkpt_v1_ulong( prep, tag      );
      prep = fd_wksp_private_checkpt_v1_ulong( prep, gaddr_lo );
      prep = fd_wksp_private_checkpt_v1_ulong( prep, sz       );
      fd_wksp_private_checkpt_v1_publish( checkpt, prep );

      /* Checkpt partition data */

      err = fd_wksp_private_checkpt_v1_write( checkpt, laddr_lo, sz ); if( FD_UNLIKELY( err ) ) goto io_err;
    }

    /* Advance to next partition */

    i = fd_wksp_private_pinfo_idx( pinfo[ i ].next_cidx );
  }

//FD_LOG_INFO(( "Checkpt footer" ));

  prep = fd_wksp_private_checkpt_v1_prepare( checkpt, 1UL*9UL, &err ); if( FD_UNLIKELY( !prep ) ) goto io_err;
  prep = fd_wksp_private_checkpt_v1_ulong( prep, 0UL ); /* tags are never 0 above */
  fd_wksp_private_checkpt_v1_publish( checkpt, prep );

  err = fd_io_buffered_ostream_flush( checkpt ); if( FD_UNLIKELY( err ) ) goto io_err;

  fd_wksp_private_unlock( wksp );

//FD_LOG_INFO(( "Checkpt successful" ));

  /* note: err == 0 at this point */

fini: /* note: wksp unlocked at this point */
  fd_io_buffered_ostream_fini( checkpt );
  if( FD_UNLIKELY( err ) && FD_UNLIKELY( unlink( path ) ) )
    FD_LOG_WARNING(( "unlink(\"%s\") failed (%i-%s); attempting to continue", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( fd ) ) )
    FD_LOG_WARNING(( "close(\"%s\") failed (%i-%s); attempting to continue", path, errno, fd_io_strerror( errno ) ));
  return err;

io_err: /* Failed due to I/O error ... clean up and log (note: wksp locked at this point) */
  fd_wksp_private_unlock( wksp );
  FD_LOG_WARNING(( "Checkpt wksp \"%s\" to \"%s\" failed due to I/O error (%i-%s)",
                   wksp->name, path, err, fd_io_strerror( err ) ));
  err = FD_WKSP_ERR_FAIL;
  goto fini;

corrupt_wksp: /* Failed due to wksp corruption ... clean up and log (note: wksp locked at this point) */
  fd_wksp_private_unlock( wksp );
  FD_LOG_WARNING(( "Checkpt wksp \"%s\" to \"%s\" failed due to wksp corruption", wksp->name, path ));
  err = FD_WKSP_ERR_CORRUPT;
  goto fini;
}

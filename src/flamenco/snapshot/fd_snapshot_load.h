#ifndef HEADER_fd_src_flamenco_snapshot_fd_snapshot_load_h
#define HEADER_fd_src_flamenco_snapshot_fd_snapshot_load_h

#include "fd_snapshot_restore.h"
#include "../../ballet/zstd/fd_zstd.h"

/* fd_snapshot_load.h manages a single-threaded streaming pipeline for
   loading snapshots.

   TODO: The indirect call architecture used here is suboptimal.
         In the future, we'd want to use a fd_tango based message
         passing architecture to allow streamlining the pipeline across
         multiple cores.  This scales better, is more secure, faster,
         and more flexible.  However, it requires non-trivial tile
         orchestration, which is still being worked on at the time of
         writing. */

/* Input stream API ***************************************************/

/* Below is an experimental object-oriented API for handling output
   streams of data.  It is dynamically dispatched (C++ style virtual
   function tables) */

struct fd_io_istream_vt {

  /* Virtual version of fd_io_read
     Assumed to be blocking (TODO fix) */

  int
  (* read)( void *  _this,
            void *  _dst,
            ulong   dst_max,
            ulong * _dst_sz );

};

typedef struct fd_io_istream_vt fd_io_istream_vt_t;

struct fd_io_istream_obj {
  void *                     this;
  fd_io_istream_vt_t const * vt;
};

typedef struct fd_io_istream_obj fd_io_istream_obj_t;

FD_PROTOTYPES_BEGIN

static inline int
fd_io_istream_obj_read( fd_io_istream_obj_t * obj,
                        void *                dst,
                        ulong                 dst_max,
                        ulong *               dst_sz ) {
  return obj->vt->read( obj->this, dst, dst_max, dst_sz );
}

FD_PROTOTYPES_END


/* fd_io_istream_zstd_t implements fd_io_istream_vt_t. ****************/

#ifdef FD_HAS_ZSTD

struct fd_io_istream_zstd {
  fd_zstd_dstream_t * dstream;  /* borrowed for lifetime of self */
  fd_io_istream_obj_t src;

# define FD_IO_ISTREAM_ZSTD_BUFSZ (8192UL)  /* should probably be configurable at runtime */
  uchar   in_buf[ FD_IO_ISTREAM_ZSTD_BUFSZ ];
  uchar * in_cur;  /* in_cur in [in_buf,in_end) */
  uchar * in_end;  /* in_end in [in_buf,in_buf+FD_IO_ISTREAM_ZSTD_BUFSZ) */

  int dirty;
};

typedef struct fd_io_istream_zstd fd_io_istream_zstd_t;

FD_PROTOTYPES_BEGIN

fd_io_istream_zstd_t *
fd_io_istream_zstd_new( void *              mem,
                        fd_zstd_dstream_t * dstream,
                        fd_io_istream_obj_t src );

void *
fd_io_istream_zstd_delete( fd_io_istream_zstd_t * this );

int
fd_io_istream_zstd_read( void *  _this,
                         void *  dst,
                         ulong   dst_max,
                         ulong * dst_sz );

extern fd_io_istream_vt_t const fd_io_istream_zstd_vt;

static inline fd_io_istream_obj_t
fd_io_istream_zstd_virtual( fd_io_istream_zstd_t * this ) {
  return (fd_io_istream_obj_t) {
    .this = this,
    .vt   = &fd_io_istream_zstd_vt
  };
}

FD_PROTOTYPES_END

#endif /* FD_HAS_ZSTD */


/* fd_io_istream_file_t implements fd_io_istream_vt_t. ****************/

struct fd_io_istream_file {
  int fd;
};

typedef struct fd_io_istream_file fd_io_istream_file_t;

FD_PROTOTYPES_BEGIN

fd_io_istream_file_t *
fd_io_istream_file_new( void * mem,
                        int    fd );

void *
fd_io_istream_file_delete( fd_io_istream_file_t * this );

int
fd_io_istream_file_read( void *  _this,
                         void *  dst,
                         ulong   dst_max,
                         ulong * dst_sz );

extern fd_io_istream_vt_t const fd_io_istream_file_vt;

static inline fd_io_istream_obj_t
fd_io_istream_file_virtual( fd_io_istream_file_t * this ) {
  return (fd_io_istream_obj_t) {
    .this = this,
    .vt   = &fd_io_istream_file_vt
  };
}

FD_PROTOTYPES_END


/* fd_tar_io_reader_t reads a tar from an fd_io_istream_obj_t source. */

struct fd_tar_io_reader {
  fd_tar_reader_t *   reader;  /* borrowed for lifetime */
  fd_io_istream_obj_t src;
};

typedef struct fd_tar_io_reader fd_tar_io_reader_t;

FD_PROTOTYPES_BEGIN

fd_tar_io_reader_t *
fd_tar_io_reader_new( void *              mem,
                      fd_tar_reader_t *   reader,
                      fd_io_istream_obj_t src );

void *
fd_tar_io_reader_delete( fd_tar_io_reader_t * this );

int
fd_tar_io_reader_advance( fd_tar_io_reader_t * this );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_snapshot_fd_snapshot_load_h */

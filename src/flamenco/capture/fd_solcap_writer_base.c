#include "fd_solcap_logger_backend.h"
#include <stdio.h>
#include "../../tango/fd_tango.h"

struct fd_solcap_writer_vt {
  uchar * (*prepare)( void * backend, ulong sz );
  int     (*publish)( void * backend, uchar const * data, ulong sz );
};
typedef struct fd_solcap_writer_vt fd_solcap_writer_vt_t;

struct fd_solcap_writer {
  fd_solcap_writer_vt_t const vt;
};

typedef struct fd_solcap_writer fd_solcap_writer_t;

struct fd_solcap_logger_backend_file {
  fd_solcap_logger_backend_t base;
  FILE * file;
};
typedef struct fd_solcap_logger_backend_file fd_solcap_logger_backend_file_t;

struct fd_solcap_logger_backend_tile {
  fd_solcap_logger_backend_t base;
  fd_frag_meta_t * mcache;
  uchar * dcache;
};
typedef struct fd_solcap_logger_backend_tile fd_solcap_logger_backend_tile_t;

FD_FN_CONST ulong
fd_solcap_logger_backend_align( void ) {
  
}


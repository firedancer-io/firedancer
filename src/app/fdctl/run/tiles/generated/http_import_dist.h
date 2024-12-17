#ifndef HEADER_fd_src_app_fdctl_run_tiles_generated_http_import_dist_h
#define HEADER_fd_src_app_fdctl_run_tiles_generated_http_import_dist_h

#include "../../../../../util/fd_util.h"

struct fd_http_static_file {
    char const *  name;
    uchar const * data;
    ulong const * data_len;
    uchar const * zstd_data;
    ulong         zstd_data_len;
};

typedef struct fd_http_static_file fd_http_static_file_t;

extern fd_http_static_file_t STATIC_FILES[]; /* null terminated */

#endif

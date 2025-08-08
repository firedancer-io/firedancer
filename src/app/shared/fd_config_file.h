#ifndef HEADER_fd_src_app_shared_fd_config_file_h
#define HEADER_fd_src_app_shared_fd_config_file_h

#include "../../util/fd_util_base.h"

struct fd_config_file {
  char const *  name;

  uchar const * data;
  ulong         data_sz;
};

typedef struct fd_config_file fd_config_file_t;

#endif /* HEADER_fd_src_app_shared_fd_config_file_h */

#ifndef HEADER_fd_src_archive_fd_tar_old_h
#define HEADER_fd_src_archive_fd_tar_old_h

#include "../valloc/fd_valloc.h"

#define TAR_BLOCKSIZE 512

struct fd_tar_old_stream {
    fd_valloc_t valloc;
    ulong cursize_;     // Current position in header/data
    ulong totalsize_;   // 0 if reading header, size of data otherwise
    ulong roundedsize_; // Rounded up to full bloxkes
    char header_[TAR_BLOCKSIZE] __attribute__((aligned(64)));
    void* buf_;
    ulong bufmax_;
};

inline ulong fd_tar_old_stream_footprint( void ) { return sizeof(struct fd_tar_old_stream); }

/*
  Initialize a fd_tar_old_stream data structure
*/
extern void fd_tar_old_stream_init(struct fd_tar_old_stream* self, fd_valloc_t valloc);

typedef void (*fd_tar_old_stream_callback)(void* arg, const char* name, void const * data, ulong datalen);

/*
  Process more tarball data. The callback is invoked on every complete file. Returns non-zero on end of tarball.
*/
extern int fd_tar_old_stream_moreData(struct fd_tar_old_stream* self, void const * data, ulong datalen, fd_tar_old_stream_callback cb, void* arg);

/*
  Cleanup a fd_tar_old_stream data structure
*/
extern void fd_tar_old_stream_delete(struct fd_tar_old_stream* self);

#endif /* HEADER_fd_src_archive_fd_tar_old_h */

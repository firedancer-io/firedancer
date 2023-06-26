#ifndef HEADER_fd_src_archive_fd_tar_h
#define HEADER_fd_src_archive_fd_tar_h

typedef char* (*fd_alloc_fun_t)(void *arg, ulong align, ulong len);
typedef void  (*fd_free_fun_t) (void *arg, void *ptr);

#define TAR_BLOCKSIZE 512

struct fd_tar_stream {
    fd_alloc_fun_t allocf_;
    void* allocf_arg_;
    fd_free_fun_t freef_;
    size_t cursize_;     // Current position in header/data
    size_t totalsize_;   // 0 if reading header, size of data otherwise
    size_t roundedsize_; // Rounded up to full bloxkes
    char header_[TAR_BLOCKSIZE] __attribute__((aligned(64)));
    void* buf_;
    size_t bufmax_;
};

inline size_t fd_tar_stream_footprint( void ) { return sizeof(struct fd_tar_stream); }

/*
  Initialize a fd_tar_stream data structure
*/
extern void fd_tar_stream_init(struct fd_tar_stream* self, fd_alloc_fun_t allocf, void* allocf_arg, fd_free_fun_t freef);

typedef void (*fd_tar_stream_callback)(void* arg, const char* name, const void* data, size_t datalen);

/*
  Process more tarball data. The callback is invoked on every complete file. Returns non-zero on end of tarball.
*/
extern int fd_tar_stream_moreData(struct fd_tar_stream* self, const void* data, size_t datalen, fd_tar_stream_callback cb, void* arg);

/*
  Cleanup a fd_tar_stream data structure
*/
extern void fd_tar_stream_delete(struct fd_tar_stream* self);

#endif /* HEADER_fd_src_archive_fd_tar_h */

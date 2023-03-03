#ifndef HEADER_fd_src_archive_fd_tar_h
#define HEADER_fd_src_archive_fd_tar_h

#define TAR_BLOCKSIZE 512

struct fd_tar_read_stream {
  size_t cursize_;     // Current position in header/data
  size_t totalsize_;   // 0 if reading header, size of data otherwise
  size_t roundedsize_; // Rounded up to full bloxkes
  char   header_[TAR_BLOCKSIZE];
  void*  buf_;
  size_t bufmax_;
};
typedef struct fd_tar_read_stream fd_tar_read_stream_t;

inline size_t fd_tar_read_stream_footprint() { return sizeof(struct fd_tar_read_stream); }
inline ulong  fd_tar_read_stream_align()     { return 8UL; }

typedef void (*fd_tar_read_stream_callback_t)(void* arg, const char* name, const void* data, size_t datalen);

FD_PROTOTYPES_BEGIN

/* fd_tar_read_stream_new formats an unused wksp allocation with the appropriate
   alignment and footprint as a fd_alloc.  Caller is not joined on
   return. */
extern fd_tar_read_stream_t* fd_tar_read_stream_new      (fd_tar_read_stream_t* self);

/* fd_tar_read_stream_join joins the caller to a fd_tar_read_stream. returns the underlying memory */
extern fd_tar_read_stream_t* fd_tar_read_stream_join     (fd_tar_read_stream_t* self);

/* fd_tar_read_stream_leave leaves the existing join.  Returns the underlying data */
extern void                  fd_tar_read_stream_leave    (fd_tar_read_stream_t* self);

/* when data becomes available, you call fd_tar_read_stream_more_data
  to parse the data.  As files becomes available, the
  fd_tar_read_stream_callback_t gets invoked with the resuling parsed
  files */
extern int  fd_tar_read_stream_more_data(fd_tar_read_stream_t* self, const void* data, size_t datalen, fd_tar_read_stream_callback_t cb, void* arg);

/* fd_tar_read_stream_delete deletes the underlying
   fd_tar_read_stream_t data structures */
extern void fd_tar_read_stream_delete  (fd_tar_read_stream_t* self);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_archive_fd_tar_h */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <malloc.h>
#include <string.h>
#include <dirent.h>
#include "../../util/fd_util.h"
#include "fd_tar.h"
#include "gnu_tar_impl.h"

#define fd_tar_read_stream_new_buf_size (1<<16)

fd_tar_read_stream_t* 
fd_tar_read_stream_new(fd_tar_read_stream_t* self) {
  self->totalsize_ = 0;
  self->cursize_ = 0;
  self->buf_ = malloc(fd_tar_read_stream_new_buf_size);
  self->bufmax_ = fd_tar_read_stream_new_buf_size;

  return self;
}

fd_tar_read_stream_t* fd_tar_read_stream_join (fd_tar_read_stream_t* self) {
  return self;
}

void 
fd_tar_read_stream_leave (FD_FN_UNUSED fd_tar_read_stream_t* self) {
}

// This is used TWICE in a c file... is it really worth making a macro out of it?
#define CONSUME_DATA(target, cursize, maxsize)           \
  { size_t newsize = cursize + datalen;                  \
    if (newsize > maxsize) newsize = maxsize;            \
    size_t consumed = (size_t)(newsize - cursize);       \
    fd_memcpy((char*)target + cursize, data, consumed);     \
    cursize = newsize;                                   \
    data = (const char*)data + consumed;                 \
    datalen -= consumed; }

int fd_tar_read_stream_more_data(fd_tar_read_stream_t* self, const void* data, size_t datalen, fd_tar_read_stream_callback_t cb, void* arg) {
  union block* blk = (union block*)self->header_;
  while (datalen) {
    if (self->totalsize_ == 0) {
      // Reading header
      CONSUME_DATA(self->header_, self->cursize_, BLOCKSIZE);
      if (self->cursize_ < BLOCKSIZE) {
        // Incomplete header
        continue;
      }
      if (blk->header.name[0] == '\0') {
        // End of tarball
        return -1;
      }
      if (memcmp(blk->header.magic, TMAGIC " ", sizeof(blk->header.magic)) != 0) {
        FD_LOG_ERR(( "tar file has wrong magic number" ));
      }
      size_t entsize = 0;
      for (const char* p = blk->header.size; p < blk->header.size + sizeof(blk->header.size); ++p) {
        if (*p == '\0')
          break;
        entsize = (entsize << 3) + (size_t)(*p - '0'); // Octal
      }
      if (entsize == 0) {
        // No content. Probably a directory.
        if (blk->header.typeflag == 0 || blk->header.typeflag == '0')
          (*cb)(arg, blk->header.name, NULL, 0);
        self->cursize_ = self->totalsize_ = 0;
        continue;
      }
      // Prepare to read content
      self->cursize_ = 0;
      self->totalsize_ = entsize;
      self->roundedsize_ = (entsize + (BLOCKSIZE-1))&(~((size_t)BLOCKSIZE-1));
      if (self->roundedsize_ <= datalen) {
        // Bypass data copy
        if (blk->header.typeflag == 0 || blk->header.typeflag == '0')
          (*cb)(arg, blk->header.name, data, self->totalsize_);
        data = (const char*)data + self->roundedsize_;
        datalen -= self->roundedsize_;
        self->cursize_ = self->totalsize_ = 0;
        continue;
      }
      if (self->roundedsize_ > self->bufmax_) {
        free(self->buf_);
        self->buf_ = malloc(self->bufmax_ = self->roundedsize_);
      }

    } else {
      // Read content
      CONSUME_DATA(self->buf_, self->cursize_, self->roundedsize_);
      if (self->cursize_ == self->roundedsize_) {
        // Finished entry
        if (blk->header.typeflag == 0 || blk->header.typeflag == '0')
          (*cb)(arg, blk->header.name, self->buf_, self->totalsize_);
        self->cursize_ = self->totalsize_ = 0;
      }
    }
  }

  return 0;
}

void fd_tar_read_stream_delete(fd_tar_read_stream_t* self) {
  if (NULL != self->buf_) {
    free(self->buf_);
    self->buf_ = NULL;
  }
}

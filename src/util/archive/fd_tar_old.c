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
#include "../fd_util.h"
#include "fd_tar_old.h"
typedef unsigned char bool;
#include "gnu_tar_impl.h"

#define fd_tar_old_stream_initBufSize (1<<16)

void
fd_tar_old_stream_init( struct fd_tar_old_stream * self,
                    fd_valloc_t            valloc ) {
  self->valloc = valloc;
  self->totalsize_ = 0;
  self->cursize_ = 0;
  self->buf_ = fd_valloc_malloc( valloc, 64, fd_tar_old_stream_initBufSize );
  self->bufmax_ = fd_tar_old_stream_initBufSize;
}

int fd_tar_old_stream_moreData(struct fd_tar_old_stream* self, const void* data, size_t datalen, fd_tar_old_stream_callback cb, void* arg) {
#define CONSUME_DATA(target, cursize, maxsize)           \
  { size_t newsize = cursize + datalen;                  \
    if (newsize > maxsize) newsize = maxsize;            \
    size_t consumed = (size_t)(newsize - cursize);       \
    fd_memcpy((char*)target + cursize, data, consumed);  \
    cursize = newsize;                                   \
    data = (const char*)data + consumed;                 \
    datalen -= consumed; }

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
        fd_valloc_free( self->valloc, self->buf_ );
        self->buf_ = fd_valloc_malloc( self->valloc, 64, (self->bufmax_ = self->roundedsize_));
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

#undef CONSUME_DATA
}

void
fd_tar_old_stream_delete( struct fd_tar_old_stream * self ) {
  fd_valloc_free( self->valloc, self->buf_ );
}

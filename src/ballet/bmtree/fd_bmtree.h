#ifndef HEADER_fd_src_ballet_bmtree_fd_bmtree_h
#define HEADER_fd_src_ballet_bmtree_fd_bmtree_h

/* Doing this by default is arguable.  This is largely to provide
   backward compat with existing code that expects these to have been
   already declared (by the same token, if we are willing to further
   cleanup names and the like, we would probably rename things like
   fd_bmtree20_commit_t -> fd_bmtree20_t). */

#define FD_BMTREE20_HASH_SZ      (20UL)
#define FD_BMTREE20_COMMIT_ALIGN (8UL)
#define BMTREE_NAME              fd_bmtree20
#define BMTREE_HASH_SZ           FD_BMTREE20_HASH_SZ
#include "fd_bmtree_tmpl.c"

#define FD_BMTREE32_HASH_SZ      (32UL)
#define FD_BMTREE32_COMMIT_ALIGN (8UL)
#define BMTREE_NAME              fd_bmtree32
#define BMTREE_HASH_SZ           FD_BMTREE32_HASH_SZ
#include "fd_bmtree_tmpl.c"

#endif /* HEADER_fd_src_ballet_bmtree_fd_bmtree_h */

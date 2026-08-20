#ifndef HEADER_fd_src_util_fd_boolau_h
#define HEADER_fd_src_util_fd_boolau_h

/* Tri-state boolean: false / true / auto.  Used by config fields that
   accept "auto" in addition to true/false (boolau). */

#define FD_BOOLAU_FALSE (0)
#define FD_BOOLAU_TRUE  (1)
#define FD_BOOLAU_AUTO  (2)

#endif /* HEADER_fd_src_util_fd_boolau_h */

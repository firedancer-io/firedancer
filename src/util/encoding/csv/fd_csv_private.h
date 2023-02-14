#ifndef HEADER_fd_src_util_cstr_fd_csv_private_h
#define HEADER_fd_src_util_cstr_fd_csv_private_h

/* FD_CSV_BUFSZ: Max length of a CSV record cstr */
#define FD_CSV_BUFSZ (1024UL)

/* FD_CSV_READSZ: Max char cnt to copy per fread(3) call. Note that
   fread(3) is called on every CSV record.  Using a larger value will
   result in less libc calls but more redundant copies. */
#define FD_CSV_READSZ (16UL)

/* FD_CSVERR_BUFSZ: Internal size of `fd_csv_strerror()` buffer. */
#define FD_CSVERR_BUFSZ (128UL)

FD_PROTOTYPES_BEGIN

extern FD_TLS char csv_buf[ FD_CSV_BUFSZ ];

/* fd_csv_seterr: Persists the given error and source line number in
   thread-local storage, and returns `err`. */
int
fd_csv_seterr( int err,
               int srcln );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_cstr_fd_csv_private_h */

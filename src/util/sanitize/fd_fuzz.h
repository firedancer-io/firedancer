#ifndef HEADER_fd_src_util_fuzz_fd_fuzz_h
#define HEADER_fd_src_util_fuzz_fd_fuzz_h

#if FD_HAS_COVERAGE
#define FD_FUZZ_MUST_BE_COVERED ((void) 0)
#else
#define FD_FUZZ_MUST_BE_COVERED
#endif

#endif

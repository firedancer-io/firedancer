#ifndef HEADER_fd_src_util_fuzz_fd_fuzz_h
#define HEADER_fd_src_util_fuzz_fd_fuzz_h

#include "../fd_util_base.h"

#if FD_HAS_COVERAGE
#define FD_FUZZ_MUST_BE_COVERED ((void) 0)
#else
#define FD_FUZZ_MUST_BE_COVERED
#endif

FD_PROTOTYPES_BEGIN

ulong
LLVMFuzzerMutate( uchar * data,
                  ulong   data_sz,
                  ulong   max_sz );

FD_PROTOTYPES_END

#endif

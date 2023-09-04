/*
 *  Copyright (C) 2022 - This file was originally part of the x509-parser project
 *
 *  Original Author:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 */
#ifndef HEADER_fd_src_ballet_x509_fd_x509_utils_h
#define HEADER_fd_src_ballet_x509_fd_x509_utils_h

#include "../../util/fd_util_base.h"
#include <unistd.h>
#include <string.h>
#include "fd_x509_config.h"

#if defined(__FRAMAC__)
#define ATTRIBUTE_UNUSED
#else
#define ATTRIBUTE_UNUSED __attribute__((unused))
#endif

#ifdef ERROR_TRACE_ENABLE
#define ERROR_TRACE_APPEND(x) do {			 \
	FD_LOG_WARNING(( "x509: %06d", (x) )); \
	} while (0);
#else
#define ERROR_TRACE_APPEND(x)
#endif

/*
 * Historically, we used -__LINE__ as return value. This worked well when
 * the parser was a single file. Now that we have multiple files in the
 * project, we encode a unique numerical identifier for each file in the
 * return value. For that to work, we need each *implementation* file
 * to define a unique value for X509_FILE_NUM at its beginning.
 */
#define X509_FILE_LINE_NUM_ERR ((X509_FILE_NUM * 100000) + __LINE__)

/*
 * We need to pass some array as macro argument. Protection is needed in that
 * case.
 */
#define P99_PROTECT(...) __VA_ARGS__

static inline int
bufs_differ(const uchar *b1, const uchar *b2, uint n) {
  return 0!=memcmp( b1, b2, n );
}

#endif /* HEADER_fd_src_ballet_x509_fd_x509_utils_h */

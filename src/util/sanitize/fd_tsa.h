#ifndef HEADER_fd_src_util_sanitize_fd_tsa_h
#define HEADER_fd_src_util_sanitize_fd_tsa_h

/* Adopted from
   https://github.com/llvm/llvm-project/blob/5e4f17714259361ca3b355085ff61288aad6f30f/compiler-rt/lib/scudo/standalone/thread_annotations.h
 */

#if FD_USING_CLANG
#  define THREAD_ANNOTATION_ATTRIBUTE_(x) __attribute__((x))
#else
#  define THREAD_ANNOTATION_ATTRIBUTE_(x)
#endif


#define FD_CAPABILITY(x) THREAD_ANNOTATION_ATTRIBUTE_(capability(x))

#define FD_SCOPED_CAPABILITY THREAD_ANNOTATION_ATTRIBUTE_(scoped_lockable)

#define FD_GUARDED_BY(x) THREAD_ANNOTATION_ATTRIBUTE_(guarded_by(x))

#define FD_PT_GUARDED_BY(x) THREAD_ANNOTATION_ATTRIBUTE_(pt_guarded_by(x))

#define FD_ACQUIRED_BEFORE(...)                                                   \
  THREAD_ANNOTATION_ATTRIBUTE_(acquired_before(__VA_ARGS__))

#define FD_ACQUIRED_AFTER(...)                                                    \
  THREAD_ANNOTATION_ATTRIBUTE_(acquired_after(__VA_ARGS__))

#define FD_REQUIRES(...)                                                          \
  THREAD_ANNOTATION_ATTRIBUTE_(requires_capability(__VA_ARGS__))

#define FD_REQUIRES_SHARED(...)                                                   \
  THREAD_ANNOTATION_ATTRIBUTE_(requires_shared_capability(__VA_ARGS__))

#define FD_ACQUIRE(...)                                                           \
  THREAD_ANNOTATION_ATTRIBUTE_(acquire_capability(__VA_ARGS__))

#define FD_ACQUIRE_SHARED(...)                                                    \
  THREAD_ANNOTATION_ATTRIBUTE_(acquire_shared_capability(__VA_ARGS__))

#define FD_RELEASE(...)                                                           \
  THREAD_ANNOTATION_ATTRIBUTE_(release_capability(__VA_ARGS__))

#define FD_RELEASE_SHARED(...)                                                    \
  THREAD_ANNOTATION_ATTRIBUTE_(release_shared_capability(__VA_ARGS__))

#define FD_RELEASE_GENERIC(...)                                                   \
  THREAD_ANNOTATION_ATTRIBUTE_(release_generic_capability(__VA_ARGS__))

#define FD_TRY_ACQUIRE(...)                                                       \
  THREAD_ANNOTATION_ATTRIBUTE_(try_acquire_capability(__VA_ARGS__))

#define FD_TRY_ACQUIRE_SHARED(...)                                                \
  THREAD_ANNOTATION_ATTRIBUTE_(try_acquire_shared_capability(__VA_ARGS__))

#define FD_EXCLUDES(...) THREAD_ANNOTATION_ATTRIBUTE_(locks_excluded(__VA_ARGS__))

#define FD_ASSERT_CAPABILITY(x) THREAD_ANNOTATION_ATTRIBUTE_(assert_capability(x))

#define FD_ASSERT_SHARED_CAPABILITY(x)                                            \
  THREAD_ANNOTATION_ATTRIBUTE_(assert_shared_capability(x))

#define FD_RETURN_CAPABILITY(x) THREAD_ANNOTATION_ATTRIBUTE_(lock_returned(x))

#define FD_NO_THREAD_SAFETY_ANALYSIS                                              \
  THREAD_ANNOTATION_ATTRIBUTE_(no_thread_safety_analysis)

#endif /* HEADER_fd_src_util_sanitize_fd_tsa_h */

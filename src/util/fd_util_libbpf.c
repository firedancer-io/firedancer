/* libbpf version check*/
#include <bpf/libbpf_common.h>
#if LIBBPF_MAJOR_VERSION!=1 || LIBBPF_MINOR_VERSION<1
#error "fd_xdp requires libbpf version ^1.1.0 (or newer)"
#endif

#include <bpf/libbpf.h>
#include <string.h>

/* fd_libbpf_print: libbpf print callback */
static int
fd_libbpf_print( enum libbpf_print_level level,
				 const char *            fmt,
                 va_list                 ap ) {
  static FD_TLS char log_buf[ 8192UL ];
  vsnprintf( log_buf, 8192UL, fmt, ap );

  /* Remove newline */
  char * newline = strrchr( log_buf, '\n' );
  if( FD_LIKELY( newline ) ) newline[0] = '\0';

  switch( level ) {
  case LIBBPF_WARN:  FD_LOG_WARNING(( "%s", log_buf )); break;
  case LIBBPF_INFO:  FD_LOG_INFO   (( "%s", log_buf )); break;
  case LIBBPF_DEBUG: FD_LOG_DEBUG  (( "%s", log_buf )); break;
  }

  return 0;
}

/* fd_libbpf_boot: Configures the libbpf library including logging and
   error handling. Must be called on boot if this thread group calls
   any libbpf function during its lifetime. */
static void
fd_libbpf_boot( void ) {
  libbpf_set_strict_mode( LIBBPF_STRICT_DIRECT_ERRS | LIBBPF_STRICT_CLEAN_PTRS );
  libbpf_set_print( fd_libbpf_print );
}

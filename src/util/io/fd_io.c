#include "fd_io.h"

/* TODO: try to eliminate use of FD_LOG_STYLE in log if possible in
   favor of FD_IO_STYLE here. */

#ifndef FD_IO_STYLE
#if FD_HAS_HOSTED
#define FD_IO_STYLE 0
#else
#error "Define FD_IO_STYLE for this platform"
#endif
#endif

#if FD_IO_STYLE==0 /* POSIX style */

#include <errno.h>
#include <signal.h>
#include <unistd.h>

int
fd_io_read( int     fd,
            void *  _dst,
            ulong   dst_min,
            ulong   dst_max,
            ulong * _dst_sz ) {

  if( FD_UNLIKELY( dst_max==0UL ) ) {
    *_dst_sz = 0UL;
    return 0;
  }

  uchar * dst = (uchar *)_dst;

  ulong dst_sz = 0UL;
  do {

    /* Note: POSIX indicates read with sz larger than SSIZE_MAX (which
       is the same as LONG_MAX here) is IB.  While this is an
       impractically large value nowadays, we don't take chances. */

    long  ssz = read( fd, dst+dst_sz, fd_ulong_min( dst_max-dst_sz, (ulong)LONG_MAX ) );
    ulong rsz = (ulong)ssz;

    if( FD_UNLIKELY( !((0L<ssz) & (rsz<=(dst_max-dst_sz))) ) ) {

      /* At this point, ssz is not in [1,dst_max-dst_sz] */

      if( FD_LIKELY( !ssz ) ) { /* hit EOF */
        *_dst_sz = dst_sz;
        return -1;
      }

      /* At this point, ssz is not in [0,dst_max-dst_sz].  Thus, ssz
         should be -1 and errno should be set.  If errno is set to
         EAGAIN, it appears that fd is configured as non-blocking and,
         because we have not yet read dst_min, we try again.  Because of
         glitches in the POSIX spec, read is also allowed to use
         EWOULDBLOCK for this and EWOULDBLOCK is not required to have
         the same value as EAGAIN (if EAGAIN==EWOULDBLOCK on the target,
         the compiler will almost certainly optimize out the unnecessary
         cmov). */

      int err = errno;
      if( err==EWOULDBLOCK ) err = EAGAIN; /* cmov / no-op */
      if( FD_UNLIKELY( (dst_sz<dst_min) & (err==EAGAIN) ) ) continue;

      /* At this point, ssz is not in [0,dst_max-dst_sz].  ssz should be
         -1 and errno set (and not EWOULDBLOCK).  If not, read does not
         seem to be following POSIX and we flag such as EPROTO (which
         should not be used as an errno case for read above and is at
         least suggestive of the issue) to make a strong guarantee to
         the caller. */

      if( !err ) err = EPROTO; /* cmov */
      *_dst_sz = 0UL;
      return err;
    }

    /* At this point, rsz is in [1,dst_max-dst_sz] */

    dst_sz += rsz;
  } while( dst_sz<dst_min );

  *_dst_sz = dst_sz;
  return 0;
}

int
fd_io_write( int          fd,
             void const * _src,
             ulong        src_min,
             ulong        src_max,
             ulong *      _src_sz ) {

  if( FD_UNLIKELY( src_max==0UL ) ) {
    *_src_sz = 0UL;
    return 0;
  }

  /* Note: this is virtually identical to read.  See read for more
     details. */

  uchar const * src = (uchar const *)_src;

  ulong src_sz = 0UL;
  do {

    long  ssz = write( fd, src+src_sz, fd_ulong_min( src_max-src_sz, (ulong)LONG_MAX ) );
    ulong wsz = (ulong)ssz;

    if( FD_UNLIKELY( !((0L<ssz) & (wsz<=(src_max-src_sz))) ) ) {

      /* Note: The POSIX spec explicitly indicates _reads_ use ssz
         -1 and errno EAGAIN/EWOULDBLOCK for no-data-available-now and
         ssz 0 for end-of-file to explicitly disambiguate these cases.
         It also specifically indicates that _writes_ follow the same
         convention to keep read and write call return handling similar
         even though there is no POSIX concept of an end-of-file for
         writes.  At the same time, there seem to be no cases in the
         standard where a write with a positive size (as it is above)
         should return 0.  So, we skip "EOF" handling here.  If a zero
         ssz unexpectedly occurs, it will be likely be treated as an
         EPROTO below. */

#     if 0
      if( FD_UNLIKELY( !ssz ) ) {
        *_src_sz = src_sz;
        return -1;
      }
#     endif

      int err = errno;
      if( err==EWOULDBLOCK ) err = EAGAIN;
      if( FD_UNLIKELY( (src_sz<src_min) & (err==EAGAIN) ) ) continue;

      if( !err ) err = EPROTO;
      *_src_sz = 0UL;
      return err;
    }

    src_sz += wsz;
  } while( src_sz<src_min );

  *_src_sz = src_sz;
  return 0;
}

int
fd_io_buffered_read( int     fd,
                     void *  _dst,
                     ulong   dst_sz,
                     void *  _rbuf,
                     ulong   rbuf_sz,
                     ulong * _rbuf_lo,
                     ulong * _rbuf_ready ) {

  if( FD_UNLIKELY( !dst_sz ) ) return 0; /* Nothing to do ... optimize for non-trivial read */

  uchar * dst        = (uchar *)_dst;
  uchar * rbuf       = (uchar *)_rbuf;
  ulong   rbuf_lo    = *_rbuf_lo;
  ulong   rbuf_ready = *_rbuf_ready;

  ulong rsz;

  if( FD_LIKELY( rbuf_ready ) ) { /* Optimize for lots of tiny reads */

    /* At this point we have at least one byte already buffered and one
       byte to write.  Copy as many bytes as possible from rbuf into
       dst. */

    ulong cpy_sz = fd_ulong_min( dst_sz, rbuf_ready ); /* At least 1 and either dst_sz or rbuf_ready */
    fd_memcpy( dst, rbuf + rbuf_lo, cpy_sz );
    dst    += cpy_sz;
    dst_sz -= cpy_sz;

    /* If this completed the read, we are done. */

    if( FD_LIKELY( !dst_sz ) ) { /* Optimize for lots of tiny reads */
      *_rbuf_lo    = rbuf_lo    + cpy_sz;
      *_rbuf_ready = rbuf_ready - cpy_sz;
      return 0;
    }

    /* At this point we have more bytes to read, which implies cpy_sz
       was less than dst_sz, which implies cpy_sz was rbuf_ready, which
       implies rbuf is empty because it was drained above. */
  }

  /* At this point, rbuf is empty and we have at least one byte to read. */

  if( FD_UNLIKELY( dst_sz>=rbuf_sz ) ) { /* If we have a large amount of data to read ... (optimize for tiny reads) */

#   if 0 /* This implementation guarantees at most one fd read per call but will not block fd reads */

    /* Read it directly into dst */

    *_rbuf_lo    = 0UL;
    *_rbuf_ready = 0UL;
    return fd_io_read( fd, dst, dst_sz, dst_sz, &rsz );

#   else /* This implementation will block fd reads into multiples of rbuf_sz */

    /* Read the largest rbuf_sz multiple directly into dst. */

    ulong bulk_sz = rbuf_sz*(dst_sz/rbuf_sz); /* TODO: require rbuf_sz to be a power of 2 for faster performance here? */

    int err = fd_io_read( fd, dst, bulk_sz, bulk_sz, &rsz );
    if( FD_UNLIKELY( err ) ) {
      *_rbuf_lo    = 0UL;
      *_rbuf_ready = 0UL;
      return err;
    }

    dst    += bulk_sz;
    dst_sz -= bulk_sz;

    /* If this completed the read, we are done. */

    if( FD_LIKELY( !dst_sz ) ) { /* Optimize for tiny reads */
      *_rbuf_lo    = 0UL;
      *_rbuf_ready = 0UL;
      return 0;
    }

    /* At this point, we have dst_sz in [1,rbuf_sz) bytes to read */

#   endif

  }

  /* At this point, we have dst_sz in [1,rbuf_sz).  Fill up rbuf
     as much as we can and return the results from there. */

  int err = fd_io_read( fd, rbuf, dst_sz, rbuf_sz, &rsz );
  if( FD_UNLIKELY( err ) ) { /* failed (err>0,rsz==0) or EOF (err<0,rsz<dst_sz), either way, we can't handle the request */
    *_rbuf_lo    = 0UL;
    *_rbuf_ready = 0UL;
    return err;
  }

  fd_memcpy( dst, rbuf, dst_sz );
  *_rbuf_lo    = dst_sz;
  *_rbuf_ready = rsz - dst_sz;
  return 0;
}

int
fd_io_buffered_skip( int     fd,
                     ulong   skip_sz,
                     void *  rbuf,
                     ulong   rbuf_sz,
                     ulong * _rbuf_lo,
                     ulong * _rbuf_ready ) {

  /* For large skips, flush rbuf and lseek the fd for the remainder.
     TODO: Consider a variant where fd lseek is aligned to a rbuf_sz
     like the above (such might require this function to do some
     buffering of data if the skip_sz isn't an rbuf_sz multiple). */

  ulong rbuf_ready = *_rbuf_ready;

  if( FD_UNLIKELY( skip_sz>rbuf_ready ) ) { /* Optimize for tiny skips */

    skip_sz -= rbuf_ready; /* At least 1 */
    do {

      /* Note: lseek allows seeking past EOF (even on a RDONLY fd). */

      ulong lseek_sz = fd_ulong_min( skip_sz, (ulong)LONG_MAX ); /* Workaround POSIX sign / unsigned glitches */
      if( FD_UNLIKELY( lseek( fd, (long)lseek_sz, SEEK_CUR )==-1L ) ) {

        int err = errno;

        if( FD_UNLIKELY( err==ESPIPE ) ) {

          /* It appears the stream isn't seekable ... skip over via
             actual reads.  It is kinda gross that we do this every time
             we have to skip on an unseekable stream.  At the same time,
             such usages are likely so low bandwidth and so rare that
             the perf hit from just doing the spurious lseeks is
             probably in the noise and not worth the extra overhead /
             complexity to do more elaborate handling. */

          do {
            ulong read_sz = fd_ulong_min( rbuf_sz, skip_sz );
            ulong rsz;
            err = fd_io_read( fd, rbuf, read_sz, read_sz, &rsz );
            if( FD_UNLIKELY( !((!err) | (err==EAGAIN)) ) ) break;
            skip_sz -= rsz;
          } while( skip_sz );

          *_rbuf_lo    = 0UL;
          *_rbuf_ready = 0UL;
          return err;

        }

        if( !err ) err = EPROTO; /* cmov, paranoia for non-conform to provide strong guarantees to caller */

        *_rbuf_lo    = 0UL;
        *_rbuf_ready = 0UL;
        return err;
      }

      skip_sz -= lseek_sz;
    } while( FD_UNLIKELY( skip_sz ) );

    *_rbuf_lo    = 0UL;
    *_rbuf_ready = 0UL;
    return 0;
  }

  /* Skip is purely over buffered bytes */

  *_rbuf_lo    += skip_sz;
  *_rbuf_ready  = rbuf_ready - skip_sz;
  return 0;
}

int
fd_io_buffered_write( int          fd,
                      void const * _src,
                      ulong        src_sz,
                      void *       _wbuf,
                      ulong        wbuf_sz,
                      ulong *      _wbuf_used ) {

  if( FD_UNLIKELY( !src_sz ) ) return 0; /* Nothing to do ... optimize for non-trivial writes */

  uchar const * src  = (uchar const *)_src;
  uchar *       wbuf = (uchar *)      _wbuf;

  ulong wsz;

  ulong wbuf_used = *_wbuf_used;

  if( FD_LIKELY( wbuf_used ) ) { /* Optimize for lots of tiny writes */

    /* At this point, we have at least one byte already buffered and one
       byte to write.  Copy as many bytes as possible from src into
       wbuf. */

    ulong cpy_sz = fd_ulong_min( wbuf_sz - wbuf_used, src_sz ); /* cpy_sz>=1, cpy_sz is either wbuf_free or src_sz */

    if( FD_LIKELY( cpy_sz ) ) fd_memcpy( wbuf + wbuf_used, src, cpy_sz );

    src       += cpy_sz;
    src_sz    -= cpy_sz;
    wbuf_used += cpy_sz;

    /* If this filled up the buffer, flush it */

    if( FD_UNLIKELY( wbuf_used >= wbuf_sz ) ) { /* Optimize for lots of tiny writes */
      int err = fd_io_write( fd, wbuf, wbuf_sz, wbuf_sz, &wsz );
      if( FD_UNLIKELY( err ) ) {
        *_wbuf_used = 0UL;
        return err;
      }
      wbuf_used = 0UL;
    }

    /* If this completed the write, we are done. */

    if( FD_LIKELY( !src_sz ) ) { /* Optimize for lots of tiny writes */
      *_wbuf_used = wbuf_used;
      return 0;
    }

    /* At this point, we have more bytes to write, which implies cpy_sz
       was less than src_sz, which implies cpy_sz was wbuf_free, which
       implies wbuf is empty because it was flushed above. */

  }

  /* At this point, wbuf is empty and we have at least one byte to
     write. */

  if( FD_UNLIKELY( src_sz>=wbuf_sz ) ) { /* If we have a large amount of data to write ... (optimize for tiny writes) */

#   if 0 /* This implementation guarantees at most one fd write per call but will not block fd writes */

    /* Write it directly from src */

    *_wbuf_used = 0UL;
    return fd_io_write( fd, src, src_sz, src_sz, &wsz );

#   else /* This implementation will block fd writes into multiples of wbuf_sz */

    /* Write the largest wbuf_sz multiple directly into src. */

    ulong bulk_sz = wbuf_sz*(src_sz/wbuf_sz); /* TODO: require wbuf_sz to be a power of 2 for faster performance here? */

    int err = fd_io_write( fd, src, bulk_sz, bulk_sz, &wsz );
    if( FD_UNLIKELY( err ) ) {
      *_wbuf_used = 0UL;
      return err;
    }

    src    += bulk_sz;
    src_sz -= bulk_sz;

    /* If this completed the write, we are done. */

    if( FD_LIKELY( !src_sz ) ) { /* Optimize for tiny writes */
      *_wbuf_used = 0UL;
      return 0;
    }

    /* At this point, we have src_sz in [1,wbuf_sz) bytes to write. */

#   endif

  }

  /* At this point, we have src_sz in [1,wbuf_sz) and an empty
     buffer.  Buffer these bytes. */

  fd_memcpy( wbuf, src, src_sz );
  *_wbuf_used = src_sz;
  return 0;
}

char const *
fd_io_strerror( int err ) {

  /* This covers the standard POSIX-2008 errnos.  We handle the POSIX
     glitches around EWOULDBLOCK / EAGAIN and EOPNOTSUPP / ENOTSUP so
     this will build fine regardless of whether these map to the same
     or different error codes (they typically map to the same nowadays).
     We also throw in negative values for EOF as that is how the above
     handles such. */

  if( err<0 ) return "end-of-file";

  if( err==EWOULDBLOCK ) err = EAGAIN;  /* cmov / no-op */
  if( err==EOPNOTSUPP  ) err = ENOTSUP; /* cmov / no-op */

  switch( err ) {
  case 0              : return "success";
  case E2BIG          : return "E2BIG-argument list too long";
  case EACCES         : return "EACCES-permission denied";
  case EADDRINUSE     : return "EADDRINUSE-address already in use";
  case EADDRNOTAVAIL  : return "EADDRNOTAVAIL-cannot assign requested address";
  case EAFNOSUPPORT   : return "EAFNOSUPPORT-address family not supported by protocol";
  case EAGAIN         : return "EAGAIN-resource temporarily unavailable";
  case EALREADY       : return "EALREADY-operation already in progress";
  case EBADF          : return "EBADF-bad file descriptor";
  case EBADMSG        : return "EBADMSG-bad message";
  case EBUSY          : return "EBUSY-device or resource busy";
  case ECANCELED      : return "ECANCELED-operation canceled";
  case ECHILD         : return "ECHILD-no child processes";
  case ECONNABORTED   : return "ECONNABORTED-software caused connection abort";
  case ECONNREFUSED   : return "ECONNREFUSED-connection refused";
  case ECONNRESET     : return "ECONNRESET-connection reset by peer";
  case EDEADLK        : return "EDEADLK-resource deadlock avoided";
  case EDESTADDRREQ   : return "EDESTADDRREQ-destination address required";
  case EDOM           : return "EDOM-numerical argument out of domain";
  case EEXIST         : return "EEXIST-file exists";
  case EFAULT         : return "EFAULT-bad address";
  case EFBIG          : return "EFBIG-file too large";
  case EHOSTUNREACH   : return "EHOSTUNREACH-no route to host";
  case EIDRM          : return "EIDRM-identifier removed";
  case EILSEQ         : return "EILSEQ-invalid or incomplete multibyte or wide character";
  case EINPROGRESS    : return "EINPROGRESS-operation now in progress";
  case EINTR          : return "EINTR-interrupted system call";
  case EINVAL         : return "EINVAL-invalid argument";
  case EIO            : return "EIO-input/output error";
  case EISCONN        : return "EISCONN-transport endpoint is already connected";
  case EISDIR         : return "EISDIR-is a directory";
  case ELOOP          : return "ELOOP-too many levels of symbolic links";
  case EMFILE         : return "EMFILE-too many open files";
  case EMLINK         : return "EMLINK-too many links";
  case EMSGSIZE       : return "EMSGSIZE-message too long";
  case ENAMETOOLONG   : return "ENAMETOOLONG-file name too long";
  case ENETDOWN       : return "ENETDOWN-network is down";
  case ENETRESET      : return "ENETRESET-network dropped connection on reset";
  case ENETUNREACH    : return "ENETUNREACH-network is unreachable";
  case ENFILE         : return "ENFILE-too many open files in system";
  case ENOBUFS        : return "ENOBUFS-no buffer space available";
  case ENODEV         : return "ENODEV-no such device";
  case ENOENT         : return "ENOENT-no such file or directory";
  case ENOEXEC        : return "ENOEXEC-exec format error";
  case ENOLCK         : return "ENOLCK-no locks available";
  case ENOMEM         : return "ENOMEM-cannot allocate memory";
  case ENOMSG         : return "ENOMSG-no message of desired type";
  case ENOPROTOOPT    : return "ENOPROTOOPT-protocol not available";
  case ENOSPC         : return "ENOSPC-no space left on device";
  case ENOSYS         : return "ENOSYS-function not implemented";
  case ENOTCONN       : return "ENOTCONN-transport endpoint is not connected";
  case ENOTDIR        : return "ENOTDIR-not a directory";
  case ENOTEMPTY      : return "ENOTEMPTY-directory not empty";
  case ENOTRECOVERABLE: return "ENOTRECOVERABLE-state not recoverable";
  case ENOTSOCK       : return "ENOTSOCK-socket operation on non-socket";
  case ENOTSUP        : return "ENOTSUP-operation not supported";
  case ENOTTY         : return "ENOTTY-inappropriate ioctl for device";
  case ENXIO          : return "ENXIO-no such device or address";
  case EOVERFLOW      : return "EOVERFLOW-value too large for defined data type";
  case EOWNERDEAD     : return "EOWNERDEAD-owner died";
  case EPERM          : return "EPERM-operation not permitted";
  case EPIPE          : return "EPIPE-broken pipe";
  case EPROTONOSUPPORT: return "EPROTONOSUPPORT-protocol not supported";
  case EPROTO         : return "EPROTO-protocol error";
  case EPROTOTYPE     : return "EPROTOTYPE-protocol wrong type for socket";
  case ERANGE         : return "ERANGE-numerical result out of range";
  case EROFS          : return "EROFS-read-only file system";
  case ESPIPE         : return "ESPIPE-illegal seek";
  case ESRCH          : return "ESRCH-no such process";
  case ETIMEDOUT      : return "ETIMEDOUT-connection timed out";
  case ETXTBSY        : return "ETXTBSY-text file busy";
  case EXDEV          : return "EXDEV-invalid cross-device link";
  default: break;
  }

  return "unknown";
}

char const *
fd_io_strsignal( int sig ) {
  switch( sig ) {
  case 0              : return "success";
  case SIGHUP         : return "SIGHUP-Hangup";
  case SIGINT         : return "SIGINT-Interrupt";
  case SIGQUIT        : return "SIGQUIT-Quit";
  case SIGILL         : return "SIGILL-Illegal instruction";
  case SIGTRAP        : return "SIGTRAP-Trace/breakpoint trap";
  case SIGABRT        : return "SIGABRT-Aborted";
  case SIGBUS         : return "SIGBUS-Bus error";
  case SIGFPE         : return "SIGFPE-Arithmetic exception";
  case SIGKILL        : return "SIGKILL-Killed";
  case SIGUSR1        : return "SIGUSR1-User defined signal 1";
  case SIGSEGV        : return "SIGSEGV-Segmentation fault";
  case SIGUSR2        : return "SIGUSR2-User defined signal 2";
  case SIGPIPE        : return "SIGPIPE-Broken pipe";
  case SIGALRM        : return "SIGALRM-Alarm clock";
  case SIGTERM        : return "SIGTERM-Terminated";
#if defined(SIGSTKFLT)
  case SIGSTKFLT      : return "SIGSTKFLT-Stack fault";
#elif defined(SIGEMT)
  case SIGEMT         : return "SIGEMT-Emulator trap";
#endif
  case SIGCHLD        : return "SIGCHLD-Child process status";
  case SIGCONT        : return "SIGCONT-Continued";
  case SIGSTOP        : return "SIGSTOP-Stopped (signal)";
  case SIGTSTP        : return "SIGTSTP-Stopped";
  case SIGTTIN        : return "SIGTTIN-Stopped (tty input)";
  case SIGTTOU        : return "SIGTTOU-Stopped (tty output)";
  case SIGURG         : return "SIGURG-Urgent I/O condition";
  case SIGXCPU        : return "SIGXCPU-CPU time limit exceeded";
  case SIGXFSZ        : return "SIGXFSZ-File size limit exceeded";
  case SIGVTALRM      : return "SIGVTALRM-Virtual timer expired";
  case SIGPROF        : return "SIGPROF-Profiling timer expired";
  case SIGWINCH       : return "SIGWINCH-Window changed";
  case SIGPOLL        : return "SIGPOLL-I/O possible";
  case SIGPWR         : return "SIGPWR-Power failure";
  case SIGSYS         : return "SIGSYS-Bad system call";
  default: break;
  }

  return "unknown";
}

#else
#error "Unknown FD_IO_STYLE"
#endif

#include "fd_openssl.h"

#if !FD_HAS_OPENSSL
#error "fd_openssl.c requires FD_HAS_OPENSSL"
#endif

#include "../../util/log/fd_log.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

FD_FN_CONST char const *
fd_openssl_ssl_strerror( int ssl_err ) {
  switch( ssl_err ) {
  case SSL_ERROR_NONE:                 return "SSL_ERROR_NONE";
  case SSL_ERROR_SSL:                  return "SSL_ERROR_SSL";
  case SSL_ERROR_WANT_READ:            return "SSL_ERROR_WANT_READ";
  case SSL_ERROR_WANT_WRITE:           return "SSL_ERROR_WANT_WRITE";
  case SSL_ERROR_WANT_X509_LOOKUP:     return "SSL_ERROR_WANT_X509_LOOKUP";
  case SSL_ERROR_SYSCALL:              return "SSL_ERROR_SYSCALL";
  case SSL_ERROR_ZERO_RETURN:          return "SSL_ERROR_ZERO_RETURN";
  case SSL_ERROR_WANT_CONNECT:         return "SSL_ERROR_WANT_CONNECT";
  case SSL_ERROR_WANT_ACCEPT:          return "SSL_ERROR_WANT_ACCEPT";
  case SSL_ERROR_WANT_ASYNC:           return "SSL_ERROR_WANT_ASYNC";
  case SSL_ERROR_WANT_ASYNC_JOB:       return "SSL_ERROR_WANT_ASYNC_JOB";
  case SSL_ERROR_WANT_CLIENT_HELLO_CB: return "SSL_ERROR_WANT_CLIENT_HELLO_CB";
  case SSL_ERROR_WANT_RETRY_VERIFY:    return "SSL_ERROR_WANT_RETRY_VERIFY";
  default: return "unknown";
  }
}

/* Custom BIO method that uses send(MSG_NOSIGNAL) instead of write()
   to prevent SIGPIPE on broken TCP connections.

   We implement all callbacks ourselves rather than copying them from
   BIO_s_socket() with the deprecated BIO_meth_get_* functions. */

struct fd_bio_sock_data {
  int fd;
  int close_flag;
};

static int
fd_bio_nosigpipe_create( BIO * bio ) {
  struct fd_bio_sock_data * data = OPENSSL_zalloc( sizeof(struct fd_bio_sock_data) );
  if( FD_UNLIKELY( !data ) ) return 0;
  data->fd         = -1;
  data->close_flag = BIO_NOCLOSE;
  BIO_set_data( bio, data );
  return 1;
}

static int
fd_bio_nosigpipe_destroy( BIO * bio ) {
  struct fd_bio_sock_data * data = BIO_get_data( bio );
  if( FD_UNLIKELY( !data ) ) return 0;
  if( data->close_flag==BIO_CLOSE && data->fd>=0 ) {
    close( data->fd );
    data->fd = -1;
  }
  OPENSSL_free( data );
  BIO_set_data( bio, NULL );
  BIO_set_init( bio, 0 );
  return 1;
}

static int
fd_bio_nosigpipe_write( BIO *        bio,
                        char const * buf,
                        int          len ) {
  struct fd_bio_sock_data * data = BIO_get_data( bio );
  if( FD_UNLIKELY( !data || data->fd<0 ) ) return -1;
  if( FD_UNLIKELY( len<=0 ) ) return 0;

  BIO_clear_retry_flags( bio );
  int ret = (int)sendto( data->fd, buf, (size_t)len, MSG_NOSIGNAL, NULL, 0 );
  if( ret<=0 && BIO_sock_should_retry( ret ) ) {
    BIO_set_retry_write( bio );
  }
  return ret;
}

static int
fd_bio_nosigpipe_read( BIO *  bio,
                       char * buf,
                       int    len ) {
  struct fd_bio_sock_data * data = BIO_get_data( bio );
  if( FD_UNLIKELY( !data || data->fd<0 ) ) return -1;

  BIO_clear_retry_flags( bio );
  int ret = (int)read( data->fd, buf, (ulong)len );
  if( ret<=0 && BIO_sock_should_retry( ret ) ) {
    BIO_set_retry_read( bio );
  }
  return ret;
}

static long
fd_bio_nosigpipe_ctrl( BIO *  bio,
                       int    cmd,
                       long   num,
                       void * ptr ) {
  struct fd_bio_sock_data * data = BIO_get_data( bio );
  if( FD_UNLIKELY( !data ) ) return 0;

  switch( cmd ) {
  case BIO_C_SET_FD:
    if( data->close_flag==BIO_CLOSE && data->fd>=0 ) close( data->fd );
    data->fd         = *(int *)ptr;
    data->close_flag = (int)num;
    BIO_set_init( bio, (data->fd>=0) );
    return 1;
  case BIO_C_GET_FD:
    if( data->fd<0 ) return -1;
    if( ptr ) *(int *)ptr = data->fd;
    return (long)data->fd;
  case BIO_CTRL_GET_CLOSE:
    return (long)data->close_flag;
  case BIO_CTRL_SET_CLOSE:
    data->close_flag = (int)num;
    return 1;
  case BIO_CTRL_FLUSH:
    return 1;
  default:
    return 0;
  }
}

static int
fd_bio_nosigpipe_puts( BIO *        bio,
                       char const * str ) {
  return fd_bio_nosigpipe_write( bio, str, (int)strlen( str ) );
}

static BIO_METHOD * fd_bio_nosigpipe_method_ptr;

static void
fd_bio_nosigpipe_method_init( void ) {
  BIO_METHOD * method = BIO_meth_new( BIO_TYPE_SOCKET, "socket(nosigpipe)" );
  if( FD_UNLIKELY( !method ) ) FD_LOG_ERR(( "BIO_meth_new failed" ));

  if( FD_UNLIKELY( !BIO_meth_set_write  ( method, fd_bio_nosigpipe_write   ) ) ) FD_LOG_ERR(( "BIO_meth_set_write failed" ));
  if( FD_UNLIKELY( !BIO_meth_set_read   ( method, fd_bio_nosigpipe_read    ) ) ) FD_LOG_ERR(( "BIO_meth_set_read failed" ));
  if( FD_UNLIKELY( !BIO_meth_set_puts   ( method, fd_bio_nosigpipe_puts    ) ) ) FD_LOG_ERR(( "BIO_meth_set_puts failed" ));
  if( FD_UNLIKELY( !BIO_meth_set_ctrl   ( method, fd_bio_nosigpipe_ctrl    ) ) ) FD_LOG_ERR(( "BIO_meth_set_ctrl failed" ));
  if( FD_UNLIKELY( !BIO_meth_set_create ( method, fd_bio_nosigpipe_create  ) ) ) FD_LOG_ERR(( "BIO_meth_set_create failed" ));
  if( FD_UNLIKELY( !BIO_meth_set_destroy( method, fd_bio_nosigpipe_destroy ) ) ) FD_LOG_ERR(( "BIO_meth_set_destroy failed" ));

  fd_bio_nosigpipe_method_ptr = method;
}

static BIO_METHOD *
fd_bio_nosigpipe_method( void ) {
  FD_ONCE_BEGIN {
    fd_bio_nosigpipe_method_init();
  } FD_ONCE_END;
  return fd_bio_nosigpipe_method_ptr;
}

BIO *
fd_openssl_bio_new_socket( int fd,
                           int close_flag ) {
  BIO_METHOD * method = fd_bio_nosigpipe_method();
  if( FD_UNLIKELY( !method ) ) return NULL;

  BIO * bio = BIO_new( method );
  if( FD_UNLIKELY( !bio ) ) return NULL;
  BIO_set_fd( bio, fd, close_flag );
  return bio;
}

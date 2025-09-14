#include "../fd_config.h"
#include "../fd_action.h"

#include "../../platform/fd_file_util.h"
#include "../../../disco/keyguard/fd_keyload.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/random.h>

typedef enum {
  CMD_NEW_KEY,
  CMD_PUBKEY,
} cmd_type_t;

void
keys_cmd_args( int *    pargc,
               char *** pargv,
               args_t * args ) {
  if( FD_UNLIKELY( *pargc < 2 ) ) goto err;

  if( FD_LIKELY( !strcmp( *pargv[ 0 ], "new" ) ) ) {
    (*pargc)--;
    (*pargv)++;
    if( FD_UNLIKELY( *pargc < 1 ) ) goto err;
    args->keys.cmd = CMD_NEW_KEY;
    fd_memcpy( args->keys.file_path, *pargv[ 0 ], sizeof( args->keys.file_path ) );
  }
  else if( FD_LIKELY( !strcmp( *pargv[ 0 ], "pubkey"  ) ) ) {
    (*pargc)--;
    (*pargv)++;
    if( FD_UNLIKELY( *pargc < 1 ) ) goto err;
    args->keys.cmd = CMD_PUBKEY;
    fd_memcpy( args->keys.file_path, *pargv[ 0 ], sizeof( args->keys.file_path ) );
  }
  else goto err;

  (*pargc)--;
  (*pargv)++;

  return;

err:
    FD_LOG_ERR(( "unrecognized subcommand `%s`\nusage:\n"
                 "  keys new key <path-to-keyfile>\n"
                 "  keys pubkey <path-to-keyfile>\n",
                 *pargv[0] ));
}

void FD_FN_SENSITIVE
generate_keypair( char const *     keyfile,
                  uint             target_uid,
                  uint             target_gid,
                  int              use_grnd_random ) {
  uint flags = use_grnd_random ? GRND_RANDOM : 0U;

  uchar keypair[ 64 ];
  long bytes_produced = 0L;
  while( FD_LIKELY( bytes_produced<32L ) ) {
    long n = getrandom( keypair+bytes_produced, (ulong)(32-bytes_produced), flags );
    if( FD_UNLIKELY( -1==n ) ) FD_LOG_ERR(( "could not create keypair, getrandom() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    bytes_produced += n;
  }

  fd_sha512_t _sha[ 1 ];
  fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );
  if( FD_UNLIKELY( !sha ) ) FD_LOG_ERR(( "could not create keypair, fd_sha512 join failed" ));
  fd_ed25519_public_from_private( keypair+32UL, keypair, sha );

  /* Switch to non-root uid/gid for file creation.  Permissions checks
     are still done as root. */
  gid_t gid = getgid();
  uid_t uid = getuid();
  if( FD_LIKELY( !gid && setegid( target_gid ) ) ) FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( !uid && seteuid( target_uid ) ) ) FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* find last `/` in keyfile and zero it */
  char keyfile_copy[ PATH_MAX ] = {0};
  strncpy( keyfile_copy, keyfile, sizeof( keyfile_copy )-1UL );
  char * last_slash = strrchr( keyfile_copy, '/' );
  if( FD_LIKELY( last_slash ) ) {
    *last_slash = '\0';
    if( FD_UNLIKELY( -1==fd_file_util_mkdir_all( keyfile_copy, target_uid, target_gid, 1 ) ) ) {
      FD_LOG_ERR(( "could not create keypair, `mkdir -p %s` failed (%i-%s)", keyfile_copy, errno, fd_io_strerror( errno ) ));
    }
  }

  int fd = open( keyfile, O_WRONLY|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR );
  if( FD_UNLIKELY( -1==fd ) ) {
    if( FD_LIKELY( errno==EEXIST ) ) FD_LOG_ERR(( "could not create keypair as the keyfile `%s` already exists", keyfile ));
    else                             FD_LOG_ERR(( "could not create keypair, open(%s) failed (%i-%s)", keyfile, errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( write( fd, "[", 1 )!=1L ) ) FD_LOG_ERR(( "could not create keypair, write() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  for( ulong i=0UL; i<64UL; i++ ) {
    if( FD_LIKELY( i ) ) {
      if( FD_UNLIKELY( write( fd, ",", 1 )!=1L ) ) FD_LOG_ERR(( "could not create keypair, write() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }

    char digits[ 4 ];
    ulong digits_len;
    FD_TEST( fd_cstr_printf_check( digits, sizeof( digits ), &digits_len, "%d", keypair[ i ] ) );
    if( FD_UNLIKELY( write( fd, digits, digits_len )!=(long)digits_len ) ) FD_LOG_ERR(( "could not create keypair, write() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( write( fd, "]", 1 )!=1L ) ) FD_LOG_ERR(( "could not create keypair, write() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "could not create keypair, close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  FD_LOG_NOTICE(( "successfully created keypair in `%s`", keyfile ));

  if( FD_UNLIKELY( seteuid( uid ) ) ) FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( setegid( gid ) ) ) FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_memset_explicit( keypair, 0, 64UL );
}

static void
keys_pubkey( const char * file_path ) {
  uchar const * pubkey = fd_keyload_load( file_path, 1 );
  char pubkey_str[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( pubkey, NULL, pubkey_str );
  FD_LOG_STDOUT(( "%s\n", pubkey_str ));
}

void
keys_cmd_fn( args_t *   args,
             config_t * config ) {
  if( FD_LIKELY( args->keys.cmd == CMD_NEW_KEY ) ) {
    generate_keypair( args->keys.file_path, config->uid, config->gid, 1 );
  } else if( FD_LIKELY( args->keys.cmd==CMD_PUBKEY ) ) {
    keys_pubkey( args->keys.file_path );
  } else {
    FD_LOG_ERR(( "unknown key type `%lu`", args->keys.cmd ));
  }
}

action_t fd_action_keys = {
  .name        = "keys",
  .args        = keys_cmd_args,
  .fn          = keys_cmd_fn,
  .perm        = NULL,
  .description = "Generate new keypairs for use with the validator or print a public key",
};

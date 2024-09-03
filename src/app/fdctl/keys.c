#include "fdctl.h"

#include "../../disco/keyguard/fd_keyload.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/random.h>

typedef enum {
  CMD_NEW_IDENTITY,
  CMD_NEW_VOTE_ACCOUNT,
  CMD_PUBKEY,
} cmd_type_t;

void
keys_cmd_args( int *    pargc,
               char *** pargv,
               args_t * args) {
  if( FD_UNLIKELY( *pargc < 2 ) ) goto err;

  if( FD_LIKELY( !strcmp( *pargv[ 0 ], "new" ) ) ) {
    (*pargc)--;
    (*pargv)++;
    if( FD_LIKELY( !strcmp( *pargv[ 0 ], "identity" ) ) )   args->keys.cmd = CMD_NEW_IDENTITY;
    else if( FD_LIKELY( !strcmp( *pargv[ 0 ], "vote"  ) ) ) args->keys.cmd = CMD_NEW_VOTE_ACCOUNT;
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
                 "  keys new identity\n"
                 "  keys new vote\n"
                 "  keys pubkey <path-to-keyfile>\n",
                 *pargv[0] ));
}

void FD_FN_SENSITIVE
generate_keypair( char const *     keyfile,
                  config_t * const config,
                  int              use_grnd_random ) {
  uint flags = use_grnd_random ? GRND_RANDOM : 0U;

  uchar private_key[ 64 ];
  long bytes_produced = 0L;
  while( FD_LIKELY( bytes_produced<32 ) ) {
    long n = getrandom( private_key+bytes_produced, (ulong)(32-bytes_produced), flags );
    if( FD_UNLIKELY( -1==n ) ) FD_LOG_ERR(( "could not create keypair, getrandom() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    bytes_produced += n;
  }

  fd_sha512_t _sha[ 1 ];
  fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );
  if( FD_UNLIKELY( !sha ) ) FD_LOG_ERR(( "could not create keypair, fd_sha512 join failed" ));
  fd_ed25519_public_from_private( private_key+32UL, private_key, sha );

  /* Switch to non-root uid/gid for file creation.  Permissions checks
     are still done as root. */
  gid_t gid = getgid();
  uid_t uid = getuid();
  if( FD_LIKELY( !gid && setegid( config->gid ) ) ) FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( !uid && seteuid( config->uid ) ) ) FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* find last `/` in keyfile and zero it */
  char * last_slash = strrchr( keyfile, '/' );
  if( FD_LIKELY( last_slash ) ) {
    *last_slash = '\0';
    mkdir_all( keyfile, config->uid, config->gid );
    *last_slash = '/';
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
    FD_TEST( fd_cstr_printf_check( digits, sizeof( digits ), &digits_len, "%d", private_key[ i ] ) );
    if( FD_UNLIKELY( write( fd, digits, digits_len )!=(long)digits_len ) ) FD_LOG_ERR(( "could not create keypair, write() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( write( fd, "]", 1 )!=1L ) ) FD_LOG_ERR(( "could not create keypair, write() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "could not create keypair, close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  FD_LOG_NOTICE(( "successfully created keypair in `%s`", keyfile ));

  if( FD_UNLIKELY( seteuid( uid ) ) ) FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( setegid( gid ) ) ) FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_memset_explicit( private_key, 0, 64UL );
}

void
keys_pubkey( const char * file_path ) {
  uchar const * pubkey = fd_keyload_load( file_path, 1 );
  char pubkey_str[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( pubkey, NULL, pubkey_str );
  FD_LOG_STDOUT(( "%s\n", pubkey_str ));
}

void
keys_cmd_fn( args_t *         args,
             config_t * const config ) {
  if( FD_LIKELY( args->keys.cmd == CMD_NEW_IDENTITY ) ) {
    generate_keypair( config->consensus.identity_path, config, 1 );
  } else if( FD_LIKELY( args->keys.cmd == CMD_NEW_VOTE_ACCOUNT ) ) {
    if( FD_UNLIKELY( !strcmp( config->consensus.vote_account_path, "" ) ) )
      FD_LOG_ERR(( "Cannot create a vote account keypair because your validator is not configured "
                   "to vote. Please set [consensus.vote_account_path] in your configuration file." ));

    generate_keypair( config->consensus.vote_account_path, config, 1 );
  } else if( FD_LIKELY( args->keys.cmd == CMD_PUBKEY ) ) {
    keys_pubkey( args->keys.file_path );
  } else {
    FD_LOG_ERR(( "unknown key type `%lu`", args->keys.cmd ));
  }
}

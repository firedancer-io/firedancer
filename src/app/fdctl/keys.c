#include "fdctl.h"

#include "../../disco/keyguard/fd_keyload.h"

#include <stdio.h>
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
    if( FD_LIKELY( !strcmp( *pargv[ 0 ], "identity" ) ) )     args->keys.cmd = CMD_NEW_IDENTITY;
    else if( FD_LIKELY( !strcmp( *pargv[ 0 ], "vote"  ) ) )   args->keys.cmd = CMD_NEW_VOTE_ACCOUNT;
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

void
generate_keypair( char const *     keyfile,
                  config_t * const config,
                  int              use_grnd_random ) {
  uchar keys[ 64 ];

  uint flags = use_grnd_random ? GRND_RANDOM : 0;

  long bytes_produced = 0L;
  while( FD_LIKELY( bytes_produced<32 ) ) {
    long n = getrandom( keys+bytes_produced, (ulong)(32-bytes_produced), flags );
    if( FD_UNLIKELY( -1==n ) ) FD_LOG_ERR(( "could not create keypair, getrandom() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    bytes_produced += n;
  }

  fd_sha512_t _sha[1];
  fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );
  if( FD_UNLIKELY( !sha ) ) FD_LOG_ERR(( "could not create keypair, fd_sha512 join failed" ));
  fd_ed25519_public_from_private( keys+32, keys, sha );

  /* switch to non-root uid/gid for file creation. permissions checks still done as root. */
  gid_t gid = getgid();
  uid_t uid = getuid();
  if( FD_LIKELY( gid == 0 && setegid( config->gid ) ) )
    FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( uid == 0 && seteuid( config->uid ) ) )
    FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  mode_t previous = umask( S_IRWXO | S_IRWXG | S_IXUSR );

  FILE * fp = fopen( keyfile, "wx" );
  if( FD_UNLIKELY( !fp ) ) {
    if( FD_LIKELY( errno == EEXIST ) )
      FD_LOG_ERR(( "could not create keypair as the keyfile `%s` already exists", keyfile ));
    else
      FD_LOG_ERR(( "could not create keypair, fopen(%s) failed (%i-%s)", keyfile, errno, fd_io_strerror( errno ) ));
  }

  if( fwrite( "[", 1, 1, fp ) != 1 )
      FD_LOG_ERR(( "could not create keypair, fwrite() failed" ));

  if( fprintf( fp, "%d", keys[ 0 ] ) < 1 )
      FD_LOG_ERR(( "could not create keypair, fprintf() failed" ));
  for( int i=1; i<64; i++ ) {
    if( fprintf( fp, ",%d", keys[ i ] ) < 1 )
        FD_LOG_ERR(( "could not create keypair, fprintf() failed" ));
  }

  if( fwrite( "]", 1, 1, fp ) != 1 )
      FD_LOG_ERR(( "could not create keypair, fwrite() failed" ));

  if( FD_UNLIKELY( fclose( fp ) ) ) FD_LOG_ERR(( "could not create keypair, fclose failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  FD_LOG_NOTICE(( "successfully created keypair in `%s`", keyfile ));

  umask( previous );

  if( FD_UNLIKELY( seteuid( uid ) ) ) FD_LOG_ERR(( "seteuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( setegid( gid ) ) ) FD_LOG_ERR(( "setegid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

void
keys_pubkey( const char * file_path ) {
  uchar const * pubkey = fd_keyload_load( file_path, 1 );
  char pubkey_str[FD_BASE58_ENCODED_32_SZ];
  fd_base58_encode_32( pubkey, NULL, pubkey_str );
  printf( "%s\n", pubkey_str );
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

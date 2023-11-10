#include "fdctl.h"

#include "../../ballet/ed25519/fd_ed25519.h"

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/random.h>

#define KEYGEN_KEY_IDENTITY     (0UL)
#define KEYGEN_KEY_VOTE_ACCOUNT (1UL)

void
keygen_cmd_args( int *    pargc,
                 char *** pargv,
                 args_t * args) {
  char * usage = "usage: keygen <identity|vote>";
  if( FD_UNLIKELY( *pargc < 1 ) ) FD_LOG_ERR(( "%s", usage ));

  if( FD_LIKELY( !strcmp( *pargv[ 0 ], "identity" ) ) ) args->keygen.key_type = KEYGEN_KEY_IDENTITY;
  else if( FD_LIKELY( !strcmp( *pargv[ 0 ], "vote"  ) ) ) args->keygen.key_type = KEYGEN_KEY_VOTE_ACCOUNT;
  else FD_LOG_ERR(( "unrecognized subcommand `%s`, %s", *pargv[0], usage ));

  (*pargc)--;
  (*pargv)++;

  return;
}

void
generate_keypair( const char * keyfile,
                  config_t * const config ) {
  uchar keys[ 64 ];

  long bytes_produced = 0L;
  while( FD_LIKELY( bytes_produced<32 ) ) {
    long n = getrandom( keys+bytes_produced, (ulong)(32-bytes_produced), GRND_RANDOM );
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
keygen_cmd_fn( args_t *         args,
               config_t * const config ) {
  if( FD_LIKELY( args->keygen.key_type == KEYGEN_KEY_IDENTITY ) ) {
    generate_keypair( config->consensus.identity_path, config );
  } else if( FD_LIKELY( args->keygen.key_type == KEYGEN_KEY_VOTE_ACCOUNT ) ) {
    if( FD_UNLIKELY( !strcmp( config->consensus.vote_account_path, "" ) ) )
      FD_LOG_ERR(( "Cannot create a vote account keypair because your validator is not configured "
                   "to vote. Please set [consensus.vote_account_path] in your configuration file." ));

    generate_keypair( config->consensus.vote_account_path, config );
  } else {
    FD_LOG_ERR(( "unknown key type `%lu`", args->keygen.key_type ));
  }
}

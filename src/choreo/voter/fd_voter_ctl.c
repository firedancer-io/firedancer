#include "../../ballet/base58/fd_base58.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  FILE * file = fopen( "/home/chali/.firedancer/fd1/vote-1.json", "r" );
  FD_TEST( file );

  char line[1000];
  FD_TEST( fgets( line, sizeof( line ), file ) );
  fclose( file );

  uchar  bytes[32];
  char * token = strtok( line, "[, ]" );
  for( ulong i = 0; i < 64; i++ ) {
    if( i >= 32 ) {
      int parsed = atoi( token );
      FD_TEST( parsed > 0 && parsed < UCHAR_MAX );
      bytes[i - 32] = (uchar)parsed;
    }
    token = strtok( NULL, "[, ]" );
  }

  char vote_acc_addr[100];
  FD_LOG_NOTICE( ( "vote account address: %s",
                   fd_base58_encode_32( bytes, NULL, vote_acc_addr ) ) );

  fd_halt();
  return 0;
}

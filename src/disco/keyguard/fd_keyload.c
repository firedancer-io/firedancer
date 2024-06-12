#define _GNU_SOURCE
#include "fd_keyload.h"

#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>

/* Expects that key[i] is writable for i in [0, 1600). */
static inline uchar * FD_FN_SENSITIVE
read_key( char const * key_path,
          uchar      * key       ) {
  int key_fd = open( key_path, O_RDONLY );
  if( FD_UNLIKELY( key_fd==-1 ) ) {
    if( FD_UNLIKELY( errno==ENOENT ) ) {
      FD_LOG_ERR((
          "The [consensus.identity_path] in your configuration expects a "
          "keyfile at `%s` but there is no such file. Either update the "
          "configuration file to point to your validator identity "
          "keypair, or generate a new validator identity key by running "
          "`fdctl keys new identity`", key_path ));
    } else
      FD_LOG_ERR(( "Opening key file (%s) failed (%i-%s)", key_path,  errno, fd_io_strerror( errno ) ));
  }
#define KEY_PARSE_ERR( ... ) \
  FD_LOG_ERR(( "Error while parsing the validator identity key at path " \
               "`%s` specified by [consensus.identity_path] in the "     \
               "configuration TOML file. Solana key files are "         \
               "formatted as a 64-element JSON array. " __VA_ARGS__ ))
#define KEY_SZ 64UL
  /* at least one digit per byte, commas in between each byte, opening and closing brackets */
#define MIN_KEY_FILE_SZ ((ssize_t)(KEY_SZ + KEY_SZ-1UL + 2UL))
#define MAX_KEY_FILE_SZ     1023UL /* Unless it has extraneous whitespace, max is 64*4+1 */


  char * json_key_file = (char *)key+KEY_SZ;
  ssize_t bytes_read = read( key_fd, key+KEY_SZ, MAX_KEY_FILE_SZ );
  if( FD_UNLIKELY( bytes_read==-1  ) ) FD_LOG_ERR(( "reading key file (%s) failed (%i-%s)", key_path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( key_fd ) ) ) FD_LOG_ERR(( "closing key file (%s) failed (%i-%s)", key_path, errno, fd_io_strerror( errno ) ));

  if( bytes_read<MIN_KEY_FILE_SZ    ) FD_LOG_ERR(( "the specified key file (%s) was too short", key_path ));
  json_key_file[ bytes_read ] = '\0';


  /* These pointers reveal information about the key, so store them in
     the protected page temporarily as well. */
  char ** tok = (char **)(key+KEY_SZ+1024UL);
  if( FD_UNLIKELY( fd_cstr_tokenize( tok, KEY_SZ, json_key_file, ',' ) != KEY_SZ ) ) KEY_PARSE_ERR( "", key_path );

  if( FD_UNLIKELY( 1!=sscanf( tok[ 0 ], "[ %hhu", &key[ 0 ] ) ) )
    KEY_PARSE_ERR( "The file should start with an opening `[` followed by a decimal integer.", key_path );
  for( ulong i=1UL; i<63UL; i++ ) {
    if( FD_UNLIKELY( 1!=sscanf( tok[ i ], "%hhu", &key[ i ] ) ) )
      KEY_PARSE_ERR( "Parsing failed near the %luth value.", key_path, i );
  }
  if( FD_UNLIKELY( 1!=sscanf( tok[ 63 ], "%hhu ]", &key[ 63 ] ) ) )
    KEY_PARSE_ERR( "Parsing failed near the 63rd value. Perhaps the file is missing a closing `]`", key_path );


  /* Clear out the buffer just in case it was actually used */
  explicit_bzero( json_key_file, MAX_KEY_FILE_SZ       );
  explicit_bzero( tok,           KEY_SZ*sizeof(char *) );
#undef MAX_KEY_FILE_SZ
#undef MIN_KEY_FILE_SZ
#undef KEY_SZ
#undef KEY_PARSE_ERR

  return key;
}

uchar const * FD_FN_SENSITIVE
fd_keyload_load( char const * key_path,
                 int          public_key_only ) {
  /* Load the signing key. Since this is key material, we load it into
     its own page that's non-dumpable, readonly, and protected by guard
     pages. */
  uchar * key_page = fd_keyload_alloc_protected_pages( 1UL, 2UL );

  read_key( key_path, key_page );

  if( public_key_only ) explicit_bzero( key_page, 32UL );

  /* For good measure, make the key page read-only */
  if( FD_UNLIKELY( mprotect( key_page, 4096UL, PROT_READ ) ) )
    FD_LOG_ERR(( "mprotect failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( public_key_only ) return key_page+32UL;
  else                  return key_page;
}

void FD_FN_SENSITIVE
fd_keyload_unload( uchar const * key,
                   int           public_key_only ) {
  void * key_page = public_key_only ? (uchar *)key-32UL : (uchar *)key;
  ulong sz = (2UL*1UL+2UL)*4096UL;

  if( FD_UNLIKELY( mprotect( key_page, 4096UL, PROT_READ | PROT_WRITE ) ) )
    FD_LOG_ERR(( "mprotect failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  explicit_bzero( key_page, 4096UL );

  if( FD_UNLIKELY( -1==munmap( (uchar*)key_page - 2UL*4096UL, sz ) ) )
    FD_LOG_ERR(( "munmap failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

void * FD_FN_SENSITIVE
fd_keyload_alloc_protected_pages( ulong page_cnt,
                                  ulong guard_page_cnt ) {
#define PAGE_SZ (4096UL)
  void * pages = mmap( NULL, (2UL*guard_page_cnt+page_cnt)*PAGE_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0UL );
  if( FD_UNLIKELY( pages==MAP_FAILED ) ) FD_LOG_ERR(( "mmap failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  uchar * middle_pages = (uchar *)( (ulong)pages + guard_page_cnt*PAGE_SZ );

  /* Make the guard pages untouchable */
  if( FD_UNLIKELY( mprotect( pages, guard_page_cnt*PAGE_SZ, PROT_NONE ) ) )
    FD_LOG_ERR(( "mprotect failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( mprotect( middle_pages+page_cnt*PAGE_SZ, guard_page_cnt*PAGE_SZ, PROT_NONE ) ) )
    FD_LOG_ERR(( "mprotect failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* Lock the key page so that it doesn't page to disk */
  if( FD_UNLIKELY( mlock( middle_pages, page_cnt*PAGE_SZ ) ) )
    FD_LOG_ERR(( "mlock failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* Prevent the key page from showing up in core dumps. It shouldn't be
     possible to fork this process typically, but we also prevent any
     forked child from having this page. */
  if( FD_UNLIKELY( madvise( middle_pages, page_cnt*PAGE_SZ, MADV_WIPEONFORK | MADV_DONTDUMP ) ) )
    FD_LOG_ERR(( "madvise failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  return middle_pages;
#undef PAGE_SZ
}

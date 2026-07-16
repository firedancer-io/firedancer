#include "fd_version.h"
#include "cstr/fd_cstr.h"
#include "fd_version_generated.h"

/* Firedancer version */
__attribute__((weak)) ulong const fd_major_version = FD_VERSION_MAJOR;
__attribute__((weak)) ulong const fd_minor_version = FD_VERSION_MINOR;
__attribute__((weak)) ulong const fd_patch_version = FD_VERSION_PATCH;
char const * fd_version_cstr = ""; /* set on boot */

/* Commit information */
__attribute__((weak)) char const fd_commit_ref_private[] = FIREDANCER_COMMIT_REF_CSTR;
char const * fd_commit_ref_cstr = ""; /* cstr */
uint         fd_commit_ref_u32  = 0;  /* set on boot */

static inline int
unhex( int c ) {
  if( c>='0' && c<='9' ) return c-'0';
  if( c>='a' && c<='f' ) return c-'a'+0xa;
  if( c>='A' && c<='F' ) return c-'A'+0xa;
  return -1;
}

void
fd_version_private_commit_ref_init( void ) {
  char const * str = fd_commit_ref_private;
  fd_commit_ref_cstr = str;
  uint ref = 0;
  char tmp[9] = {0}; fd_cstr_ncpy( tmp, str, 9 );
  for( ulong i=0UL; i<8UL; i+=2 ) {
    int hi = unhex( tmp[ i   ] );
    int lo = unhex( tmp[ i+1 ] );
    if( FD_UNLIKELY( hi<0 || lo<0 ) ) {
      ref = 0;
      break;
    }
    ref <<= 8;
    ref |= (uint)( (hi<<4) | lo );
  }
  fd_commit_ref_u32 = ref;
}

__attribute__((weak)) void
fd_version_private_boot( int *    pargc,
                         char *** pargv ) {
  (void)pargc; (void)pargv;
  static char ver_cstr[ 512 ];
  fd_cstr_printf( ver_cstr, sizeof(ver_cstr), NULL, "%lu.%lu.%lu",
                  fd_major_version, fd_minor_version, fd_patch_version );
  fd_version_cstr = ver_cstr;
  fd_version_private_commit_ref_init();
}

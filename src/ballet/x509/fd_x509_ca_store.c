#include "fd_x509_ca_store.h"
#include "../base64/fd_base64.h"
#include <string.h>
#include <stdio.h>

#define PEM_BEGIN "-----BEGIN CERTIFICATE-----"
#define PEM_END   "-----END CERTIFICATE-----"
#define PEM_BEGIN_SZ (sizeof(PEM_BEGIN)-1)
#define PEM_END_SZ   (sizeof(PEM_END)-1)

/* Scan [p, end) for needle.  Returns pointer to first match, or NULL. */
static char const *
find_line( char const * p, char const * end, char const * needle, ulong needle_sz ) {
  for( ; p + needle_sz <= end; p++ ) {
    if( p[0]==needle[0] && !memcmp( p, needle, needle_sz ) ) return p;
  }
  return NULL;
}

#define PEM_B64_STRIPPED_MAX (8192UL)

static long
pem_b64_decode( uchar * out,      ulong out_max,
                char const * b64, ulong b64_sz ) {
  char stripped[ PEM_B64_STRIPPED_MAX ];
  ulong j = 0;
  for( ulong i=0; i<b64_sz; i++ ) {
    char c = b64[i];
    if( c=='\n' || c=='\r' || c==' ' || c=='\t' ) continue;
    if( FD_UNLIKELY( j >= sizeof(stripped) ) ) return -1;
    stripped[j++] = c;
  }
  while( j & 3 ) {
    if( FD_UNLIKELY( j >= sizeof(stripped) ) ) return -1;
    stripped[j++] = '=';
  }
  if( !j ) return -1;
  if( FD_UNLIKELY( FD_BASE64_DEC_SZ(j) > out_max ) ) return -1;
  return fd_base64_decode( out, stripped, j );
}

long
fd_x509_ca_store_load( fd_x509_ca_store_t * store,
                       char const *         pem_path ) {
  store->cnt = 0;

  FILE * f = fopen( pem_path, "r" );
  if( FD_UNLIKELY( !f ) ) return -1;

  /* Read file.  CA bundles are typically 200-400 KB. */
  static uchar file_buf[ 1UL<<20 ];
  ulong file_sz = fread( file_buf, 1, sizeof(file_buf), f );
  fclose( f );
  if( !file_sz ) return -1;

  char const * p   = (char const *)file_buf;
  char const * end = p + file_sz;
  ulong loaded = 0;

  while( p < end && store->cnt < FD_X509_CA_STORE_MAX ) {
    /* Find next PEM certificate block */
    char const * begin = find_line( p, end, PEM_BEGIN, PEM_BEGIN_SZ );
    if( !begin ) break;
    char const * b64 = begin + PEM_BEGIN_SZ;

    char const * finish = find_line( b64, end, PEM_END, PEM_END_SZ );
    if( !finish ) break;
    p = finish + PEM_END_SZ;

    uchar der[ FD_BASE64_DEC_SZ(PEM_B64_STRIPPED_MAX) ];
    long der_sz = pem_b64_decode( der, sizeof(der), b64, (ulong)(finish - b64) );
    if( FD_UNLIKELY( -1L==der_sz ) ) continue;

    fd_x509_cert_info_t info;
    if( fd_x509_cert_parse( der, (ulong)der_sz, &info ) ) continue;
    if( info.key_type == FD_X509_KEY_UNKNOWN )            continue;
    if( info.subject_len > FD_X509_CA_SUBJECT_MAX )       continue;

    fd_x509_ca_entry_t * e = &store->entries[ store->cnt++ ];
    fd_memcpy( e->subject, info.subject, info.subject_len );
    e->subject_len = info.subject_len;
    fd_memcpy( e->pubkey, info.pubkey, info.pubkey_len );
    e->pubkey_len = info.pubkey_len;
    e->key_type   = info.key_type;
    loaded++;
  }

  return (long)loaded;
}

fd_x509_ca_entry_t const *
fd_x509_ca_store_find( fd_x509_ca_store_t const * store,
                       uchar const *              subject,
                       ulong                      subject_len ) {
  for( ulong i=0; i < store->cnt; i++ ) {
    fd_x509_ca_entry_t const * e = &store->entries[i];
    if( e->subject_len == subject_len &&
        !memcmp( e->subject, subject, subject_len ) )
      return e;
  }
  return NULL;
}

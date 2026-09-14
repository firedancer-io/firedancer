#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

/* fuzz_x509_tls_cert_msg fuzzes TLS Certificate message verification.
   The first input byte selects verifier options.  The trust store is
   seeded from certs in the message itself (leaf issuer name with the
   leaf key, or the last presented cert as root) so that path building,
   anchor checks, and signature verification all run.  With a genuine
   chain in the corpus the root anchor mode verifies successfully. */

#include <stdlib.h>
#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_x509.h"
#include "fd_x509_verify.h"
#include "fd_x509_ca_store.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set( 3 );
  return 0;
}

/* Walk the certificate_list (best effort, verifier does the real
   validation).  Returns number of certs found, fills first and last. */

static ulong
peek_certs( uchar const *  msg,
            ulong          msg_sz,
            uchar const ** first, ulong * first_sz,
            uchar const ** last,  ulong * last_sz ) {
  if( msg_sz < 4UL || msg[0] ) return 0UL;
  uchar const * p   = msg+4UL;
  uchar const * end = msg+msg_sz;
  ulong cnt = 0UL;
  while( (ulong)(end-p) >= 3UL ) {
    ulong cert_len = ( (ulong)p[0]<<16 ) | ( (ulong)p[1]<<8 ) | (ulong)p[2];
    p += 3UL;
    if( !cert_len || cert_len > (ulong)(end-p) ) break;
    if( !cnt ) { *first = p; *first_sz = cert_len; }
    *last = p; *last_sz = cert_len;
    cnt++;
    p += cert_len;
    if( (ulong)(end-p) < 2UL ) break;
    ulong ext_len = ( (ulong)p[0]<<8 ) | (ulong)p[1];
    p += 2UL;
    if( ext_len > (ulong)(end-p) ) break;
    p += ext_len;
  }
  return cnt;
}

static void
add_anchor( fd_x509_ca_store_t *        store,
            uchar const *               subject,
            ulong                       subject_len,
            fd_x509_cert_info_t const * key_src,
            uchar const *               name_constraints,
            ulong                       name_constraints_sz ) {
  if( store->cnt >= FD_X509_CA_STORE_MAX ) return;
  if( subject_len > FD_X509_CA_SUBJECT_MAX ) return;
  if( key_src->pubkey_len > sizeof(store->entries[0].pubkey) ) return;
  fd_x509_ca_entry_t * e = &store->entries[ store->cnt++ ];
  fd_memset( e, 0, sizeof(*e) );
  fd_memcpy( e->subject, subject,         subject_len         ); e->subject_len = subject_len;
  fd_memcpy( e->pubkey,  key_src->pubkey, key_src->pubkey_len ); e->pubkey_len  = key_src->pubkey_len;
  e->key_type = key_src->key_type;
  if( name_constraints_sz ) {
    fd_memcpy( e->name_constraints, name_constraints, name_constraints_sz );
    e->name_constraints_permitted_len = name_constraints_sz;
    e->has_name_constraints           = 1;
  }
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {
  if( data_sz < 1UL ) return -1;
  uchar opts = data[0];
  data++; data_sz--;

  int   with_host   = !!( opts &  1 );
  int   anchor_leaf = !!( opts &  2 );  /* anchor named after leaf issuer, leaf key */
  int   anchor_self = !!( opts &  4 );  /* anchor named after leaf subject, leaf key */
  int   anchor_nc   = !!( opts &  8 );  /* like anchor_leaf, with a permitted dNSName subtree */
  long  now         = ( opts & 16 ) ? 1577836800L : 2000000000L;
  char const * host = ( opts & 32 ) ? "localhost" : "www.example.com";
  int   anchor_root = !!( opts & 64 );  /* anchor = last presented cert (subject and key) */
  ulong host_len    = strlen( host );

  /* GeneralSubtree { dNSName "example.com" } */
  static uchar const permitted[] = {
    0x30, 0x0d, 0x82, 0x0b, 'e','x','a','m','p','l','e','.','c','o','m'
  };

  static fd_x509_ca_store_t store;
  store.cnt = 0UL;

  uchar const * first = NULL; ulong first_sz = 0UL;
  uchar const * last  = NULL; ulong last_sz  = 0UL;
  ulong cert_cnt = peek_certs( data, data_sz, &first, &first_sz, &last, &last_sz );

  fd_x509_cert_info_t leaf;
  if( cert_cnt && 0==fd_x509_cert_parse( first, first_sz, &leaf ) ) {
    if( anchor_leaf ) add_anchor( &store, leaf.issuer,  leaf.issuer_len,  &leaf, NULL, 0UL );
    if( anchor_self ) add_anchor( &store, leaf.subject, leaf.subject_len, &leaf, NULL, 0UL );
    if( anchor_nc   ) add_anchor( &store, leaf.issuer,  leaf.issuer_len,  &leaf, permitted, sizeof(permitted) );
  }
  fd_x509_cert_info_t root;
  if( anchor_root && cert_cnt>1UL && 0==fd_x509_cert_parse( last, last_sz, &root ) ) {
    add_anchor( &store, root.subject, root.subject_len, &root,
                anchor_nc ? permitted : NULL, anchor_nc ? sizeof(permitted) : 0UL );
  }

  int verify_result = fd_x509_verify_tls_cert_msg(
      data, data_sz, &store,
      with_host ? host : NULL, with_host ? host_len : 0UL, now );
  FD_COMPILER_UNPREDICTABLE( verify_result );
  FD_COMPILER_MFENCE();
  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}

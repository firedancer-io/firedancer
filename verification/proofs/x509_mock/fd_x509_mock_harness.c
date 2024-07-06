#include <ballet/x509/fd_x509_mock.h>
#include <assert.h>

void *
memmem( void const * haystack,
        ulong        haystack_sz,
        void const * needle,
        ulong        needle_sz ) {
  if( !haystack_sz ) return NULL;
  if( !needle_sz   ) return NULL;
  if( needle_sz > haystack_sz ) return NULL;
  void * rc;
  __CPROVER_assume(
    rc==NULL ||
    ( (ulong)rc             >= (ulong)haystack &&
      (ulong)rc + needle_sz <= (ulong)haystack+haystack_sz ) );
  return rc;
}

void
harness( void ) {
  ulong sz;
  __CPROVER_assume( sz<=UINT_MAX );
  uchar buf[sz];
  uchar const * pubkey = fd_x509_mock_pubkey( buf, sz );
  assert(
    pubkey==NULL ||
    ( (ulong)pubkey >= (ulong)buf &&
      (ulong)pubkey <  (ulong)(buf+sz) ) );
}

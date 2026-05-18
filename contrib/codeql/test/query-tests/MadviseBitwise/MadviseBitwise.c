typedef unsigned long size_t;

#define MADV_DONTFORK    10
#define MADV_DONTDUMP    16
#define MADV_WIPEONFORK  18

int
madvise( void * addr, size_t length, int advise );

int
not_madvise( void * addr, size_t length, int advise );

int
test_madvise( void * addr, size_t length ) {
  int rc = 0;

  rc += madvise( addr, length, MADV_WIPEONFORK | MADV_DONTDUMP );   // $ Alert
  rc += madvise( addr, length, MADV_WIPEONFORK );                   // NO Alert
  rc += madvise( addr, length, MADV_DONTDUMP );                     // NO Alert

  return rc;
}

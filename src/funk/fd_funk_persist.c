#include "fd_funk.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

/* On-disk header for a chunk of free space */
struct __attribute__((packed)) fd_funk_persist_free_head {
#define FD_FUNK_PERSIST_FREE_TYPE 872042957
    uint type;                       /* FD_FUNK_PERSIST_FREE_TYPE */
    ulong alloc_sz;                  /* Actual allocation size, including header */
};

/* On-disk header for a record */
struct __attribute__((packed)) fd_funk_persist_record_head {
#define FD_FUNK_PERSIST_RECORD_TYPE 497505361
    uint type;                       /* FD_FUNK_PERSIST_RECORD_TYPE */
    ulong alloc_sz;                  /* Actual allocation size, including header */
    fd_funk_xid_key_pair_t pair;     /* Transaction id and record key pair */
    uint val_sz;                     /* Num bytes in record value, in [0,val_max] */
    /* Record data follows */
};

/* On-disk header for a record erasure */
struct __attribute__((packed)) fd_funk_persist_erase_head {
#define FD_FUNK_PERSIST_ERASE_TYPE 127491733
    uint type;                       /* FD_FUNK_PERSIST_ERASE_TYPE */
    ulong alloc_sz;                  /* Actual allocation size, including header */
    fd_funk_xid_key_pair_t pair;     /* Transaction id and record key pair */
};

/* On-disk header for a transaction write-ahead log */
struct __attribute__((packed)) fd_funk_persist_walog_head {
#define FD_FUNK_PERSIST_WALOG_TYPE 161299373
    uint type;                       /* FD_FUNK_PERSIST_WALOG_TYPE */
    ulong alloc_sz;                  /* Actual allocation size, including header */
    /* Nested instances of fd_funk_persist_record_head and
       fd_funk_persist_erase_head follow. */
};

/* Allocate a chunk of disk space. Returns the position on the disk
   and the actual size of the allocation. */
ulong
fd_funk_persist_alloc( fd_funk_t * funk, ulong needed, ulong * actual );

/* Remember that a chunk of disk space is free. Takes the position and
   size of the allocation. */
void
fd_funk_persist_remember_free( fd_funk_t * funk, ulong pos, ulong sz );

/* Free a chunk of disk space. Takes the position and size of the
   allocation. */
void
fd_funk_persist_free( fd_funk_t * funk, ulong pos, ulong sz );

int
fd_funk_persist_open( fd_funk_t * funk, const char * filename ) {
  funk->persistfd = open(filename, O_CREAT, 0600);
  if (funk->persistfd == -1) {
    FD_LOG_WARNING(( "failed to open %s: %s", filename, strerror(errno) ));
    return FD_FUNK_ERR_SYS;
  }
  return FD_FUNK_SUCCESS;
}

void
fd_funk_persist_close( fd_funk_t * funk ) {
  close(funk->persistfd);
  funk->persistfd = -1;
}

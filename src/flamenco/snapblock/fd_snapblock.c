#include "fd_snapblock.h"


struct fd_snapblock {
  ulong           magic;
  ulong           slot;
  fd_banks_t *    banks;
  fd_store_t *    store;
  fd_funk_t *     funk;
  fd_funk_txn_t * funk_txn;
  char const *    path;
};
typedef struct fd_snapblock fd_snapblock_t;

ulong
fd_snapblock_align( void ) {
  return alignof(fd_snapblock_t);
}

ulong
fd_snapblock_footprint( void ) {
  return sizeof(fd_snapblock_t);
}

void *
fd_snapblock_writer_new( void *       mem,
                         ulong        slot,
                         fd_banks_t * banks,
                         fd_store_t * store,
                         fd_funk_t *  funk,
                         char const * path ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !banks ) ) {
    FD_LOG_WARNING(( "NULL banks" ));
    return NULL;
  }

  if( FD_UNLIKELY( !store ) ) {
    FD_LOG_WARNING(( "NULL store" ));
    return NULL;
  }

  if( FD_UNLIKELY( !funk ) ) {
    FD_LOG_WARNING(( "NULL funk" ));
    return NULL;
  }

  if( FD_UNLIKELY( !path ) ) {
    FD_LOG_WARNING(( "NULL path" ));
    return NULL;
  }

  fd_snapblock_t * snapblock = (fd_snapblock_t *)mem;

  snapblock->slot  = slot;
  snapblock->banks = banks;
  snapblock->store = store;
  snapblock->funk  = funk;
  snapblock->path  = path;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( snapblock->magic ) = FD_SNAPBLOCK_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_snapblock_t *
fd_snapblock_writer_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  fd_snapblock_t * snapblock = (fd_snapblock_t *)mem;

  if( FD_UNLIKELY( snapblock->magic!=FD_SNAPBLOCK_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return snapblock;
}

fd_snapblock_t *
fd_snapblock_writer_create( fd_snapblock_t * snapblock );

void *
fd_snapblock_writer_fini( fd_snapblock_t * snapblock );

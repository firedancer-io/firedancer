#ifndef HEADER_fd_src_flamenco_snapblock_fd_snapblock_h
#define HEADER_fd_src_flamenco_snapblock_fd_snapblock_h

#include "../fd_flamenco_base.h"
#include "../../disco/store/fd_store.h"
#include "../../funk/fd_funk.h"

/* fd_snap_block_t is a way to dump and replay a single slot. It can be
   used to dump a slot in a replayable format.

   1. fd_banks_t
   2. all shreds for a given slot
   3. all accounts referenced in a slot. */

struct fd_snapblock;
typedef struct fd_snapblock fd_snapblock_t;

FD_PROTOTYPES_BEGIN

#define FD_SNAPBLOCK_MAGIC (0xF17EDA2C53A7B10C) /* FIREDANC SNAPBLOC */

FD_FN_CONST ulong
fd_snapblock_align( void );

FD_FN_CONST ulong
fd_snapblock_footprint( void );

void *
fd_snapblock_writer_new( void *       mem,
                         ulong        slot,
                         fd_banks_t * banks,
                         fd_store_t * store,
                         fd_funk_t *  funk,
                         char const * path );

fd_snapblock_t *
fd_snapblock_writer_join( void * mem );

fd_snapblock_t *
fd_snapblock_writer_create( fd_snapblock_t * snapblock );

void *
fd_snapblock_writer_fini( fd_snapblock_t * snapblock );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_archive_fd_tar_h */

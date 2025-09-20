#ifndef HEADER_fd_src_discof_restore_utils_fd_slot_delta_parser_h
#define HEADER_fd_src_discof_restore_utils_fd_slot_delta_parser_h

#include "fd_txncache_msg.h"

struct fd_slot_delta_parser_private;
typedef struct fd_slot_delta_parser_private fd_slot_delta_parser_t;

#define FD_SLOT_DELTA_MAX_ENTRIES (300UL)

#define FD_SLOT_DELTA_PARSER_ERROR_SLOT_GREATER_THAN_MAX_ROOT (-1)
#define FD_SLOT_DELTA_PARSER_ERROR_SLOT_IS_NOT_ROOT           (-2)
#define FD_SLOT_DELTA_PARSER_ERROR_SLOT_HASH_MULTIPLE_ENTRIES (-3)
#define FD_SLOT_DELTA_PARSER_ERROR_TOO_MANY_ENTRIES           (-4)

struct fd_slot_entry {
  ulong slot;

  struct {
    ulong next;
  } pool;

  struct {
    ulong next;
    ulong prev;
  } map;
};
typedef struct fd_slot_entry fd_slot_entry_t;

#define POOL_NAME  slot_pool
#define POOL_T     fd_slot_entry_t
#define POOL_IDX_T ulong
#define POOL_NEXT  pool.next
#include "../../../util/tmpl/fd_pool.c"

#define MAP_NAME                           slot_set
#define MAP_KEY                            slot
#define MAP_KEY_T                          ulong
#define MAP_ELE_T                          fd_slot_entry_t
#define MAP_PREV                           map.prev
#define MAP_NEXT                           map.next
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../../util/tmpl/fd_map_chain.c"

typedef void
(* fd_slot_delta_parser_process_entry_fn_t)( void *                        _ctx,
                                             fd_sstxncache_entry_t const * entry );

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_slot_delta_parser_align( void );

FD_FN_CONST ulong
fd_slot_delta_parser_footprint( void );

void *
fd_slot_delta_parser_new( void * shmem );

fd_slot_delta_parser_t *
fd_slot_delta_parser_join( void * shmem );

void *
fd_slot_delta_parser_leave( fd_slot_delta_parser_t * parser );

void *
fd_slot_delta_parser_delete( void * shmem );

void
fd_slot_delta_parser_init( fd_slot_delta_parser_t *                parser,
                           fd_slot_delta_parser_process_entry_fn_t entry_cb,
                           void *                                  cb_arg,
                           ulong                                   bank_slot );


int
fd_slot_delta_parser_consume( fd_slot_delta_parser_t * parser,
                              uchar const *            buf,
                              ulong                    bufsz );

slot_set_t const *
fd_slot_delta_parser_get_slot_set( fd_slot_delta_parser_t * parser );

fd_slot_entry_t const *
fd_slot_delta_parser_get_slot_pool( fd_slot_delta_parser_t * parser );
FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_slot_delta_parser_h */

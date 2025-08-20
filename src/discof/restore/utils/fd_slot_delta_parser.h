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

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_slot_delta_parser_align( void );

FD_FN_CONST ulong
fd_slot_delta_parser_footprint( void );

void *
fd_slot_delta_parser_new( void * shmem );

fd_slot_delta_parser_t *
fd_slot_delta_parser_join( void * shmem );

void
fd_slot_delta_parser_init( fd_slot_delta_parser_t *       parser,
                           fd_snapshot_txncache_entry_t * entry,
                           ulong                          bank_slot );


int
fd_slot_delta_parser_consume( fd_slot_delta_parser_t * parser,
                              uchar const *            buf,
                              ulong                    bufsz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_slot_delta_parser_h */

#ifndef HEADER_fd_src_discof_restore_utils_fd_ssparse_h
#define HEADER_fd_src_discof_restore_utils_fd_ssparse_h

#include "../../../util/fd_util_base.h"

#define FD_SSPARSE_ALIGN (8UL)

#define FD_SSPARSE_MAGIC (0xF17EDA2CE58AC5E0) /* FIREDANCE PARSE V0 */

#define FD_SSPARSE_ADVANCE_ERROR          (-1)
#define FD_SSPARSE_ADVANCE_AGAIN          ( 0)
#define FD_SSPARSE_ADVANCE_MANIFEST       ( 1)
#define FD_SSPARSE_ADVANCE_ACCOUNT_HEADER ( 2)
#define FD_SSPARSE_ADVANCE_ACCOUNT_DATA   ( 3)
#define FD_SSPARSE_ADVANCE_DONE           ( 4)

struct fd_ssparse_private;
typedef struct fd_ssparse_private fd_ssparse_t;

struct fd_ssparse_advance_result {
  ulong bytes_consumed;

  union {
    struct {
      ulong slot;
      ulong size;
    } manifest;

    struct {
      ulong slot;
      ulong data_len;
      uchar const * pubkey;
      ulong lamports;
      ulong rent_epoch;
      uchar const * owner;
      int executable;
      uchar const * hash;
    } account_header;

    struct {
      uchar const * data;
      ulong len;
    } account_data;
  };
};

typedef struct fd_ssparse_advance_result fd_ssparse_advance_result_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_ssparse_align( void );

FD_FN_CONST ulong
fd_ssparse_footprint( void );

void *
fd_ssparse_new( void *  shmem,
                ulong   seed );

fd_ssparse_t *
fd_ssparse_join( void * ssparse );

void
fd_ssparse_reset( fd_ssparse_t * ssparse,
                  uchar *        payload,
                  ulong          payload_sz );

int
fd_ssparse_advance( fd_ssparse_t *                ssparse,
                    uchar const *                 data,
                    ulong                         data_sz,
                    fd_ssparse_advance_result_t * result );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssparse_h */

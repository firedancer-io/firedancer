#ifndef HEADER_fd_src_util_bin_parse_fd_bin_parse_h
#define HEADER_fd_src_util_bin_parse_fd_bin_parse_h

#include "fd_slice.h"
#include "../fd_util.h"
#include "../bc_types/fd_bc_types.h"

struct fd_bin_parse_ctx {
    fd_slice_t src;
    fd_slice_t dst;
    ulong      input_blob_sz;
    uchar    * pre_parse_src_cur;
    uchar    * pre_parse_dst_cur;
    int        invalid_state;
};

typedef struct fd_bin_parse_ctx fd_bin_parse_ctx_t;

FD_PROTOTYPES_BEGIN

void
fd_bin_parse_init( fd_bin_parse_ctx_t * ctx,
                       void           * src,
                       ulong            src_sz,
                       void           * dst,
                       ulong            dst_sz  );

void
fd_bin_parse_set_input_blob_size( fd_bin_parse_ctx_t * ctx,
                                   ulong                input_blob_sz );

int
fd_bin_parse_was_entire_input_blob_consumed( fd_bin_parse_ctx_t * ctx );

ulong
fd_bin_parse_total_dst_size_remaining( fd_bin_parse_ctx_t * ctx );

ulong
fd_bin_parse_total_src_size_remaining( fd_bin_parse_ctx_t * ctx );

ulong
fd_bin_parse_src_blob_size_remaining( fd_bin_parse_ctx_t * ctx );

int
fd_bin_parse_dst_has_enough_size_remaining( fd_bin_parse_ctx_t * ctx,
                                            ulong                sz   );

int
fd_bin_parse_is_state_ok_to_begin_parse( fd_bin_parse_ctx_t * ctx );

void *
fd_bin_parse_get_cur_dst( fd_bin_parse_ctx_t * ctx );

void *
fd_bin_parse_get_cur_src( fd_bin_parse_ctx_t * ctx );

ulong fd_bin_parse_bytes_written_during_this_parse( fd_bin_parse_ctx_t * ctx );

void
fd_bin_parse_update_state_parse_succeeded( fd_bin_parse_ctx_t * ctx,
                                     ulong                data_written_sz );

void
fd_bin_parse_update_state_parse_failed( fd_bin_parse_ctx_t * ctx );

void
fd_bin_parse_update_state_encode_succeeded( fd_bin_parse_ctx_t * ctx );

void
fd_bin_parse_update_state_encode_failed( fd_bin_parse_ctx_t * ctx );

int
fd_bin_parse_is_enough_space_in_src( fd_bin_parse_ctx_t * ctx,
                                     ulong                sz   );

int
fd_bin_parse_is_enough_space_in_dst( fd_bin_parse_ctx_t * ctx,
                                     ulong                sz   );

ulong
fd_bin_parse_input_blob_size( fd_bin_parse_ctx_t * ctx );

int
fd_bin_parse_read_u8( fd_bin_parse_ctx_t * ctx,
                      uchar              * dest );

int
fd_bin_parse_read_u16( fd_bin_parse_ctx_t * ctx,
                       ushort             * dest );

int
fd_bin_parse_read_u32( fd_bin_parse_ctx_t * ctx,
                       uint               * dest );

int
fd_bin_parse_read_option_u32( fd_bin_parse_ctx_t * ctx,
                              uint               * dest );

int
fd_bin_parse_read_u64( fd_bin_parse_ctx_t * ctx,
                       ulong              * dest );

int
fd_bin_parse_read_varint_u64( fd_bin_parse_ctx_t * ctx,
                              ulong              * dest );

int
fd_bin_parse_read_varint_u32( fd_bin_parse_ctx_t * ctx,
                              uint               * dest );

int
fd_bin_parse_read_varint_u16( fd_bin_parse_ctx_t * ctx,
                              ushort             * dest );

int
fd_bin_parse_write_varint_u64( fd_bin_parse_ctx_t * ctx,
                               ulong                value );

int
fd_bin_parse_write_varint_u32( fd_bin_parse_ctx_t * ctx,
                               uint                 value );

int
fd_bin_parse_write_varint_u16( fd_bin_parse_ctx_t * ctx,
                               ushort               value );

int
fd_bin_parse_read_option_u64( fd_bin_parse_ctx_t * ctx,
                              ulong              * dest );

int
fd_bin_parse_read_blob_of_size( fd_bin_parse_ctx_t * ctx,
                                ulong                size,
                                void               * dest );
                                
int
fd_bin_parse_decode_vector( fd_bin_parse_ctx_t * ctx,
                          ulong        type_sz,
                          void       * dst,
                          ulong        dst_sz,  
                          ulong      * nelems  );

int
fd_bin_parse_decode_option_vector( fd_bin_parse_ctx_t * ctx,
                                   ulong                type_sz,
                                   void               * dst,
                                   ulong                dst_sz,  
                                   ulong              * nelems   );

int fd_bin_parse_read_pubkey( fd_bin_parse_ctx_t  * ctx,
                              fd_pubkey_t         * pubkey_out );

int
fd_bin_parse_write_u8( fd_bin_parse_ctx_t  * ctx,
                       uchar                 value );

int
fd_bin_parse_write_u16( fd_bin_parse_ctx_t  * ctx,
                        ushort                value );

int
fd_bin_parse_write_u32( fd_bin_parse_ctx_t  * ctx,
                        uint                  value  );

int
fd_bin_parse_write_u64( fd_bin_parse_ctx_t  * ctx,
                        ulong                 value );

int
fd_bin_parse_write_blob_of_size( fd_bin_parse_ctx_t * ctx,
                                 void               * src,
                                 ulong                size );

int fd_bin_parse_write_pubkey( fd_bin_parse_ctx_t  * ctx,
                               fd_pubkey_t         * pubkey );

FD_PROTOTYPES_END

#endif



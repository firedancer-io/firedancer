#ifndef HEADER_fd_src_util_gossip_fd_gossip_msg_h
#define HEADER_fd_src_util_gossip_fd_gossip_msg_h

#include "fd_gossip_crds.h"
#include "../fd_ballet_base.h"
#include "../../util/bc_types/fd_bc_types.h"
#include "../../util/binparse/fd_slice.h"

/* gossip message types */

#define FD_GOSSIP_MSG_ID_PULL_REQ  (0)
#define FD_GOSSIP_MSG_ID_PULL_RESP (1)
#define FD_GOSSIP_MSG_ID_PUSH      (2)
#define FD_GOSSIP_MSG_ID_PRUNE     (3)
#define FD_GOSSIP_MSG_ID_PING      (4)
#define FD_GOSSIP_MSG_ID_PONG      (5)

/* macros for interfacing with vector structures parsed out of gossip messages
   and accompanying CRDS objects */

#define GET_BLOOM_FILTER_DATA_AND_SIZE( msg, bloom_data, bloom_data_sz )                             \
    void * bloom_data = (uchar *)msg + msg->crds_filter.bloom.bits.bits.offset;                      \
    ulong bloom_data_sz = msg->crds_filter.bloom.bits.bits.num_objs;                                 \

#define FOR_EACH_U64_IN_VECTOR( msg, vec_descriptor, value )                                         \
    ulong * value_ptr = (ulong *)((uchar *)msg + msg->vec_descriptor.offset);                        \
    ulong value = *value_ptr;                                                                        \
    for( ulong i = 0 ; i < msg->vec_descriptor.num_objs; i++, value_ptr += 1, value = *value_ptr )

#define FOR_EACH_CRDS_IN_VECTOR( msg, vec_descr_name, value )                                        \
    uchar * crds_ptr = (uchar *)msg + msg->vec_descr_name.offset;                                    \
    fd_gossip_crds_header_t * value = (fd_gossip_crds_header_t *)crds_ptr;                           \
    for( ulong i = 0 ; i < msg->vec_descr_name.num_objs; i++, value = (fd_gossip_crds_header_t *)((uchar *)value + value->obj_sz) )

#define GET_DATA_AND_NUM_ELEMENTS_FOR_VECTOR( msg, vector_name, ptr_to_vector, num_elements )        \
    void * ptr_to_vector = (uchar *)msg + msg->vector_name.offset;                                   \
    ulong num_elements = msg->vector_name.num_objs;

#define FOR_EACH_ADDR_IN_VECTOR( msg, vec_descr_name, value )                                        \
    uchar * addr_vec_ptr = (uchar *)msg + msg->vec_descr_name.offset;                                \
    fd_socketaddr_t * value = (fd_socketaddr_t *)addr_vec_ptr;                                       \
    for( ulong i = 0 ; i < msg->vec_descr_name.num_objs; i++, value = (fd_socketaddr_t *)((uchar *)value + sizeof( fd_socketaddr_t )) )

#define FOR_EACH_SOCKET_ENTRY_IN_VECTOR( msg, vec_descr_name, value )                                \
    uchar * socket_entry_ptr = (uchar *)msg + msg->vec_descr_name.offset;                            \
    fd_gossip_socketentry_t * value = (fd_gossip_socketentry_t *)socket_entry_ptr;                   \
    for( ulong i = 0 ; i < msg->vec_descr_name.num_objs; i++, value = (fd_gossip_socketentry_t *)((uchar *)value + sizeof( fd_gossip_socketentry_t )) )

#define FOR_EACH_SLOT_HASH_IN_VECTOR( msg, vec_descr_name, value )                                   \
    uchar * slot_hash_ptr = (uchar *)msg + msg->vec_descr_name.offset;                               \
    fd_gossip_crds_slot_hash_t * value = (fd_gossip_crds_slot_hash_t *)slot_hash_ptr;                \
    for( ulong i = 0 ; i < msg->vec_descr_name.num_objs; i++, value = (fd_gossip_crds_slot_hash_t *)((uchar *)value + sizeof( fd_gossip_crds_slot_hash_t )) )

#define FOR_EACH_COMPRESSED_SLOTS_IN_VECTOR( msg, vec_descr_name, value )                            \
    uchar * slot_hash_ptr = (uchar *)msg + msg->vec_descr_name.offset;                               \
    fd_gossip_crds_compressed_slots_t * value = (fd_gossip_crds_compressed_slots_t *)slot_hash_ptr;  \
    for( ulong i = 0 ; i < msg->vec_descr_name.num_objs; i++, value = (fd_gossip_crds_compressed_slots_t *)((uchar *)value + value->obj_sz) )

#define FOR_EACH_PUBKEY_IN_VECTOR( msg, vec_descriptor, value )                                      \
    fd_pubkey_t * value_ptr = (fd_pubkey_t *)((uchar *)msg + msg->vec_descriptor.offset);            \
    fd_pubkey_t value = *value_ptr;                                                                  \
    for( ulong i = 0 ; i < msg->vec_descriptor.num_objs; i++, value_ptr += 1, value = *value_ptr )


/* data structures for gossip messages */

struct fd_gossip_ping_msg {
  int            msg_id;
  ulong          msg_sz;
  fd_pubkey_t    from;
  uchar          token[32];
  fd_signature_t signature;
};

typedef struct fd_gossip_ping_msg      fd_gossip_ping_msg_t;

struct fd_gossip_pong_msg {
  int            msg_id;
  ulong          msg_sz;
  fd_pubkey_t    from;
  uchar          hash[32];
  fd_signature_t signature;
};

typedef struct fd_gossip_pong_msg      fd_gossip_pong_msg_t;

struct fd_gossip_prune_data {
  ulong                              obj_sz;
  fd_pubkey_t                        pubkey;
  fd_gossip_vector_descriptor_t      prunes;
  fd_signature_t                     signature;
  fd_pubkey_t                        destination;
  ulong                              wallclock;
};

typedef struct fd_gossip_prune_data fd_gossip_prune_data_t;

struct fd_gossip_prune_msg {
  int                                msg_id;
  ulong                              msg_sz;
  fd_pubkey_t                        pubkey;
  fd_gossip_prune_data_t             data;
};

typedef struct fd_gossip_prune_msg fd_gossip_prune_msg_t;

struct fd_gossip_pull_response {
  int                                msg_id;
  ulong msg_sz;
  fd_pubkey_t                        pubkey;
  fd_gossip_vector_descriptor_t values;
};

typedef struct fd_gossip_pull_response fd_gossip_pull_response_t;

struct fd_gossip_push {
  int                                msg_id;
  ulong msg_sz;
  fd_pubkey_t                        pubkey;
  fd_gossip_vector_descriptor_t values;
};

typedef struct fd_gossip_push          fd_gossip_push_msg_t;

struct fd_gossip_pull_request {
  int msg_id;
  ulong msg_sz;
  fd_gossip_crds_filter_t crds_filter;
  fd_gossip_vector_descriptor_t value;
};

typedef struct fd_gossip_pull_request  fd_gossip_pull_req_t;

/* base structure */
struct fd_gossip_msg {
  int msg_id;
  ulong msg_sz;
  uchar msg_payload[];
};

typedef struct fd_gossip_msg           fd_gossip_msg_t;

/* interface for gossip message parsing */

FD_PROTOTYPES_BEGIN

/* decoding */

fd_gossip_msg_t *
fd_gossip_parse_msg( fd_bin_parse_ctx_t * ctx );

int
fd_gossip_parse_pull_request_msg( fd_bin_parse_ctx_t * ctx,
                                  void               * out_buf,
                                  ulong                out_buf_sz,
                                  ulong              * obj_sz      );

int
fd_gossip_parse_pull_response_msg( fd_bin_parse_ctx_t * ctx,
                                   void               * out_buf,
                                   ulong                out_buf_sz,
                                   ulong              * obj_sz      );

int
fd_gossip_parse_prune_msg( fd_bin_parse_ctx_t * ctx,
                           void               * out_buf,
                           ulong                out_buf_sz,
                           ulong              * obj_sz      );

int
fd_gossip_parse_push_msg( fd_bin_parse_ctx_t * ctx,
                          void               * out_buf,
                          ulong                out_buf_sz,
                          ulong              * obj_sz      );

int
fd_gossip_parse_ping_msg( fd_bin_parse_ctx_t * ctx,
                          void               * out_buf,
                          ulong                out_buf_sz,
                          ulong              * obj_sz      );

int
fd_gossip_parse_pong_msg( fd_bin_parse_ctx_t * ctx,
                          void               * out_buf,
                          ulong                out_buf_sz,
                          ulong              * obj_sz      );

/* encoding */

void *
fd_gossip_encode_msg( fd_bin_parse_ctx_t * ctx,
                      ulong              * data_out_sz );

int
fd_gossip_encode_ping_msg( fd_bin_parse_ctx_t * ctx );

int
fd_gossip_encode_pong_msg( fd_bin_parse_ctx_t * ctx );

int
fd_gossip_encode_pull_resp_msg( fd_bin_parse_ctx_t * ctx );

int
fd_gossip_encode_push_msg( fd_bin_parse_ctx_t * ctx );

int
fd_gossip_encode_prune_msg( fd_bin_parse_ctx_t * ctx );

int
fd_gossip_encode_pull_req_msg( fd_bin_parse_ctx_t * ctx );

/* pretty-print for debugging */
void
fd_gossip_pretty_print( void * msg );

ulong
fd_gossip_pretty_print_crds_object( void * data );

FD_PROTOTYPES_END
                      
#endif





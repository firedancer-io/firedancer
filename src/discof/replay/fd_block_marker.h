#ifndef HEADER_fd_src_discof_replay_fd_block_marker_h
#define HEADER_fd_src_discof_replay_fd_block_marker_h

#include "../../util/fd_util_base.h"
#include "../../flamenco/fd_flamenco_base.h"


struct __attribute__((packed)) fd_block_header {
   uchar header_version;
   struct {
     ulong     parent_slot;
     fd_hash_t parent_block_id;
   } v1;
};
typedef struct fd_block_header fd_block_header_t;

struct __attribute__((packed)) fd_block_footer {
   uchar footer_version;
   struct {
     fd_hash_t bank_hash;
     ulong     block_producer_time_nanos;
     uchar     block_user_agent_length;
     /* things that are optional whyyyyyy */
     // uchar     block_user_agent[255];
     /* uchar   has_final_cert;
        uchar   final_cert[255];

        uchar   has_skip_reward_cert;
        uchar   skip_reward_cert[255];
        uchar   has_notar_reward_cert;
        uchar notar_reward_cert[255]; */
   } v1;
};
typedef struct fd_block_footer fd_block_footer_t;

struct __attribute__((packed)) fd_update_parent {
   uchar     update_parent_version;
   ulong     new_parent_slot;
   fd_hash_t new_parent_block_id;
};
typedef struct fd_update_parent fd_update_parent_t;

enum fd_block_marker_variant {
   FOOTER = 0,
   HEADER = 1,
   UPDATE_PARENT = 2,
   GENESIS_CERTIFICATE = 3, /* ??? */
};

struct __attribute__((packed)) fd_block_marker {
   ulong  marker_flag; /* always 0 */
   ushort version;     /* block marker header version, currently 1  */
   uchar  variant;     /* variant of block marker */
   ushort length;
   union {
    fd_block_header_t header;
    fd_block_footer_t footer;
    fd_update_parent_t update_parent;
   } data;
};
typedef struct fd_block_marker fd_block_marker_t;

#endif /*HEADER_fd_src_discof_replay_fd_block_marker_h */
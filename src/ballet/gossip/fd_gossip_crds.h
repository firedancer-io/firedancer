#ifndef HEADER_fd_src_util_gossip_fd_gossip_crds_h
#define HEADER_fd_src_util_gossip_fd_gossip_crds_h

#include "../fd_ballet_base.h"
#include "../../util/binparse/fd_slice.h"
#include "../../util/binparse/fd_bin_parse.h"
#include "../txn/fd_txn.h"

#define FD_GOSSIP_CRDS_ID_LEGACY_CONTACT_INFO          (0)
#define FD_GOSSIP_CRDS_ID_VOTE                         (1)
#define FD_GOSSIP_CRDS_ID_LOWEST_SLOT                  (2)
#define FD_GOSSIP_CRDS_ID_SNAPSHOT_HASHES              (3)
#define FD_GOSSIP_CRDS_ID_ACCOUNT_HASHES               (4)
#define FD_GOSSIP_CRDS_ID_EPOCH_SLOTS                  (5)
#define FD_GOSSIP_CRDS_ID_LEGACY_VERSION               (6)
#define FD_GOSSIP_CRDS_ID_VERSION                      (7)
#define FD_GOSSIP_CRDS_ID_NODE_INSTANCE                (8)
#define FD_GOSSIP_CRDS_ID_DUPLICATE_SHRED              (9)
#define FD_GOSSIP_CRDS_ID_INCREMENTAL_SNAPSHOT_HASHES  (10)
#define FD_GOSSIP_CRDS_ID_CONTACT_INFO                 (11)

#define FD_GOSSIP_COMPRESSION_TYPE_FLATE2              (0)
#define FD_GOSSIP_COMPRESSION_TYPE_UNCOMPRESSED        (1)

/* CRDS object structs */

struct fd_gossip_crds_vector_descriptor {
	ulong num_objs;
  ulong offset;
};

typedef struct fd_gossip_crds_vector_descriptor fd_gossip_vector_descriptor_t;

struct fd_gossip_crds_header {
  uint           crds_id;
  fd_signature_t signature;
  ulong obj_sz;
};

typedef struct fd_gossip_crds_header fd_gossip_crds_header_t;

struct fd_gossip_bit_vec_descriptor {
  fd_gossip_vector_descriptor_t bits;
  ulong len;
};

typedef struct fd_gossip_bit_vec_descriptor fd_gossip_bit_vec_descriptor_t;

struct fd_gossip_bloom_filter {
  fd_gossip_vector_descriptor_t keys;
  fd_gossip_bit_vec_descriptor_t bits;
  ulong num_bits_set;
};

typedef struct fd_gossip_bloom_filter fd_gossip_bloom_filter_t;

struct fd_gossip_crds_filter {
  fd_gossip_bloom_filter_t bloom;
  ulong mask;
  uint mask_bits;
};

typedef struct fd_gossip_crds_filter fd_gossip_crds_filter_t;

struct fd_gossip_crds_data_legacy_contact_info {
  fd_pubkey_t     id;
  fd_socketaddr_t gossip;
  fd_socketaddr_t tvu;
  fd_socketaddr_t tvu_fwd;
  fd_socketaddr_t repair;
  fd_socketaddr_t tpu;
  fd_socketaddr_t tpu_fwd;
  fd_socketaddr_t tpu_vote;
  fd_socketaddr_t rpc;
  fd_socketaddr_t rpc_pub_sub;
  fd_socketaddr_t serve_repair;
  ulong           wallclock;
  ushort          shred_version;
};

typedef struct fd_gossip_crds_data_legacy_contact_info fd_gossip_crds_data_legacy_contact_info_t;

struct fd_gossip_crds_value_legacy_contact_info {
  fd_gossip_crds_header_t hdr;
  fd_gossip_crds_data_legacy_contact_info_t data;
};

typedef struct fd_gossip_crds_value_legacy_contact_info fd_gossip_crds_value_legacy_contact_info_t;

struct fd_gossip_crds_data_legacy_version {
  fd_pubkey_t from;
  ulong       wallclock;
  ushort      major;
  ushort      minor;
  ushort      patch;
  int         commit;  /* optional. -1 indicates field was absent in incoming message */
};

typedef struct fd_gossip_crds_data_legacy_version fd_gossip_crds_data_legacy_version_t;

struct fd_gossip_crds_value_legacy_version {
  fd_gossip_crds_header_t hdr;
  fd_gossip_crds_data_legacy_version_t data;
};

typedef struct fd_gossip_crds_value_legacy_version fd_gossip_crds_value_legacy_version_t;

struct fd_gossip_crds_data_version {
  fd_pubkey_t from;
  ulong       wallclock;
  ushort      major;
  ushort      minor;
  ushort      patch;
  int         commit;    /* optional. -1 indicates field was absent in incoming message */
  uint        features;
};

typedef struct fd_gossip_crds_data_version fd_gossip_crds_data_version_t;

struct fd_gossip_crds_value_version {
  fd_gossip_crds_header_t hdr;
  fd_gossip_crds_data_version_t data;
};

typedef struct fd_gossip_crds_value_version fd_gossip_crds_value_version_t;

struct fd_gossip_crds_data_node_instance {
  fd_pubkey_t from;
  ulong wallclock;
  ulong timestamp;
  ulong token;
};

typedef struct fd_gossip_crds_data_node_instance fd_gossip_crds_data_node_instance_t;

struct fd_gossip_crds_value_node_instance {
  fd_gossip_crds_header_t hdr;
  fd_gossip_crds_data_node_instance_t data;
};

typedef struct fd_gossip_crds_value_node_instance fd_gossip_crds_value_node_instance_t;

struct fd_gossip_crds_slot_hash {
  ulong slot;
  uchar hash[32];
};

typedef struct fd_gossip_crds_slot_hash fd_gossip_crds_slot_hash_t;

struct fd_gossip_crds_data_incremental_snapshot_hashes {
  fd_pubkey_t from;
  fd_gossip_crds_slot_hash_t base;
  fd_gossip_vector_descriptor_t hashes;
  ulong wallclock;
};

typedef struct fd_gossip_crds_data_incremental_snapshot_hashes fd_gossip_crds_data_incremental_snapshot_hashes_t;

struct fd_gossip_crds_value_incremental_snapshot_hashes {
  fd_gossip_crds_header_t hdr;
  fd_gossip_crds_data_incremental_snapshot_hashes_t data;
};

typedef struct fd_gossip_crds_value_incremental_snapshot_hashes fd_gossip_crds_value_incremental_snapshot_hashes_t;

struct fd_gossip_crds_data_duplicate_shred {
  ushort index;
  fd_pubkey_t from;
  ulong wallclock;
  ulong slot;
  uint shred_index;
  uchar shred_type;
  uchar num_chunks;
  uchar chunk_index;
  fd_gossip_vector_descriptor_t chunk;
};

typedef struct fd_gossip_crds_data_duplicate_shred fd_gossip_crds_data_duplicate_shred_t;

struct fd_gossip_crds_compressed_slots {
  ulong obj_sz;
  uchar type;       /* 0 = flate2, 1 = uncompressed */
  ulong first_slot;
  ulong num;
  fd_gossip_vector_descriptor_t compressed;
  fd_gossip_bit_vec_descriptor_t slots;
};

typedef struct fd_gossip_crds_compressed_slots fd_gossip_crds_compressed_slots_t;

struct fd_gossip_crds_value_duplicate_shred {
  fd_gossip_crds_header_t hdr;
  fd_gossip_crds_data_duplicate_shred_t data;
};

typedef struct fd_gossip_crds_value_duplicate_shred fd_gossip_crds_value_duplicate_shred_t;

struct fd_gossip_crds_data_lowest_slot {
  uchar index;
  fd_pubkey_t from;
  ulong root;                             /* deprecated */
  ulong lowest;
  fd_gossip_vector_descriptor_t slots;    /* deprecated */
  fd_gossip_vector_descriptor_t stash;    /* deprecated */
  ulong wallclock;
};

typedef struct fd_gossip_crds_data_lowest_slot fd_gossip_crds_data_lowest_slot_t;

struct fd_gossip_crds_value_lowest_slot {
  fd_gossip_crds_header_t hdr;
  fd_gossip_crds_data_lowest_slot_t data;
};

typedef struct fd_gossip_crds_value_lowest_slot fd_gossip_crds_value_lowest_slot_t;

struct fd_gossip_crds_data_snapshot_hashes {
  fd_pubkey_t from;
  fd_gossip_vector_descriptor_t hashes;
  ulong wallclock;
};

typedef struct fd_gossip_crds_data_snapshot_hashes fd_gossip_crds_data_snapshot_hashes_t;

struct fd_gossip_crds_value_snapshot_hashes {
  fd_gossip_crds_header_t hdr;
  fd_gossip_crds_data_snapshot_hashes_t data;
};

typedef struct fd_gossip_crds_value_snapshot_hashes fd_gossip_crds_value_snapshot_hashes_t;

struct fd_gossip_crds_data_account_hashes {
  fd_pubkey_t from;
  fd_gossip_vector_descriptor_t hashes;
  ulong wallclock;
};

typedef struct fd_gossip_crds_data_account_hashes fd_gossip_crds_data_account_hashes_t;

struct fd_gossip_crds_value_account_hashes {
  fd_gossip_crds_header_t hdr;
  fd_gossip_crds_data_account_hashes_t data;
};

typedef struct fd_gossip_crds_value_account_hashes fd_gossip_crds_value_account_hashes_t;

struct fd_gossip_crds_data_vote {
  uchar index;
  fd_pubkey_t from;
  ulong wallclock;
  ulong slot;
  fd_gossip_vector_descriptor_t transaction;
};

typedef struct fd_gossip_crds_data_vote fd_gossip_crds_data_vote_t;

struct fd_gossip_crds_value_vote {
  fd_gossip_crds_header_t hdr;
  fd_gossip_crds_data_vote_t data;
};

typedef struct fd_gossip_crds_value_vote fd_gossip_crds_value_vote_t;

struct fd_gossip_crds_data_epoch_slots {
  uchar index;
  fd_pubkey_t from;
  fd_gossip_vector_descriptor_t compressed_slots;
  ulong wallclock;
};

typedef struct fd_gossip_crds_data_epoch_slots fd_gossip_crds_data_epoch_slots_t;

struct fd_gossip_crds_value_epoch_slots {
  fd_gossip_crds_header_t hdr;
  fd_gossip_crds_data_epoch_slots_t data;
};

typedef struct fd_gossip_crds_value_epoch_slots fd_gossip_crds_value_epoch_slots_t;

struct fd_gossip_version {
  ushort major;    /* varint encoded */
  ushort minor;    /* varint encoded */
  ushort patch;    /* varint encoded */
  uint   commit;
  uint   feature_set;
  ushort client;   /* varint encoded */
};

typedef struct fd_gossip_version fd_gossip_version_t;

struct fd_gossip_crds_data_contact_info {
  fd_pubkey_t                   pubkey;
  ulong                         wallclock;   /* varint encoded */
  ulong                         outset;
  ushort                        shred_version;
  fd_gossip_version_t           version;
  fd_gossip_vector_descriptor_t addrs;       /* shortvec encoded */
  fd_gossip_vector_descriptor_t sockets;     /* shortvec encoded */
};

typedef struct fd_gossip_crds_data_contact_info fd_gossip_crds_data_contact_info_t;

struct fd_gossip_crds_value_contact_info {
  fd_gossip_crds_header_t hdr;
  fd_gossip_crds_data_contact_info_t data;
};

typedef struct fd_gossip_crds_value_contact_info fd_gossip_crds_value_contact_info_t;

struct fd_gossip_socketentry {
  uchar key;
  uchar index;
  ushort offset;     /* varint encoded */
};

typedef struct fd_gossip_socketentry fd_gossip_socketentry_t;

FD_PROTOTYPES_BEGIN

int
fd_gossip_parse_crds_obj( fd_bin_parse_ctx_t * ctx,
                          void               * out_buf,
                          ulong                out_buf_sz,
                          ulong              * obj_sz      );

int
fd_gossip_read_socketaddr( fd_bin_parse_ctx_t * ctx,
                           fd_socketaddr_t    * socketaddr );

int
fd_bin_parse_decode_socket_entry_vector( fd_bin_parse_ctx_t * ctx,
                                         void       * dst,
                                         ulong        dst_sz,
                                         ulong      * nelems     );

int
fd_bin_parse_decode_ipaddr_entry_vector( fd_bin_parse_ctx_t * ctx,
                                         void       * out_buf,
                                         ulong        out_buf_sz,
                                         ulong      * nelems        );

int
fd_gossip_parse_crds_legacy_contact_info( fd_bin_parse_ctx_t * ctx,
                                          void               * out_buf,
                                          ulong                out_buf_sz,
                                          ulong              * obj_sz      );

int
fd_gossip_parse_crds_legacy_version( fd_bin_parse_ctx_t * ctx,
                                     void               * out_buf,
                                     ulong                out_buf_sz,
                                     ulong              * obj_sz      );

int
fd_gossip_parse_crds_version( fd_bin_parse_ctx_t * ctx,
                              void               * out_buf,
                              ulong                out_buf_sz,
                              ulong              * obj_sz      );

int
fd_gossip_parse_crds_node_instance( fd_bin_parse_ctx_t * ctx,
                                    void               * out_buf,
                                    ulong                out_buf_sz,
                                    ulong              * obj_sz      );

int
fd_gossip_parse_crds_node_instance( fd_bin_parse_ctx_t * ctx,
                                    void               * out_buf,
                                    ulong                out_buf_sz,
                                    ulong              * obj_sz      );

int
fd_gossip_parse_crds_incremental_snapshot_hashes( fd_bin_parse_ctx_t * ctx,
                                                  void               * out_buf,
                                                  ulong                out_buf_sz,
                                                  ulong              * obj_sz      );

int
fd_gossip_parse_crds_duplicate_shred( fd_bin_parse_ctx_t * ctx,
                                      void               * out_buf,
                                      ulong                out_buf_sz,
                                      ulong              * obj_sz      );

int
fd_gossip_parse_crds_lowest_slot( fd_bin_parse_ctx_t * ctx,
                                  void               * out_buf,
                                  ulong                out_buf_sz,
                                  ulong              * obj_sz      );

int
fd_gossip_parse_crds_snapshot_hashes( fd_bin_parse_ctx_t * ctx,
                                      void               * out_buf,
                                      ulong                out_buf_sz,
                                      ulong              * obj_sz      );

int
fd_gossip_parse_crds_account_hashes( fd_bin_parse_ctx_t * ctx,
                                     void               * out_buf,
                                     ulong                out_buf_sz,
                                     ulong              * obj_sz      );

int
fd_gossip_parse_crds_vote( fd_bin_parse_ctx_t * ctx,
                            void              * out_buf,
                            ulong               out_buf_sz,
                            ulong             * obj_sz      );

int
fd_gossip_parse_crds_epoch_slots( fd_bin_parse_ctx_t * ctx,
                                  void               * out_buf,
                                  ulong                out_buf_sz,
                                  ulong              * obj_sz      );

int
fd_gossip_parse_crds_contact_info( fd_bin_parse_ctx_t * ctx,
                                   void               * out_buf,
                                   ulong                out_buf_sz,
                                   ulong              * obj_sz      );

FD_PROTOTYPES_END

#endif


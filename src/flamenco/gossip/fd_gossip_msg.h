#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_msg_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_msg_h

#include "fd_gossip_types.h"
#include "fd_crds_value.h"


#define FD_GOSSIP_MSG_MTU (1232UL) /* Maximum size of a gossip message */
/* Deriving maximum number of CRDS values a message can hold:
  - Maximum bytes the CRDS array can hold is 
    1232(MTU)-4(msg disc)-32(pubkey)-8(crds len)=1188b
  - Smallest CRDS value is 64+4+48=116b 
    (64b signature + 4b discriminant + 48b slot hashes)
  - So, maximum number of CRDS values is 1188/(64+4+48) ~= 10
  - TODO: We might want to use a more conservative estimate that only includes
    the size of the signature and discriminant. */
#define FD_GOSSIP_MSG_MAX_CRDS (10UL)

/* FIXME: This should be imported from fd_crds instead. */
struct fd_crds_key {
  uchar tag;
  uchar pubkey[ 32UL ];
  union {
    uchar  vote_index;
    uchar  epoch_slots_index;
    ushort duplicate_shred_index;
  };
};
typedef struct fd_crds_key fd_crds_key_t;

struct fd_gossip_message {
  uchar tag; // uint in rust bincode
  union {
    fd_gossip_pull_request_t  pull_request[ 1 ];
    fd_gossip_pull_response_t pull_response[ 1 ]; /* CRDS Composite Type */
    fd_gossip_push_t          push[ 1 ];          /* CRDS Composite Type */
    fd_gossip_prune_t         prune[ 1 ];
    fd_gossip_ping_pong_t     piong[ 1 ];
  };

  /* Begin parsed gossip message metadata

     FIXME: These are strictly to operate on a parsed
     gossip message that is received in encoded form. The structure
     is a little awkward, especially if using this same struct to encode
     a message. Crux of the problem is half the fd_gossip_message fields function as metadata
     for the encoded message/payload, and the other half owns the data it parses
     (namely the inner message types defined above) via memcpys. We can:
      - Split this into two structs, one for metadata and one for the
        inner message types. This would be a little cleaner, but also a little
        more work to maintain.
      - Leave it as is, and just document the structure. This isn't as clean
        but is less work to maintain. */

  /* Signature related metadata, analagous to Agave's Signable trait (at least on the rx side) 
     FIXME: Prune does not define signable data as a contiguous region, which is really annoying */
  struct{
    uchar   has_signable_data; /* 0 for CRDS composite type */

    /* Should these be offsets in payload instead? */
    uchar   pubkey[32UL];
    uchar   signature[64UL]; 

    ulong   signable_data_offset; /* offset to start of signable region in payload */
    ulong   signable_sz;
  };

  uchar  has_shred_version;
  ushort shred_version;

  /* For CRDS composites, this holds information about the CRDS values necessary
     to perform an insertion into the CRDS and signature verification */
  ulong crds_cnt; /* number of CRDS values in the message, if any */
  struct {
    ulong offset; /* offset to start of CRDS value in payload */
    ulong sz;     /* size of CRDS value in payload */
  
    fd_crds_key_t key;


    uchar signature[64UL]; // signable data is always offset + sizeof(signature); signable_sz = sz - sizeof(signature)
    long wallclock_nanos;

    union {
      fd_gossip_contact_info_t contact_info;
      fd_gossip_vote_t         vote;
    };
  } crds[ FD_GOSSIP_MSG_MAX_CRDS ];

};

typedef struct fd_gossip_message fd_gossip_message_t;

void
fd_gossip_msg_init( fd_gossip_message_t * msg );

ulong
fd_gossip_msg_parse( fd_gossip_message_t * msg,
                     uchar const *         payload,
                     ulong                 payload_sz );

ulong
fd_gossip_msg_serialize( fd_gossip_message_t const * msg,
                         uchar *                  payload,
                         ulong                    payload_sz );

#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_msg_h */

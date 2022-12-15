/* packet-turbine.c
 * Routines for Solana Turbine protocol dissection
 * Copyright 2022 Firedancer Contributors <firedancer-devs [AT] jumptrading.com>
 *
 * Plugin for Wireshark - Network traffic analyzer
 *
 * SPDX-License-Identifier: Apache-2.0 */

/* Firedancer libraries */
#include "../../ballet/fd_ballet.h"
#include "../../util/fd_util_base.h"

/* Wireshark libraries */
#include <epan/epan_dissect.h>
#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <wsutil/str_util.h>

/* This Wireshark plugin is part of Firedancer, a high-performance Solana node implementation.

   Firedancer uses the Bazel build system instead of CMake.
   This required some breaking changes in plugin bootstrapping,
   such as explicitly defining plugin default exported symbols.

   This plugin is only compatible with LP64 C language data model.
   Therefore, it will only run on Unix-like systems.
   Win64 is not supported (however, Cygwin64 is).

   Another notable difference is the use of unaligned memory accesses.
   This plugin only runs on architectures that support such, e.g. x86_64 and armv8.

   Refer to //src/util:fd_util_base.h for more info on target assumptions. */

/* Exported symbols expected by the plugin loader
   This is used to ensure that this plugin is compatible with the host Wireshark. */
WS_DLL_PUBLIC char const plugin_version[];
WS_DLL_PUBLIC int  const plugin_want_major;
WS_DLL_PUBLIC int  const plugin_want_minor;

/* plugin_register: Entrypoint called by plugin loader */
WS_DLL_PUBLIC void plugin_register(void);

/* Re-export constants from <ws_version.h> */
char const plugin_version[]  = "0.1.0";
int  const plugin_want_major = WIRESHARK_VERSION_MAJOR;
int  const plugin_want_minor = WIRESHARK_VERSION_MINOR;

/***************************************************************************************************
 *                                                                                                 *
 *                                     SOLANA TURBINE PROTOCOL                                     *
 *                        as of mainnet-beta epoch 385 (Solana Labs v1.13)                         *
 *                                                                                                 *
 ***************************************************************************************************

  Solana Turbine is the data availability layer of the Solana network.
  It is used to distribute ledger data within large peer-to-peer networks over WAN.

  The protocol defines two domains:
   - The *Ledger Domain* operates on **blocks**:
     Streams of transactions with sequentially-consistent ordering. Serialized to binary blobs.
   - The *Wire Domain* operates on **shreds**:
     Authenticated UDP packets supporting distribution over peer-to-peer networks.
     Forward error correction to account for packet loss.

  Both domains converge over the concept of entry batches (and consequentially, blocks):
  A vector of entry batches (ledger domain) can be expressed by a vector of shreds (wire domain).
  Detailed information can be found below.

  In order to decode Solana Turbine traffic, we hook into Wireshark's main pass over a packet capture.
  For each packet, we take the following major steps.

   - Track out-of-order shreds and reorder them into entry batches.
     Requires short-lived heap data structures to detect the boundaries of individual fragment streams.

   - When all shreds of an entry batch become available, reassemble shreds into a virtual buffer.
     This step transitions over from the wire domain to the ledger domain.

   - Deserialize completed virtual buffers into protocol trees.

  This implementation contains the following non-trivial logic:

   - Shreds from _any_ source addresses and ports are accepted.

     In a typical production environment, a single block originates from packets sent by hundreds
     of individual peers. No peer sends more than ~1% of packets required to reassemble a single block.

   - Eviction/garbage collection of stale reorder tasks.

     Reorder data structures allocated by one packet will eventually be freed while processing another packet.

  The following features are not implemented yet.

   (!) Forward error correction from coding shreds
       This plugin cannot detect silent packet corruption nor recover missing data shreds.
       Note that Wireshark can still verify UDP/IP checksums.

   (!) Signature verification of incoming shreds
       This plugin does not verify the authenticity of incoming shreds.
       As such, a malicious peer could manipulated reassembled block data in Wireshark analyses.
       It is recommended to remove packets from untrusted source addresses.

   (!) Merkle inclusion proof checks
       This plugin does not verify inclusion proofs of Merkle-variant shreds.
       This allows malicious peers and block producers to manipulate reassembled block data.

  ### Ledger Domain

  The ledger domain operates on ledger blocks.
  The primary purpose of a block is to pack transaction data.

  This is done in three steps:
   1. Non-conflicting unordered vectors (sets) of transactions are packed into **entries**
   2. Ordered vectors of entries are packed into **entry batches**
   3. Entry batches are packed into **blocks**

  Ledger data schema:

      ```asn1
      Entry ::= SEQUENCE {
          -- Proof-of-History parameters --
          hash_cnt INTEGER(0..UINT64_MAX),
          hash     OCTET STRING(SIZE(32))

          -- Length-prefixed transaction vector --
          txns     SEQUENCE(SIZE(0..UINT64_MAX)) OF Transaction
      }

      -- Length-prefixed entry vector --
      EntryBatch ::= SEQUENCE(SIZE(0..UINT64_MAX)) OF Entry

      Block ::= SEQUENCE OF EntryBatch
      ```

  Ledger data is serialized using bincode encoding rules.

  Blocks are identified by the **slot number**.
  Slots are not a unique identifier, however: There can be multiple unrelated "chains" of blocks.
  Each chain is a sequence of blocks with monotonically increasing slot numbers.

  The points at which chains diverge from another are referred to as "forks".
  Forks exist for two reasons:
    - Hard fork: Inherently compatible chains, e.g. different networks or breaking validation changes.
    - Soft fork: Temporary network partition, eventually going to be resolved by the consensus protocol.

  ### Wire Domain

  The wire domain primarily consists of **shreds**.
  For details, refer to //src/ballet:fd_shred.h

  For the purposes of packet analysis, we will ignore erasure coding shreds and focus on data shreds.

  Each shred is transmitted as a single UDP packet of at least 1228 bytes.
  IP fragmentation of shreds is rare in the wild, and is unsupported by the Firedancer implementation.
  If the shred size is smaller than the packet size, the rest is padded with zeros.

  A vector of data shreds is created by fragmenting a serialized entry batch.
  Data shreds do not overlap over multiple entry batches.

  Each data shred header contains the following fields of interest:

      FT_UINT16  shred.version            Identifier of the hard fork
      FT_UINT64  shred.slot               Slot number (local block identifier within a chain)
      FT_UINT16  shred.data.parent_off    Slot difference between current and parent block;
                                          Helps identify sort forks
      FT_UINT32  shred.index              Incrementing fragment number within block (starts at 0)
      FT_BOOLEAN shred.data.end_of_batch  Marks the last shred of an entry batch

  When deploying Solana Turbine over a globally dispersed set of peers, shreds will arrive out-of-order.
  Consequentially, the naive approach of joining shreds in order will not work.

  Reassembly requires identifying sequences of fragments.
  In Turbine's terminology: The batch that each data shred belongs to, and ordering within the batch.

  These sequences can also be described by the set of non-overlapping contiguous shred index ranges within a slot.
  Shreds do not specify an explicit sequence identifier, so we derive a virtual sequence key instead.

  Recall that the end of an entry batch is marked by a shred with the `shred.data.end_of_batch` bit set.
  To find the start of the entry batch, we look at the end of the immediate predecessor entry batch.
  Thus, recovering the bounds of an entry batch that ends in index `i` requires knowing all shreds in index range [0;i].

***************************************************************************************************/

/* SHRED_REASSEMBLY_MAX_IDX: Max permitted shred index for reassembly
   Reassembly attempts for shreds with indices above this value are skipped.

   This value controls the max memory consumption per slot.
   During reassembly, each slot occupies 16 bytes per shred.
   A Turbine stream of 1 Gbps requires about 50k shreds per slot. */
#define SHRED_REASSEMBLY_MAX_IDX (131072U)

/* SHRED_REASSEMBLY_MIN_BUF_CNT: Min item capacity of per-slot shred buffer */
#define SHRED_REASSEMBLY_MIN_BUF_CNT (128U)
_Static_assert( __builtin_popcount( SHRED_REASSEMBLY_MIN_BUF_CNT )==1, "must be 2^x" );

/* Handles: Protocols */
static int proto_turbine = -1;
static int proto_entries = -1;
/* Handles: Protocol subtree handles */
static int ett_shred           = -1;
static int ett_shred_fragment  = -1;
static int ett_shred_fragments = -1;
static int ett_entries         = -1;
static int ett_entry           = -1;
/* Handles: Common header fields */
static int hf_sig           = -1;
static int hf_type          = -1;
static int hf_merkle_len    = -1;
static int hf_slot          = -1;
static int hf_idx           = -1;
static int hf_shred_version = -1;
static int hf_fec_set_idx   = -1;
/* Handles: Data shred fields */
static int hf_data_parent_off   = -1;
static int hf_data_flags        = -1;
static int hf_data_ref_tick     = -1;
static int hf_data_end_of_batch = -1;
static int hf_data_end_of_slot  = -1;
static int hf_data_size         = -1;
static int hf_data_payload      = -1;
/* Handles: Coding shred fields */
static int hf_code_data_cnt = -1;
static int hf_code_code_cnt = -1;
static int hf_code_idx      = -1;
static int hf_code_payload  = -1;
/* Handles: Shred fragmentation fields */
static int hf_msg_fragments                  = -1;
static int hf_msg_fragment                   = -1;
static int hf_msg_fragment_overlap           = -1;
static int hf_msg_fragment_overlap_conflicts = -1;
static int hf_msg_fragment_multiple_tails    = -1;
static int hf_msg_fragment_too_long_fragment = -1;
static int hf_msg_fragment_error             = -1;
static int hf_msg_fragment_count             = -1;
static int hf_msg_reassembled_in             = -1;
static int hf_msg_reassembled_length         = -1;
/* Handles: Block data */
static int hf_entry_cnt      = -1;
static int hf_entry          = -1;
static int hf_entry_hash_cnt = -1;
static int hf_entry_hash     = -1;
static int hf_entry_txn_cnt  = -1;

/* shred_type_vals: Lookup table for shred types (shred.variant>>4) */
static value_string const shred_type_vals[] = {
  { FD_SHRED_TYPE_LEGACY_DATA, "Legacy Data" },
  { FD_SHRED_TYPE_LEGACY_CODE, "Legacy Code" },
  { FD_SHRED_TYPE_MERKLE_DATA, "Merkle Data" },
  { FD_SHRED_TYPE_MERKLE_CODE, "Merkle Code" },
  { 0, NULL }
};

/* block_reassembly_key_t: Key identifying a block reassembly process. */
struct __attribute__((aligned(16))) block_reassembly_key {
  /* Slot number */
  ulong  slot;

  /* Shred versions identify different networks (hard forks) */
  ushort shred_version;

  /* Identify duplicate blocks with different parent slots */
  ushort parent_off;

  /* Padding */
  uint pad_0c;
};
typedef struct block_reassembly_key block_reassembly_key_t;
_Static_assert( sizeof(block_reassembly_key_t)==16, "memory layout" );

/* block_reassembly_key_hash: Returns the hash of an block_reassembly_key_t. */
static uint block_reassembly_key_hash( block_reassembly_key_t const * key ) {
  ulong h = fd_hash( 0UL, key, sizeof(block_reassembly_key_t) );
  return (uint)h;
}

/* block_reassembly_key_eq: Returns whether two block_reassembly_key_t are equal. */
static int block_reassembly_key_eq( block_reassembly_key_t const * a,
                                    block_reassembly_key_t const * b ) {
  return ( a->slot         ==b->slot          )
      && ( a->shred_version==b->shred_version )
      && ( a->parent_off   ==b->parent_off    );
}

static uint completed_batch_key_hash( uint const * key ) {
  ulong h = fd_hash( 0UL, key, sizeof(uint) );
  return (uint)h;
}

static int completed_batch_key_eq( uint const * a,
                                   uint const * b ) {
  return *a==*b;
}

/* pending_shred: A shred waiting to be reassembled. */
struct pending_shred {
  /* Copy of data in shred on file arena */
  void * data;
  /* Wireshark frame number of shred */
  uint   frame_num;
  /* Size of shred (0 implies shred does not exist) */
  ushort sz;
  /* Flag whether shred is last in batch */
  uchar  end_of_batch;
  /* Padding */
  uchar  pad_0f;
};
typedef struct pending_shred pending_shred_t;
_Static_assert( sizeof(pending_shred_t)==16, "memory layout" );

/* block_reassembly_state_t: Inflight state of a block's reassembly process */
struct block_reassembly_state {
  /* Number of shreds received */
  uint shred_cnt;

  /* Start index of lowest entry batch that has not been reassembled yet */
  uint reassemble_idx;

  /* Exclusive upper bound of shreds that are contiguous in range from zero upwards
     Invariant: contiguous_idx >= reassemble_idx */
  uint contiguous_idx;

  /* Number of shreds that have been successfully reassembled */
  uint reassemble_cnt;

  /* List of shreds. Values contain  */
  wmem_array_t * shreds;
};
typedef struct block_reassembly_state block_reassembly_state_t;

/* block_reassembly_contains: Returns whether a shred is already known within a reassembly. */
static bool
block_reassembly_contains( block_reassembly_state_t const * FD_RESTRICT state,
                           uint shred_idx ) {
  /* If array does not fit shred, it has not been received yet. */
  if( FD_UNLIKELY( shred_idx>=SHRED_REASSEMBLY_MAX_IDX              ) ) return 0;
  if( FD_UNLIKELY( shred_idx>=wmem_array_get_count( state->shreds ) ) ) return 0;

  /* Check if shred exists in buffer */
  pending_shred_t const * shred = wmem_array_index( state->shreds, shred_idx );
  return shred->sz > 0U;
}

/* dissect_entry_batch: Dissects a reassembled entry batch recovered from multiple data shreds. */
static gboolean
dissect_entry_batch( tvbuff_t    * tvb,
                     packet_info * pinfo __attribute__((unused)),
                     proto_tree  * tree ) {
  proto_item * entries_item = proto_tree_add_item( tree, proto_entries, tvb, 0, -1, ENC_NA );
  proto_tree * entries_tree = proto_item_add_subtree( entries_item, ett_entries );

  /* Track bounds */
  int offset = 0U;
  uint left  = tvb_captured_length( tvb );

  /* Primary macro to parse a node of data.
     Emits a bounds check, embeds a block scope `act`, and seeks forward. */
#define ADVANCE_RUN( n, act ) {          \
  uint _n = (n);                         \
  if( FD_UNLIKELY( left<_n ) ) return 0; \
  act                                    \
  offset+=(int)_n; left-=_n;             \
}
#define ADVANCE( n ) ADVANCE_RUN( n, {} )

  /* Add number of entries in batch */
  proto_tree_add_item( entries_tree, hf_entry_cnt, tvb, offset, 8, ENC_LITTLE_ENDIAN );
  ulong entries_cnt;
  ADVANCE_RUN( 8U, { entries_cnt = tvb_get_letoh64( tvb, offset ); } );

  /* Deserialize each entry */
  for( ulong i=0UL; i<entries_cnt; i++ ) {
    int          entry_off;
    proto_item * entry_item;
    proto_tree * entry_tree;

    /* Create new subtree */
    entry_off  = offset;
    entry_tree = proto_tree_add_subtree_format( entries_tree, tvb, offset, -1, ett_entry, &entry_item,
                                                "Entry %lu", i );

    /* Deserialize entry header */
    proto_tree_add_item( entry_tree, hf_entry_hash_cnt, tvb, offset,  8, ENC_LITTLE_ENDIAN );
    ADVANCE( 8U );

    proto_tree_add_item( entry_tree, hf_entry_hash,     tvb, offset, 32, ENC_NA            );
    ADVANCE( 32U );

    proto_tree_add_item( entry_tree, hf_entry_txn_cnt,  tvb, offset,  8, ENC_LITTLE_ENDIAN );
    ulong txn_cnt;
    ADVANCE_RUN( 8U, { txn_cnt = tvb_get_letoh64( tvb, offset ); } );

    /* Deserialize each txn */
    if( txn_cnt>0UL ) {
      /* TODO: Deserialize txns */
      return 0;
    }

    /* Update length of entry */
    proto_item_set_len( entry_item, offset-entry_off );
  }

#undef ADVANCE_RUN
#undef ADVANCE

  return 1;
}

struct __attribute__((packed)) fragment_shred_key {
  uint frame_num; /* we insert all fragments in the same frame, so this is fine */
  uint id;        /* derive from data */
};
typedef struct fragment_shred_key fragment_shred_key_t;

static uint
fragment_shred_hash( gconstpointer k ) {
  fragment_shred_key_t const * key = k;
  return (uint)fd_hash( 0UL, key, sizeof(fragment_shred_key_t) );
}

static int
fragment_shred_eq( gconstpointer k1,
                  gconstpointer k2 ) {
  fragment_shred_key_t const * key1 = k1;
  fragment_shred_key_t const * key2 = k2;

  return key1->frame_num==key2->frame_num && key1->id==key2->id;
}

static void *
fragment_shred_temporary_key( packet_info const * pinfo,
                              guint32 const       id,
				                      void const *        data __attribute__((unused)) ) {
  fragment_shred_key_t * key = g_slice_new( fragment_shred_key_t );
  key->frame_num = pinfo->num;
  key->id        = id;
  return (void *)key;
}

static void *
fragment_shred_persistent_key( packet_info const * pinfo,
					                     guint32 const       id,
                               void const *        data ) {
  return fragment_shred_temporary_key( pinfo, id, data );
}

static void
fragment_shred_free_temporary_key( gpointer ptr ) {
	g_slice_free( fragment_shred_key_t, ptr );
}

static void
fragment_shred_free_persistent_key( gpointer ptr ) {
  fragment_shred_free_temporary_key( ptr );
}

/* Special shred reassembly table functions.

   These are required because the Wireshark library functions
   only run reassembly over packets received from the same peers.

   In practice, Turbine traffic is received from hundreds of peers simultaneously. */
const reassembly_table_functions
shred_reassembly_table_functions = {
	fragment_shred_hash,
	fragment_shred_eq,
	fragment_shred_temporary_key,
	fragment_shred_persistent_key,
	fragment_shred_free_temporary_key,
	fragment_shred_free_persistent_key
};

/* Shred-to-entry reassembly.
   Currently does not support recovery from erasure codes. */
static reassembly_table shred_reassembly_table;

/* Associate shred reassembly with fragmentation-related fields. */
static fragment_items const msg_frag_items = {
  /* Fragment subtrees */
  .ett_fragment  = &ett_shred_fragment,
  .ett_fragments = &ett_shred_fragments,
  /* Fragment fields */
  .hf_fragments                  = &hf_msg_fragments,                  /* FT_NONE     */
  .hf_fragment                   = &hf_msg_fragment,                   /* FT_FRAMENUM */
  .hf_fragment_overlap           = &hf_msg_fragment_overlap,           /* FT_BOOLEAN  */
  .hf_fragment_overlap_conflict  = &hf_msg_fragment_overlap_conflicts, /* FT_BOOLEAN  */
  .hf_fragment_multiple_tails    = &hf_msg_fragment_multiple_tails,    /* FT_BOOLEAN  */
  .hf_fragment_too_long_fragment = &hf_msg_fragment_too_long_fragment, /* FT_BOOLEAN  */
  .hf_fragment_error             = &hf_msg_fragment_error,             /* FT_FRAMENUM */
  .hf_fragment_count             = &hf_msg_fragment_count,             /* FT_UINT32   */
  .hf_reassembled_in             = &hf_msg_reassembled_in,             /* FT_FRAMENUM */
  .hf_reassembled_length         = &hf_msg_reassembled_length,         /* FT_UINT32   */
  .hf_reassembled_data           = NULL,                               /* FT_BYTES    */
  /* Tag */
  .tag = "Message fragments"
};

static wmem_multimap_t * completed_map = NULL;

static wmem_multimap_t *
get_completed_map( void ) {
  if( FD_UNLIKELY( !completed_map ) ) {
    GHashFunc  hash_fn = (uint (*)( const void * ))              completed_batch_key_hash;
    GEqualFunc eq_fn   = (int  (*)( const void *, const void * ))completed_batch_key_eq;
    completed_map = wmem_multimap_new( wmem_file_scope(), hash_fn, eq_fn );
  }
  return completed_map;
}

static void
insert_completed_batch( uint frame_idx,
                        uint stream_id ) {
  uint * keys = g_new0(uint, 2);
  keys[0] = frame_idx;
  keys[1] = stream_id;
  wmem_multimap_insert32( get_completed_map(), &keys[0], stream_id, &keys[1] );
}

static tvbuff_t ** fragment_head_data( fragment_head *     fd_head,
                                       packet_info const * pinfo ) {
  /* Unfortunately, the struct offsets of fragment_head are not ABI-stable.

     We'll have to probe memory to detect the ABI on the fly.
     This is very stupid and should be fixed upstream.
     It goes without saying that this will not be used in the production-relevant parts.
     Wireshark is intended to be used as a debugging tool.

     It will also break on future Wireshark versions.
     Still better than Rust ABIs.

     This happens because the compiler is forced to pad the `reas_in_layer_num` field (uchar) to align `tvb_data`.
     However, we know the value of `reas_in_layer_num`, and this value is different enough from a pointer!

     Known binary layouts:

     GCC 8.5:
       0x28: fd_head->reas_in_layer_num
       0x30: fd_head->tvb_data

     GCC 11.3
       0x28: fd_head->tvb_data
       0x30: fd_head->reas_in_layer_num */

  uint * fd_probe = (uint *)fd_head;
  uint known_layer = (uint)pinfo->curr_layer_num;
  if( fd_probe[0x28U/4U]==known_layer ) return (tvbuff_t **)&fd_probe[0x30U/4U];
  if( fd_probe[0x30U/4U]==known_layer ) return (tvbuff_t **)&fd_probe[0x28U/4U];
  return NULL;
}

/* block_reassemble_batch: Registers a single batch for reassembly. */
static fragment_head *
block_reassemble_batch( reassembly_table *      const table,
                        uint                    const stream_id,
                        packet_info *           const pinfo,
                        pending_shred_t const * const shred,
                        ulong                   const shred_cnt ) {
  /* Iterate over list of shreds */
  pending_shred_t const * s = shred;

  /* Remember last fragment head */
  fragment_head * head;

  /* Retroactively add a fragment for each shred.
     Our custom block reassembly algorithm has already reordered items,
     so we can just use the in-order func `fragment_add_seq_next` here.  */
  ulong i=shred_cnt;
  do {
    tvbuff_t * shred_buf = tvb_new_real_data( s->data, s->sz, (int)s->sz );
    int more_frags = i>1U;
    head = fragment_add_seq_next( table, shred_buf, 0, pinfo, stream_id, NULL, s->sz, more_frags );
    s++;
  } while( --i );

  /* `fragment_add_seq_next` sets each fragment's frame number to the one we are currently dissecting.
     This is incorrect, since our buffered fragment data comes from previously seen frames.
     So, we just hijack the fragment list and fixup each frame number from our known list. */
  if( FD_UNLIKELY( !head ) ) return NULL;
  s = shred;
  for( fragment_item * node=head->next; node; node=node->next ) {
    node->frame = (s++)->frame_num;
  }

  /* Fixup data if there is only one frag */
  if( FD_UNLIKELY( shred_cnt==1UL ) ) {
    tvbuff_t ** target = fragment_head_data( head, pinfo );
    if( FD_LIKELY( target ) ) {
      /* Wrap tvb for good measure. */
      tvbuff_t * new_tvb = tvb_new_real_data( shred->data, shred->sz, (int)shred->sz );
                 new_tvb = tvb_new_chain( tvb_new_real_data( NULL, 0U, 0 ), new_tvb );
      *target  = new_tvb;
    }
  }

  return head;
}

/* _process_reassembled_data: Override Wireshark's `process_reassembled_data` to better work with out-of-order reassembly.

   `process_reassembled_data` takes the given tvb instead of reading from `fragment_head` if there is only one fragment.
   Thus, we construct a new empty-chained tvb and trick the function into accepting it.

   FIXME: This probably leaks memory.

   Our pain doesn't end here: The ABI of the struct we need is unstable, so we have to use magic to find the right pointer. */
static tvbuff_t *
_process_reassembled_data( packet_info *           pinfo,
	                         char const *            name,
                           fragment_head *         fd_head,
                           fragment_items const *  fit,
	                         proto_tree *            tree ) {
  if( FD_UNLIKELY( !fd_head ) ) return NULL;

  tvbuff_t ** frag_tvb_ptr = fragment_head_data( fd_head, pinfo );

  /* Happy path: We think to have found `frag_tvb`. */
  if( FD_LIKELY( frag_tvb_ptr && *frag_tvb_ptr ) ) {
    tvbuff_t * frag_tvb = *frag_tvb_ptr;
    proto_item * frag_tree_item;
    add_new_data_source( pinfo, frag_tvb, name );
    show_fragment_seq_tree( fd_head, fit, tree, pinfo, frag_tvb, &frag_tree_item );
    return frag_tvb;
  }

  /* Fall back to in-library function.
     This will fail for PDUs consisting of one fragment.

     `process_reassembled_data` has the unintuitive behavior of
     using the given tvb instead of the fd_head tvb if there is only one fragment.

     This only works when the single fragment is part of the packet we are currently dissecting.
     However, we often retroactively "reassemble" out-of-order fragments that we received previously.
     Sure, we technically have `fragment_add_out_of_order`, but let's not even begin with using that. */
  tvbuff_t * empty = tvb_new_real_data( NULL, 0U, 0 );
  return process_reassembled_data( empty, 0, pinfo, name, fd_head, fit, NULL, tree );
}

/* block_reassemble_batches: Registers one or more reordered batches for reassembly.

   The given new_end_idx is the inclusive upper bound (shred_idx) of the contiguous batches for reassembly. */
static void
block_reassemble_batches( block_reassembly_state_t * FD_RESTRICT state,
                          ulong              new_end_idx,
                          reassembly_table * table,
                          packet_info      * pinfo,
                          proto_tree       * tree ) {
  pending_shred_t const * pending = wmem_array_get_raw( state->shreds );

  /* Dissect up to 32 reassembled PDUs */
  tvbuff_t * reassembled[32];
  ulong i=0UL;

  ulong start = state->reassemble_idx;
  for( ulong j=start; j<=new_end_idx; j++ ) {
    fragment_head * fh;
    if( FD_UNLIKELY( pending[ j ].end_of_batch ) ) {
      uint stream_id = (uint)start;
      fh = block_reassemble_batch( table, stream_id, pinfo, pending+start, j-start+1 );
      insert_completed_batch( pinfo->num, stream_id );

      tvbuff_t * new_tvb = _process_reassembled_data( pinfo, "Reassembled block", fh, &msg_frag_items, tree );
      if( FD_UNLIKELY( new_tvb && i<32UL ) ) {
        reassembled[i++] = new_tvb;
      }
      start = (uint)j+1U;
    }
  }
  state->reassemble_idx = (uint)start;

  /* Defer dissection until end of data structure update.
     Dissection can throw an exception and break invariants. */
  while( i-->0UL ) {
    tvbuff_t * new_tvb = reassembled[i];
    TRY {
      dissect_entry_batch( new_tvb, pinfo, tree );
    }
    CATCH(ReportedBoundsError) {
      show_exception( new_tvb, pinfo, tree, ReportedBoundsError, GET_MESSAGE );
    }
    ENDTRY;
  }
}

/* block_reassembly_register: Registers a shred to be reassembled.

   Returns -1 if reassembly of an entry batch is not possible yet.
   Else, returns the shred index of the highest batch that can be reassembled.

   It is illegal to register the same shred_idx twice on the same state. */
static long
block_reassembly_register( block_reassembly_state_t * FD_RESTRICT state,
                           tvbuff_t * const tvb,
                           uint       const shred_idx,
                           uint       const frame_num,
                           ushort     const sz,
                           bool       const end_of_batch ) {
  /* Refuse reassembly if shred index is too high */
  if( FD_UNLIKELY( shred_idx>=SHRED_REASSEMBLY_MAX_IDX ) ) return -1;
  /* Ignore shreds with zero size */
  if( FD_UNLIKELY( sz==0U ) ) return -1;

  /* Reallocate shred buffer to fit
     Note that wmem_array_grow is a no-op if the internal buffer capacity is large enough. */
  uint buf_cnt = wmem_array_get_count( state->shreds );
  if( FD_UNLIKELY( shred_idx>=buf_cnt ) ) {
    uint target_sz;
    if( FD_LIKELY( shred_idx<SHRED_REASSEMBLY_MIN_BUF_CNT ) ) {
      /* Allocate min size buffer */
      target_sz = SHRED_REASSEMBLY_MIN_BUF_CNT;
    } else {
      /* Allocate 2^x */
      target_sz = 2U<<( fd_uint_find_msb( shred_idx ) );
    }

    /* Grow internal capacity */
    uint grow_by = target_sz-buf_cnt;
    wmem_array_grow( state->shreds, grow_by );

    /* Actually increase element count
       wmem_array does not export a zero-initialization API yet.
       Unfortunately, we'll have to zero by copying from .bss. */
    static pending_shred_t const zero = {0};
    do {
      wmem_array_append( state->shreds, &zero, 1U );
    } while( --grow_by>0U );
  }

  /* Fill in pending entry */
  pending_shred_t * pending = wmem_array_get_raw( state->shreds );
  pending[ shred_idx ].data         = tvb_memdup( wmem_file_scope(), tvb, FD_SHRED_DATA_HEADER_SZ, sz );
  pending[ shred_idx ].frame_num    = frame_num;
  pending[ shred_idx ].sz           = sz;
  pending[ shred_idx ].end_of_batch = end_of_batch;

  /* Update state */
  state->shred_cnt++;

  /* If shred index exceeds number of shreds,
     don't bother checking for contiguous range. */
  if( FD_LIKELY( shred_idx>(state->shred_cnt) ) ) return -1;

  /* Check if we have a contiguous range of shreds.
     This is a worst-case O(n^2) algorithm. It also fails to reassemble out-of-order.
     Optimize later. */

  /* Scan backwards for gaps */
  long i;
  for( i=(long)shred_idx-1; i>=(state->contiguous_idx); i-- ) {
    if( FD_LIKELY( pending[i].sz==0U ) ) break;
  }

  /* If buffer is contiguous up to shred_idx, scan forwards */
  if( FD_UNLIKELY( i<(state->contiguous_idx) ) ) {
    /* In case we uncover a new contiguous range of shreds,
       remember the highest end_of_batch. */
    long end_frame_idx = -1;
    if( FD_UNLIKELY( end_of_batch ) ) end_frame_idx = (long)shred_idx;

    for( i=(long)shred_idx+1; i<buf_cnt; i++ ) {
      if( FD_LIKELY  ( pending[i].sz==0U       ) ) break;
      if( FD_UNLIKELY( pending[i].end_of_batch ) ) end_frame_idx = i;
    }

    state->contiguous_idx = (uint)i;

    return end_frame_idx;
  }

  return -1;
}

/* block_reassemblies: Root map tracking all reassemblies

   Key type:   block_reassembly_key_t
   Value type: block_reassembly_state_t */
static wmem_map_t * block_reassemblies = NULL;

/* block_reassemblies_upsert: Returns a pointer to a reassembly state object for a specific block.
   Allocates a new state object if none exists. */
static block_reassembly_state_t *
block_reassemblies_upsert( block_reassembly_key_t const * key ) {
  wmem_allocator_t * alloc = wmem_file_scope();

  /* Allocate global tree if necessary. */
  if( FD_UNLIKELY( !block_reassemblies ) ) {
    GHashFunc  hash_fn = (uint (*)( const void * ))              block_reassembly_key_hash;
    GEqualFunc eq_fn   = (int  (*)( const void *, const void * ))block_reassembly_key_eq;
    block_reassemblies = wmem_map_new( alloc, hash_fn, eq_fn );
  }

  /* Check if node already exists. */
  block_reassembly_state_t * node;
  node = wmem_map_lookup( block_reassemblies, key );
  if( FD_LIKELY( node ) ) return node;

  /* Allocate new key. */
  block_reassembly_key_t * heap_key = wmem_new0( alloc, block_reassembly_key_t );
  memcpy( heap_key, key, sizeof(block_reassembly_key_t) );

  /* Allocate and insert new node. */
  node = wmem_new0( alloc, block_reassembly_state_t );
  wmem_map_insert( block_reassemblies, heap_key, node );
  node->shreds = wmem_array_new( alloc, sizeof(pending_shred_t) );
  return node;
}

/* proto_register_turbine: Register protocols, element trees, items */
void
proto_register_turbine(void) {
  /* Header fields */
  static hf_register_info hf[] = {
    /* p_id                                 name                                       abbrev                              type         display    strings               bitmask blurb ...     */
    { &hf_sig,                            { "Signature",                               "shred.signature",                  FT_BYTES,    BASE_NONE, NULL,                    0x0, NULL, HFILL } },
    { &hf_type,                           { "Type",                                    "shred.type",                       FT_UINT8,    BASE_HEX,  VALS(shred_type_vals),  0xF0, NULL, HFILL } },
    { &hf_merkle_len,                     { "Merkle Proof Len",                        "shred.merkle_len",                 FT_UINT8,    BASE_HEX,  NULL,                   0x0F, NULL, HFILL } },
    { &hf_slot,                           { "Slot",                                    "shred.slot",                       FT_UINT64,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } },
    { &hf_idx,                            { "Index",                                   "shred.index",                      FT_UINT32,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } },
    { &hf_shred_version,                  { "Shred Version",                           "shred.version",                    FT_UINT16,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } },
    { &hf_fec_set_idx,                    { "FEC Set Index",                           "shred.fec_set_idx",                FT_UINT32,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } },

    { &hf_data_parent_off,                { "Parent Slot Offset",                      "shred.data.parent_off",            FT_UINT16,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } },
    { &hf_data_flags,                     { "Flags",                                   "shred.data.flags",                 FT_UINT8,    BASE_HEX,  NULL,                    0x0, NULL, HFILL } },
    { &hf_data_end_of_slot,               { "Last shred in slot",                      "shred.data.end_of_slot",           FT_BOOLEAN,  8,         NULL,                   0x80, NULL, HFILL } },
    { &hf_data_end_of_batch,              { "Last shred in entry batch",               "shred.data.end_of_batch",          FT_BOOLEAN,  8,         NULL,                   0x40, NULL, HFILL } },
    { &hf_data_ref_tick,                  { "Reference Tick",                          "shred.data.ref_tick",              FT_UINT8,    BASE_DEC,  NULL,                   0x3f, NULL, HFILL } },
    { &hf_data_size,                      { "Shred Size",                              "shred.data.size",                  FT_UINT16,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } },
    { &hf_data_payload,                   { "Data Payload",                            "shred.data.payload",               FT_BYTES,    BASE_NONE, NULL,                    0x0, NULL, HFILL } },

    { &hf_code_data_cnt,                  { "Data Shred Count",                        "shred.code.data_cnt",              FT_UINT16,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } },
    { &hf_code_code_cnt,                  { "Code Shred Count",                        "shred.code.code_cnt",              FT_UINT16,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } },
    { &hf_code_idx,                       { "Code Shred Index",                        "shred.code.code_idx",              FT_UINT16,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } },
    { &hf_code_payload,                   { "Code Payload",                            "shred.code.payload",               FT_BYTES,    BASE_NONE, NULL,                    0x0, NULL, HFILL } },

    { &hf_msg_fragments,                  { "Block fragments",                         "shred.fragments",                  FT_NONE,     BASE_NONE, NULL,                    0x0, NULL, HFILL } },
    { &hf_msg_fragment,                   { "Block fragment",                          "shred.fragment",                   FT_FRAMENUM, BASE_NONE, NULL,                    0x0, NULL, HFILL } },
    { &hf_msg_fragment_overlap,           { "Shred overlap",                           "shred.fragment.overlap",           FT_BOOLEAN,  BASE_NONE, NULL,                    0x0, NULL, HFILL } },
    { &hf_msg_fragment_overlap_conflicts, { "Shred overlapping with conflicting data", "shred.fragment.overlap.conflicts", FT_BOOLEAN,  BASE_NONE, NULL,                    0x0, NULL, HFILL } },
    { &hf_msg_fragment_multiple_tails,    { "Block has multiple tail shreds",          "shred.fragment.multiple_tails",    FT_BOOLEAN,  BASE_NONE, NULL,                    0x0, NULL, HFILL } },
    { &hf_msg_fragment_too_long_fragment, { "Shred too long",                          "shred.fragment.too_long_fragment", FT_BOOLEAN,  BASE_NONE, NULL,                    0x0, NULL, HFILL } },
    { &hf_msg_fragment_error,             { "Block reassembly error",                  "shred.fragment.error",             FT_FRAMENUM, BASE_NONE, NULL,                    0x0, NULL, HFILL } },
    { &hf_msg_fragment_count,             { "Shred count",                             "shred.fragment.count",             FT_UINT32,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } },
    { &hf_msg_reassembled_in,             { "Reassembled in",                          "shred.reassembled.in",             FT_FRAMENUM, BASE_NONE, NULL,                    0x0, NULL, HFILL } },
    { &hf_msg_reassembled_length,         { "Reassembled block size",                  "shred.reassembled.length",         FT_UINT32,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } },

    { &hf_entry_cnt,                      { "Entry Count",                             "solana_block.entry_cnt",           FT_UINT64,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } },
    { &hf_entry,                          { "Entry",                                   "solana_block.entry",               FT_NONE,     BASE_NONE, NULL,                    0x0, NULL, HFILL } },
    { &hf_entry_hash_cnt,                 { "Entry Hash Count",                        "solana_block.entry.hash_cnt",      FT_UINT64,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } },
    { &hf_entry_hash,                     { "Entry Hash",                              "solana_block.entry.hash",          FT_BYTES,    BASE_NONE, NULL,                    0x0, NULL, HFILL } },
    { &hf_entry_txn_cnt,                  { "Transaction Count",                       "solana_block.entry.txn_cnt",       FT_UINT64,   BASE_DEC,  NULL,                    0x0, NULL, HFILL } }
  };

  static gint * ett[] = {
    &ett_shred,
    &ett_shred_fragment,
    &ett_shred_fragments,
    &ett_entries,
    &ett_entry
  };

  proto_turbine = proto_register_protocol( "Solana Turbine Shred",
                                           "Solana Turbine",
                                           "solana_turbine" );
  proto_entries = proto_register_protocol( "Solana Block Entries",
                                           "Solana Block",
                                           "solana_block" );

  proto_register_field_array( proto_turbine, hf, array_length( hf ) );
  proto_register_subtree_array( ett, array_length( ett ) );

  /* Initialize shred reassembly table using custom reassembly routines. */
  reassembly_table_register( &shred_reassembly_table, &shred_reassembly_table_functions );
}

/* reassemble_turbine: Reassembles a data shred. */
static void
reassemble_turbine( tvbuff_t    * tvb,
                    packet_info * pinfo,
                    proto_tree  * tree,
                    ushort        sz,
                    bool          end_of_batch ) {
  /* Read data from packet */
  block_reassembly_key_t const rkey = {
    .shred_version = tvb_get_letohs ( tvb, offsetof( fd_shred_t, version         ) ),
    .slot          = tvb_get_letoh64( tvb, offsetof( fd_shred_t, slot            ) ),
    .parent_off    = tvb_get_letohs ( tvb, offsetof( fd_shred_t, data.parent_off ) )
  };
  uint shred_idx   = tvb_get_letohl ( tvb, offsetof( fd_shred_t, idx             ) );

  /* Only reassemble once */
  if( FD_UNLIKELY( pinfo->fd->visited ) ) {
    uint stream_id = shred_idx+1U;
    do {
      /* Deliberately underflow */
      uint * cur_key = wmem_multimap_lookup32_le( get_completed_map(), &pinfo->num, stream_id-1U );
      if( FD_LIKELY( !cur_key ) ) break;
      stream_id = *cur_key;

      fragment_head * fh = fragment_get_reassembled_id( &shred_reassembly_table, pinfo, stream_id );
      if( FD_LIKELY( fh ) ) {
        tvbuff_t * new_tvb = _process_reassembled_data( pinfo, "Reassembled block", fh, &msg_frag_items, tree );
        if( FD_UNLIKELY( new_tvb ) ) {
          dissect_entry_batch( new_tvb, pinfo, tree );
        }
      }
    } while ( stream_id>0U );

    return;
  }

  /* Lookup reassembly state for shred */
  block_reassembly_state_t * rstate = block_reassemblies_upsert( &rkey );

  /* Bail if this shred has already been found */
  if( FD_UNLIKELY( block_reassembly_contains( rstate, shred_idx ) ) ) return;

  /* Add shred to reassembly */
  long new_end_idx = block_reassembly_register( rstate, tvb, shred_idx, pinfo->num, sz, end_of_batch );

  /* Check if we found new batches */
  if( new_end_idx>=0 ) {
    block_reassemble_batches( rstate, (ulong)new_end_idx, &shred_reassembly_table, pinfo, tree );
  }
}

/* dissect_turbine: Dissects a Solana turbine shred packet. */
static gboolean
dissect_turbine( tvbuff_t    * tvb,
                 packet_info * pinfo,
                 proto_tree  * tree,
                 void        * data __attribute__((unused)) ) {
  /* Turbine packets are always at least 1228 bytes long. */
  uint packet_sz = tvb_captured_length( tvb );
  if( packet_sz<FD_SHRED_SZ ) return 0;

  col_set_str( pinfo->cinfo, COL_PROTOCOL, "Turbine" );
  col_clear  ( pinfo->cinfo, COL_INFO );

  proto_item * ti     = proto_tree_add_item( tree, proto_turbine, tvb, 0, -1, ENC_NA );
  proto_tree * tshred = proto_item_add_subtree( ti, ett_shred );

  /* Add common shred header fields */
  proto_tree_add_item( tshred, hf_sig,           tvb, offsetof( fd_shred_t, signature   ), 64, ENC_NA            );
  proto_tree_add_item( tshred, hf_type,          tvb, offsetof( fd_shred_t, variant     ),  1, ENC_LITTLE_ENDIAN );
  proto_tree_add_item( tshred, hf_slot,          tvb, offsetof( fd_shred_t, slot        ),  8, ENC_LITTLE_ENDIAN );
  proto_tree_add_item( tshred, hf_idx,           tvb, offsetof( fd_shred_t, idx         ),  4, ENC_LITTLE_ENDIAN );
  proto_tree_add_item( tshred, hf_shred_version, tvb, offsetof( fd_shred_t, version     ),  2, ENC_LITTLE_ENDIAN );
  proto_tree_add_item( tshred, hf_fec_set_idx,   tvb, offsetof( fd_shred_t, fec_set_idx ),  4, ENC_LITTLE_ENDIAN );

  /* Detect type and size of shred */
  uchar variant = tvb_get_guint8( tvb, offsetof( fd_shred_t, variant ) );
  uchar type    = fd_shred_type( variant );

  uint header_sz = (uint)fd_shred_header_sz( variant ) + (uint)fd_shred_merkle_sz( variant );

  /* Merkle proof length. */
  if( type==FD_SHRED_TYPE_MERKLE_CODE || type==FD_SHRED_TYPE_MERKLE_DATA ) {
    proto_tree_add_item( tshred, hf_merkle_len, tvb, offsetof( fd_shred_t, variant ), 1, ENC_LITTLE_ENDIAN );
  }

  /* Add shred type specific items */
  switch( type ) {
  case FD_SHRED_TYPE_LEGACY_DATA:
  case FD_SHRED_TYPE_MERKLE_DATA: {
    /* Data shred headers */
    proto_tree_add_item( tshred, hf_data_parent_off,   tvb, offsetof( fd_shred_t, data.parent_off ), 2, ENC_LITTLE_ENDIAN );
    proto_tree_add_item( tshred, hf_data_end_of_slot,  tvb, offsetof( fd_shred_t, data.flags      ), 1, ENC_LITTLE_ENDIAN );
    proto_tree_add_item( tshred, hf_data_end_of_batch, tvb, offsetof( fd_shred_t, data.flags      ), 1, ENC_LITTLE_ENDIAN );
    proto_tree_add_item( tshred, hf_data_ref_tick,     tvb, offsetof( fd_shred_t, data.flags      ), 1, ENC_LITTLE_ENDIAN );
    proto_tree_add_item( tshred, hf_data_size,         tvb, offsetof( fd_shred_t, data.size       ), 2, ENC_LITTLE_ENDIAN );

    /* Bounds checks pre-reassembly */
    if( FD_UNLIKELY( header_sz>packet_sz ) ) return 0;
    uint actual_sz = tvb_get_letohs( tvb, offsetof( fd_shred_t, data.size ) );
    if( FD_UNLIKELY( actual_sz>packet_sz ) ) return 0;
    if( FD_UNLIKELY( actual_sz<header_sz ) ) return 0;

    col_add_fstr( pinfo->cinfo, COL_INFO, "Data Shred slot=%lu", tvb_get_letoh64( tvb, offsetof( fd_shred_t, slot ) ) );

    /* Register PDU item for fragment */
    int payload_sz = (int)(actual_sz - header_sz);
    proto_tree_add_bytes_format( tshred, hf_data_payload, tvb, FD_SHRED_DATA_HEADER_SZ,
                                 payload_sz, NULL,
                                 "Data Slice (%d byte%s)", payload_sz, plurality( payload_sz, "", "s" ) );
    bool end_of_batch = tvb_get_guint8( tvb, offsetof( fd_shred_t, data.flags ) ) & FD_SHRED_DATA_FLAG_FEC_SET_COMPLETE;

    /* Try to reassemble shred batch to entry batch */
    reassemble_turbine( tvb, pinfo, tree, (ushort)payload_sz, end_of_batch );

    return 1;
  }
  case FD_SHRED_TYPE_LEGACY_CODE:
  case FD_SHRED_TYPE_MERKLE_CODE: {
    /* Coding shred headers */
    proto_tree_add_item( tshred, hf_code_data_cnt, tvb, offsetof( fd_shred_t, code.data_cnt ), 2, ENC_LITTLE_ENDIAN );
    proto_tree_add_item( tshred, hf_code_code_cnt, tvb, offsetof( fd_shred_t, code.code_cnt ), 2, ENC_LITTLE_ENDIAN );
    proto_tree_add_item( tshred, hf_code_idx,      tvb, offsetof( fd_shred_t, code.idx      ), 2, ENC_LITTLE_ENDIAN );

    /* Bounds checks */
    int payload_sz = (int)(packet_sz - header_sz);
    if( FD_UNLIKELY( header_sz>packet_sz ) ) return 0;
    if( FD_UNLIKELY( payload_sz<0        ) ) return 0;

    col_add_fstr( pinfo->cinfo, COL_INFO, "Code Shred slot=%lu", tvb_get_letoh64( tvb, offsetof( fd_shred_t, slot ) ) );

    /* Add fragment to tree.
       Reassembly for now unsupported. */
    proto_tree_add_bytes_format( tshred, hf_code_payload, tvb, FD_SHRED_CODE_HEADER_SZ,
                                 payload_sz, NULL,
                                 "Reed-Solomon Parity Bits (%d byte%s)", payload_sz, plurality( payload_sz, "", "s" ) );
    return 1;
  }
  default:
    return 0;
  }
}

/* Registers the Turbine dissector functions with the protocol handle. */
void
proto_reg_handoff_turbine(void) {
  static dissector_handle_t turbine_handle FD_FN_UNUSED;

  /* Register dissector for unknown UDP port.
     The Turbine-assigned ports differ for each Solana node and are usually discovered via gossip. */
  turbine_handle = create_dissector_handle( dissect_turbine, proto_turbine );
  dissector_add_for_decode_as( "udp.port", turbine_handle );
}

/* This is the entrypoint called by the Wireshark host.
   Registers all protocols defined by this plugin. */
void
plugin_register( void ) {
  static proto_plugin plugin_turbine;
  plugin_turbine.register_protoinfo = proto_register_turbine;
  plugin_turbine.register_handoff   = proto_reg_handoff_turbine;
  proto_register_plugin( &plugin_turbine );
}

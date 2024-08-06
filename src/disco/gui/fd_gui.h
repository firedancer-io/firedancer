#ifndef HEADER_fd_src_disco_gui_fd_gui_h
#define HEADER_fd_src_disco_gui_fd_gui_h

#include "../fd_disco_base.h"

#include "../../ballet/http/fd_http_server.h"
#include "../../flamenco/types/fd_types.h"
#include "../../flamenco/leaders/fd_leaders.h"

#include "../topo/fd_topo.h"

#define MAX_SLOTS_CNT         432000UL
#define MAX_PUB_CNT           50000UL

struct fd_gui_gossip_peer {
  fd_pubkey_t pubkey[ 1 ];
  ulong       wallclock;
  ushort      shred_version;

  int has_version;
  struct {
    ushort major;
    ushort minor;
    ushort patch;

    int    has_commit;
    uint   commit;

    uint   feature_set;
  } version;

  struct {
    uint   ipv4;
    ushort port;
  } sockets[ 12 ];
};

struct fd_gui_vote_account {
  fd_pubkey_t pubkey[ 1 ];
  fd_pubkey_t vote_account[ 1 ];

  ulong       activated_stake;
  ulong       last_vote;
  ulong       root_slot;
  ulong       epoch_credits;
  uchar       commission;
  int         delinquent;
};

struct fd_gui_validator_info {
  fd_pubkey_t pubkey[ 1 ];

  char name[ 64 ];
  char website[ 128 ];
  char details[ 256 ];
  char icon_uri[ 128 ];
};

struct jsonb {
    char * buf;
    ulong  buf_sz;
    /* There is a NULL terminator, but this count doesn't include it. */
    ulong  cur_sz;
};

typedef struct jsonb jsonb_t;


#define JSONB_OK   (0UL)
#define JSONB_ERR  (1UL)

static FD_FN_UNUSED ulong
jsonb_new(jsonb_t * jsonb, void * buf, ulong sz) {
  FD_LOG_NOTICE(( "jsonb->buf_sz %lu", sz ));
  jsonb->buf_sz = sz;
  jsonb->cur_sz = 0;
  jsonb->buf = buf;
  return JSONB_OK;
}

static FD_FN_UNUSED ulong
jsonb_init(jsonb_t * jsonb) {
  jsonb->cur_sz = 0;
  jsonb->buf[0] = '\0';
  return JSONB_OK;
}

/* UB if !(cur_sz > 0) */
static FD_FN_UNUSED ulong
jsonb_fini(jsonb_t * jsonb) {
  if ( jsonb->buf[jsonb->cur_sz - 1] == ',' ) {
    jsonb->cur_sz--;
    jsonb->buf[jsonb->cur_sz] = '\0';
  }
  //TODO check matching parens
  return JSONB_OK;
}

// static FD_FN_UNUSED ulong
// jsonb_del(jsonb_t * jsonb) {
//   (void)jsonb;
//   return JSONB_OK;
// }

static FD_FN_UNUSED ulong
jsonb_open_obj(jsonb_t * jsonb, char const * key) {
  ulong tmp_len;
  int ret = 1;
  if ( key != NULL ) {
    ret = ret && fd_cstr_printf_check(jsonb->buf + jsonb->cur_sz, jsonb->buf_sz - jsonb->cur_sz, &tmp_len, "\"%s\":", key);
    jsonb->cur_sz += tmp_len;
  }
  ret = ret && fd_cstr_printf_check(jsonb->buf + jsonb->cur_sz, jsonb->buf_sz - jsonb->cur_sz, &tmp_len, "{");
  jsonb->cur_sz += tmp_len;

  return ret ? JSONB_OK : JSONB_ERR;
}

static FD_FN_UNUSED ulong
jsonb_close_obj(jsonb_t * jsonb) {
  ulong tmp_len;
  int ret = 1;
  if ( jsonb->buf[jsonb->cur_sz - 1] == ',' ) {
    jsonb->cur_sz--;
    jsonb->buf[jsonb->cur_sz] = '\0';
  }
  ret = ret && fd_cstr_printf_check(jsonb->buf + jsonb->cur_sz, jsonb->buf_sz - jsonb->cur_sz, &tmp_len, "},");
  jsonb->cur_sz += tmp_len;

  return ret ? JSONB_OK : JSONB_ERR;
}

static FD_FN_UNUSED ulong
jsonb_open_arr(jsonb_t * jsonb, char const * key) {
  ulong tmp_len;
  int ret = 1;
  if ( key != NULL ) {
    ret = ret && fd_cstr_printf_check(jsonb->buf + jsonb->cur_sz, jsonb->buf_sz - jsonb->cur_sz, &tmp_len, "\"%s\":", key);
    jsonb->cur_sz += tmp_len;
  }
  ret = ret && fd_cstr_printf_check(jsonb->buf + jsonb->cur_sz, jsonb->buf_sz - jsonb->cur_sz, &tmp_len, "[");
  jsonb->cur_sz += tmp_len;

  return ret ? JSONB_OK : JSONB_ERR;
}

static FD_FN_UNUSED ulong
jsonb_close_arr(jsonb_t * jsonb) {
  ulong tmp_len;
  int ret = 1;
  if ( jsonb->buf[jsonb->cur_sz - 1] == ',' ) {
    jsonb->cur_sz--;
    jsonb->buf[jsonb->cur_sz] = '\0';
  }
  ret = ret && fd_cstr_printf_check(jsonb->buf + jsonb->cur_sz, jsonb->buf_sz - jsonb->cur_sz, &tmp_len, "],");
  jsonb->cur_sz += tmp_len;

  return ret ? JSONB_OK : JSONB_ERR;
}

static FD_FN_UNUSED ulong
jsonb_ulong(jsonb_t * jsonb, char const * key, ulong val) {
  ulong tmp_len;
  int ret = 1;
  if ( key != NULL ) {
    ret = ret && fd_cstr_printf_check(jsonb->buf + jsonb->cur_sz, jsonb->buf_sz - jsonb->cur_sz, &tmp_len, "\"%s\":", key);
    jsonb->cur_sz += tmp_len;
  }
  ret = ret && fd_cstr_printf_check(jsonb->buf + jsonb->cur_sz, jsonb->buf_sz - jsonb->cur_sz, &tmp_len, "%lu,", val);
  jsonb->cur_sz += tmp_len;

  return ret ? JSONB_OK : JSONB_ERR;
}

static FD_FN_UNUSED ulong
jsonb_str(jsonb_t * jsonb, char const * key, char const * val) {
  ulong tmp_len;
  int ret = 1;
  if ( key != NULL ) {
    ret = ret && fd_cstr_printf_check(jsonb->buf + jsonb->cur_sz, jsonb->buf_sz - jsonb->cur_sz, &tmp_len, "\"%s\":", key);
    jsonb->cur_sz += tmp_len;
  }
  if( !val ) {
    ret = ret && fd_cstr_printf_check(jsonb->buf + jsonb->cur_sz, jsonb->buf_sz - jsonb->cur_sz, &tmp_len, "null,");
  } else {
    ret = ret && fd_cstr_printf_check(jsonb->buf + jsonb->cur_sz, jsonb->buf_sz - jsonb->cur_sz, &tmp_len, "\"%s\",", val);
    if( ret ) {
      // escape quotemark, reverse solidus, and control chars U+0000 through U+001F, just replace with a space
      for( ulong i=jsonb->cur_sz+1UL; i<jsonb->cur_sz+tmp_len-2UL; i++ ) {
        if( jsonb->buf[ i ] < 0x20 || jsonb->buf[ i ] == '"' || jsonb->buf[ i ] == '\\' ) {
          jsonb->buf[ i ] = ' ';
        }
      }
    }
  }
  jsonb->cur_sz += tmp_len;

  return ret ? JSONB_OK : JSONB_ERR;
}

static FD_FN_UNUSED ulong
jsonb_bool(jsonb_t * jsonb, char const * key, int val) {
  ulong tmp_len;
  int ret = 1;
  if ( key != NULL ) {
    ret = ret && fd_cstr_printf_check(jsonb->buf + jsonb->cur_sz, jsonb->buf_sz - jsonb->cur_sz, &tmp_len, "\"%s\":", key);
    jsonb->cur_sz += tmp_len;
  }
  ret = ret && fd_cstr_printf_check(jsonb->buf + jsonb->cur_sz, jsonb->buf_sz - jsonb->cur_sz, &tmp_len, "%s,", val ? "true" : "false");
  jsonb->cur_sz += tmp_len;

  return ret ? JSONB_OK : JSONB_ERR;
}


/* acquired_txns_leftover is a snapshot value at the beginning of a
   leader slot.
   buffered_txns is a point-in-time gauge value.
   Everything else comes from cumulative counters and we should take
   delats.
   acquired_txns has a base value of acquired_txns_leftover plus the
   deltas of everything else. */
struct fd_gui_txn_info {
  ulong acquired_txns;
  ulong acquired_txns_leftover;
  ulong acquired_txns_quic;
  ulong acquired_txns_nonquic;
  ulong acquired_txns_gossip;
  ulong dropped_txns;
  ulong dropped_txns_net_overrun;
  ulong dropped_txns_net_invalid;
  ulong dropped_txns_quic_overrun;
  ulong dropped_txns_quic_reasm;
  ulong dropped_txns_verify_overrun;
  ulong dropped_txns_verify_drop;
  ulong dropped_txns_dedup_drop;
  ulong dropped_txns_pack_nonleader;
  ulong dropped_txns_pack_invalid;
  ulong dropped_txns_pack_priority;
  ulong dropped_txns_bank_invalid;
  ulong executed_txns_failure;
  ulong executed_txns_success;
  ulong buffered_txns;
};

typedef struct fd_gui_txn_info fd_gui_txn_info_t;

struct fd_gui {
  fd_http_server_t * server;

  fd_alloc_t * alloc;

  fd_topo_t * topo;

  struct {
    char const * version;        
    char const * cluster;
    char const * identity_key_base58;

    ulong slot_rooted;
    ulong slot_optimistically_confirmed;
    ulong slot_completed;
    ulong slot_estimated;

    fd_gui_txn_info_t txn_info_prev[ 1 ]; /* Cumulative/Sampled */
    fd_gui_txn_info_t txn_info_this[ 1 ]; /* Cumulative/Sampled */
    fd_gui_txn_info_t txn_info_json[ 1 ]; /* Delta/Computed */
    long              last_txn_ts;
  } summary;

  struct {
#define FD_GUI_NUM_EPOCHS 2UL
    struct {
      ulong epoch;
      ulong start_slot;
      ulong end_slot;
      ulong excluded_stake;
      fd_epoch_leaders_t * lsched;
      uchar __attribute__((aligned(FD_EPOCH_LEADERS_ALIGN))) _lsched[ FD_EPOCH_LEADERS_FOOTPRINT(MAX_PUB_CNT, MAX_SLOTS_CNT) ];
      fd_stake_weight_t stakes[ MAX_PUB_CNT ];
    } epochs[ FD_GUI_NUM_EPOCHS ];
    ulong max_known_epoch;
  } epoch;

  struct {
    ulong                     peer_cnt;
    struct fd_gui_gossip_peer peers[ 40200 ];
  } gossip;

  struct {
    ulong                      vote_account_cnt;
    struct fd_gui_vote_account vote_accounts[ 40200 ];
  } vote_account;

  struct {
    ulong info_cnt;
    struct fd_gui_validator_info info[ 40200 ];
  } validator_info;

#define FD_GUI_JSON_BUF_SIZE (8192UL * 1024UL)
  jsonb_t jsonb[ 1 ];
  char    json_buf[ FD_GUI_JSON_BUF_SIZE ];
};

typedef struct fd_gui fd_gui_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_gui_align( void );

FD_FN_CONST ulong
fd_gui_footprint( void );

void *
fd_gui_new( void *             shmem,
            fd_http_server_t * server,
            fd_alloc_t *       alloc,
            char const *       version,
            char const *       cluster,
            char const *       identity_key_base58,
            fd_topo_t *        topo );

fd_gui_t *
fd_gui_join( void * shmem );

void
fd_gui_ws_open( fd_gui_t *  gui,
                ulong       conn_id );

void
fd_gui_plugin_message( fd_gui_t *    gui,
                       ulong         plugin_msg,
                       uchar const * msg,
                       ulong         msg_len );

void
fd_gui_poll( fd_gui_t * gui );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_gui_fd_gui_h */

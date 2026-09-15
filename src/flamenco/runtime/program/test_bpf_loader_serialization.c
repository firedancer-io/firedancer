#include "fd_bpf_loader_serialization.h"
#include "../fd_runtime.h"
#include "../fd_bank.h"
#include "../tests/fd_svm_mini.h"
#include "../../accdb/fd_accdb.h"
#include "../../fd_flamenco_base.h"
#include "../../../ballet/base64/fd_base64.h"
#include "../../../ballet/json/fd_jtok.h"
#include <stdio.h>

#define MM_INPUT_START 0x400000000UL

struct fixture_account {
  fd_pubkey_t pubkey;
  fd_pubkey_t owner;
  uchar *     data;
  ulong       data_len;
  ulong       lamports;
  ulong       rent_epoch;
  uchar       executable;
};
typedef struct fixture_account fixture_account_t;

struct fixture_instr_account {
  ushort index_in_transaction;
  uchar  is_signer;
  uchar  is_writable;
};
typedef struct fixture_instr_account fixture_instr_account_t;

struct fixture_region {
  uchar * data;
  ulong   data_len;
  ulong   vm_addr;
  uchar   is_writable;
};
typedef struct fixture_region fixture_region_t;

struct fixture_acc_meta {
  ulong original_data_len;
  ulong vm_addr;
  int   vm_addr_present;
  ulong vm_key_addr;
  ulong vm_lamports_addr;
  ulong vm_owner_addr;
  ulong vm_data_addr;
};
typedef struct fixture_acc_meta fixture_acc_meta_t;

struct fixture_input {
  char *                    name;
  fixture_account_t *       accounts;
  fixture_instr_account_t * instr_accounts;
  uchar *                   instr_data;
  ulong                     num_accounts;
  ulong                     num_instr_accounts;
  ulong                     instr_data_len;
  fd_pubkey_t               program_id;
  uchar                     virtual_address_space_adj;
  uchar                     direct_mapping;
  uchar                     direct_account_pointers_in_program_input;
  uchar                     is_deprecated;
};
typedef struct fixture_input fixture_input_t;

struct fixture_output {
  uchar *              buffer;
  fixture_region_t *   regions;
  fixture_acc_meta_t * acc_metas;
  ulong                buffer_len;
  ulong                num_regions;
  ulong                num_acc_metas;
  ulong                instr_data_offset;
  int                  result;
};
typedef struct fixture_output fixture_output_t;

struct fixture {
  fixture_input_t  input;
  fixture_output_t output;
};
typedef struct fixture fixture_t;

static int
check_result( int got, int expected ) {
  if( got!=expected ) {
    FD_LOG_WARNING(( "result mismatch: got %d, expected %d", got, expected ));
    return 0;
  }
  return 1;
}

static int
check_buffer( uchar const * got,
              ulong         got_len,
              uchar const * expected,
              ulong         expected_len ) {
  if( got_len!=expected_len ) {
    FD_LOG_WARNING(( "buffer size mismatch: got %lu, expected %lu", got_len, expected_len ));
    return 0;
  }
  if( got_len && !fd_memeq( got, expected, got_len ) ) {
    for( ulong i=0UL; i<got_len; i++ ) {
      if( got[i]!=expected[i] ) {
        FD_LOG_WARNING(( "buffer mismatch at offset %lu: got 0x%02x, expected 0x%02x", i, got[i], expected[i] ));
        break;
      }
    }
    return 0;
  }
  return 1;
}

static int
check_region( fd_vm_input_region_t const * got,
              fixture_region_t const *     expected,
              uint                         idx ) {
  ulong expected_offset = expected->vm_addr - MM_INPUT_START;

  if( got->vaddr_offset!=expected_offset ) {
    FD_LOG_WARNING(( "region[%u] vaddr_offset: got %lu, expected %lu", idx, got->vaddr_offset, expected_offset ));
    return 0;
  }
  if( got->is_writable!=expected->is_writable ) {
    FD_LOG_WARNING(( "region[%u] is_writable: got %d, expected %d", idx, got->is_writable, expected->is_writable ));
    return 0;
  }
  if( got->region_sz!=expected->data_len ) {
    FD_LOG_WARNING(( "region[%u] size: got %u, expected %lu", idx, got->region_sz, expected->data_len ));
    return 0;
  }
  if( got->haddr && expected->data && !fd_memeq( (void*)got->haddr, expected->data, expected->data_len ) ) {
    FD_LOG_WARNING(( "region[%u] data mismatch", idx ));
    return 0;
  }
  return 1;
}

static int
check_acc_meta( fd_vm_acc_region_meta_t const * got,
                fixture_acc_meta_t const *      expected,
                ulong                           idx ) {
  if( got->original_data_len!=expected->original_data_len ) {
    FD_LOG_WARNING(( "acc_meta[%lu] original_data_len: got %lu, expected %lu", idx, got->original_data_len, expected->original_data_len ));
    return 0;
  }
  if( expected->vm_addr_present && got->vm_addr!=expected->vm_addr ) {
    FD_LOG_WARNING(( "acc_meta[%lu] vm_addr: got %lu, expected %lu", idx, got->vm_addr, expected->vm_addr ));
    return 0;
  }
  if( got->vm_key_addr!=expected->vm_key_addr ) {
    FD_LOG_WARNING(( "acc_meta[%lu] vm_key_addr: got %lu, expected %lu", idx, got->vm_key_addr, expected->vm_key_addr ));
    return 0;
  }
  if( got->vm_lamports_addr!=expected->vm_lamports_addr ) {
    FD_LOG_WARNING(( "acc_meta[%lu] vm_lamports_addr: got %lu, expected %lu", idx, got->vm_lamports_addr, expected->vm_lamports_addr ));
    return 0;
  }
  if( got->vm_owner_addr!=expected->vm_owner_addr ) {
    FD_LOG_WARNING(( "acc_meta[%lu] vm_owner_addr: got %lu, expected %lu", idx, got->vm_owner_addr, expected->vm_owner_addr ));
    return 0;
  }
  if( got->vm_data_addr!=expected->vm_data_addr ) {
    FD_LOG_WARNING(( "acc_meta[%lu] vm_data_addr: got %lu, expected %lu", idx, got->vm_data_addr, expected->vm_data_addr ));
    return 0;
  }
  return 1;
}

static uchar *
read_file( fd_alloc_t * alloc, char const * path, ulong * out_sz ) {
  FILE * f = fopen( path, "rb" );
  if( FD_UNLIKELY( !f ) ) return NULL;

  fseek( f, 0, SEEK_END );
  long sz = ftell( f );
  fseek( f, 0, SEEK_SET );

  uchar * buf = fd_alloc_malloc( alloc, 1UL, (ulong)sz + 1UL );
  if( FD_UNLIKELY( !buf ) ) { fclose( f ); return NULL; }

  if( FD_UNLIKELY( fread( buf, 1, (ulong)sz, f )!=(ulong)sz ) ) {
    fclose( f );
    fd_alloc_free( alloc, buf );
    return NULL;
  }
  buf[sz] = '\0';
  fclose( f );
  *out_sz = (ulong)sz;
  return buf;
}

static uchar b64_scratch[ 128UL<<10 ];
static ulong b64_scratch_used;

/* b64_decode consumes the pending base64 string, decodes it into
   b64_scratch and stores it in *out / *out_len.  An empty string
   yields NULL / 0.  Returns 0 on success, -1 on failure. */

static int
b64_decode( fd_jtok_t * j,
            uchar **    out,
            ulong *     out_len ) {
  fd_jtok_str_t v = { NULL, 0UL };
  fd_jtok_str( j, &v );
  if( FD_UNLIKELY( fd_jtok_err( j ) ) ) return -1;
  if( FD_UNLIKELY( memchr( v.ptr, '\\', v.sz ) ) ) return -1;
  if( !v.sz ) { *out = NULL; *out_len = 0UL; return 0; }
  if( FD_UNLIKELY( FD_BASE64_DEC_SZ( v.sz ) > sizeof(b64_scratch)-b64_scratch_used ) ) return -1;
  uchar * buf = b64_scratch + b64_scratch_used;
  long len = fd_base64_decode( buf, v.ptr, v.sz );
  if( FD_UNLIKELY( len<0L ) ) return -1;
  b64_scratch_used += (ulong)len;
  *out     = buf;
  *out_len = (ulong)len;
  return 0;
}

/* b64_pubkey consumes the pending base64 string which must decode to
   exactly 32 bytes.  Returns 0 on success, -1 on failure. */

static int
b64_pubkey( fd_jtok_t *   j,
            fd_pubkey_t * out ) {
  uchar * buf = NULL; ulong len = 0UL;
  if( FD_UNLIKELY( b64_decode( j, &buf, &len ) || len!=32UL ) ) return -1;
  fd_memcpy( out->key, buf, 32UL );
  return 0;
}

static int
parse_bool( fd_jtok_t * j,
            uchar *     out ) {
  int b = 0;
  fd_jtok_bool( j, &b );
  *out = (uchar)b;
  return fd_jtok_err( j ) ? -1 : 0;
}

/* alloc_arr consumes the pending array from j, allocates one zeroed
   el_sz byte element per array entry (NULL if the array is empty) and
   re-tokenizes the array with j2, which is left positioned inside it
   ready for fd_jtok_arr_next.  Stores the allocation in *out_arr and
   the element count in *out_cnt.  Returns 0 on success, -1 on
   failure. */

static int
alloc_arr( fd_alloc_t * alloc,
           fd_jtok_t *  j,
           fd_jtok_t *  j2,
           ulong        el_align,
           ulong        el_sz,
           void *       out_arr,
           ulong *      out_cnt ) {
  char const * raw = NULL; ulong raw_sz = 0UL;
  fd_jtok_raw( j, &raw, &raw_sz );
  if( FD_UNLIKELY( fd_jtok_err( j ) ) ) return -1;

  ulong cnt = 0UL;
  fd_jtok_init( j2, raw, raw_sz );
  fd_jtok_arr_enter( j2 );
  while( fd_jtok_arr_next( j2 ) ) cnt++;
  if( FD_UNLIKELY( fd_jtok_fini( j2 ) ) ) return -1;

  void * arr = NULL;
  if( cnt ) {
    arr = fd_alloc_malloc( alloc, el_align, el_sz * cnt );
    if( FD_UNLIKELY( !arr ) ) return -1;
    fd_memset( arr, 0, el_sz * cnt );
  }

  fd_jtok_init( j2, raw, raw_sz );
  fd_jtok_arr_enter( j2 );
  *(void **)out_arr = arr;
  *out_cnt          = cnt;
  return 0;
}

static int
parse_accounts( fd_alloc_t *      alloc,
                fd_jtok_t *       j,
                fixture_input_t * in ) {
  fd_jtok_t j2[1];
  if( FD_UNLIKELY( alloc_arr( alloc, j, j2, alignof(fixture_account_t), sizeof(fixture_account_t), &in->accounts, &in->num_accounts ) ) ) return -1;
  for( ulong i=0UL; fd_jtok_arr_next( j2 ); i++ ) {
    fixture_account_t * a = &in->accounts[i];
    fd_jtok_str_t k;
    fd_jtok_obj_enter( j2 );
    while( fd_jtok_obj_next( j2, &k ) ) {
      if(      fd_jtok_str_eq( &k, "pubkey"     ) ) { if( FD_UNLIKELY( b64_pubkey( j2, &a->pubkey ) ) ) return -1; }
      else if( fd_jtok_str_eq( &k, "owner"      ) ) { if( FD_UNLIKELY( b64_pubkey( j2, &a->owner  ) ) ) return -1; }
      else if( fd_jtok_str_eq( &k, "lamports"   ) ) fd_jtok_ulong( j2, &a->lamports   );
      else if( fd_jtok_str_eq( &k, "rent_epoch" ) ) fd_jtok_ulong( j2, &a->rent_epoch );
      else if( fd_jtok_str_eq( &k, "executable" ) ) { if( FD_UNLIKELY( parse_bool( j2, &a->executable ) ) ) return -1; }
      else if( fd_jtok_str_eq( &k, "data"       ) ) { if( FD_UNLIKELY( b64_decode( j2, &a->data, &a->data_len ) ) ) return -1; }
    }
  }
  return fd_jtok_fini( j2 ) ? -1 : 0;
}

static int
parse_instr_accounts( fd_alloc_t *      alloc,
                      fd_jtok_t *       j,
                      fixture_input_t * in ) {
  fd_jtok_t j2[1];
  if( FD_UNLIKELY( alloc_arr( alloc, j, j2, alignof(fixture_instr_account_t), sizeof(fixture_instr_account_t), &in->instr_accounts, &in->num_instr_accounts ) ) ) return -1;
  for( ulong i=0UL; fd_jtok_arr_next( j2 ); i++ ) {
    fixture_instr_account_t * ia = &in->instr_accounts[i];
    fd_jtok_str_t k;
    fd_jtok_obj_enter( j2 );
    while( fd_jtok_obj_next( j2, &k ) ) {
      if( fd_jtok_str_eq( &k, "index_in_transaction" ) ) {
        ulong idx = 0UL;
        fd_jtok_ulong( j2, &idx );
        if( FD_UNLIKELY( idx>USHORT_MAX ) ) return -1;
        ia->index_in_transaction = (ushort)idx;
      }
      else if( fd_jtok_str_eq( &k, "is_signer"   ) ) { if( FD_UNLIKELY( parse_bool( j2, &ia->is_signer   ) ) ) return -1; }
      else if( fd_jtok_str_eq( &k, "is_writable" ) ) { if( FD_UNLIKELY( parse_bool( j2, &ia->is_writable ) ) ) return -1; }
    }
  }
  return fd_jtok_fini( j2 ) ? -1 : 0;
}

static int
parse_input( fd_alloc_t *      alloc,
             fd_jtok_t *       j,
             fixture_input_t * in ) {
  fd_jtok_str_t k;
  fd_jtok_obj_enter( j );
  while( fd_jtok_obj_next( j, &k ) ) {
    if(      fd_jtok_str_eq( &k, "accounts"             ) ) { if( FD_UNLIKELY( parse_accounts      ( alloc, j, in ) ) ) return -1; }
    else if( fd_jtok_str_eq( &k, "instruction_accounts" ) ) { if( FD_UNLIKELY( parse_instr_accounts( alloc, j, in ) ) ) return -1; }
    else if( fd_jtok_str_eq( &k, "instruction_data"     ) ) { if( FD_UNLIKELY( b64_decode( j, &in->instr_data, &in->instr_data_len ) ) ) return -1; }
    else if( fd_jtok_str_eq( &k, "program_id"           ) ) { if( FD_UNLIKELY( b64_pubkey( j, &in->program_id ) ) ) return -1; }
    else if( fd_jtok_str_eq( &k, "virtual_address_space_adjustments"        ) ) { if( FD_UNLIKELY( parse_bool( j, &in->virtual_address_space_adj                ) ) ) return -1; }
    else if( fd_jtok_str_eq( &k, "account_data_direct_mapping"              ) ) { if( FD_UNLIKELY( parse_bool( j, &in->direct_mapping                           ) ) ) return -1; }
    else if( fd_jtok_str_eq( &k, "direct_account_pointers_in_program_input" ) ) { if( FD_UNLIKELY( parse_bool( j, &in->direct_account_pointers_in_program_input ) ) ) return -1; }
    else if( fd_jtok_str_eq( &k, "is_deprecated_loader"                     ) ) { if( FD_UNLIKELY( parse_bool( j, &in->is_deprecated                            ) ) ) return -1; }
  }
  return fd_jtok_err( j ) ? -1 : 0;
}

static int
parse_regions( fd_alloc_t *       alloc,
               fd_jtok_t *        j,
               fixture_output_t * out ) {
  fd_jtok_t j2[1];
  if( FD_UNLIKELY( alloc_arr( alloc, j, j2, alignof(fixture_region_t), sizeof(fixture_region_t), &out->regions, &out->num_regions ) ) ) return -1;
  for( ulong i=0UL; fd_jtok_arr_next( j2 ); i++ ) {
    fixture_region_t * reg = &out->regions[i];
    fd_jtok_str_t k;
    fd_jtok_obj_enter( j2 );
    while( fd_jtok_obj_next( j2, &k ) ) {
      if(      fd_jtok_str_eq( &k, "vm_addr"     ) ) fd_jtok_ulong( j2, &reg->vm_addr );
      else if( fd_jtok_str_eq( &k, "is_writable" ) ) { if( FD_UNLIKELY( parse_bool( j2, &reg->is_writable ) ) ) return -1; }
      else if( fd_jtok_str_eq( &k, "data"        ) ) { if( FD_UNLIKELY( b64_decode( j2, &reg->data, &reg->data_len ) ) ) return -1; }
    }
  }
  return fd_jtok_fini( j2 ) ? -1 : 0;
}

static int
parse_acc_metas( fd_alloc_t *       alloc,
                 fd_jtok_t *        j,
                 fixture_output_t * out ) {
  fd_jtok_t j2[1];
  if( FD_UNLIKELY( alloc_arr( alloc, j, j2, alignof(fixture_acc_meta_t), sizeof(fixture_acc_meta_t), &out->acc_metas, &out->num_acc_metas ) ) ) return -1;
  for( ulong i=0UL; fd_jtok_arr_next( j2 ); i++ ) {
    fixture_acc_meta_t * m = &out->acc_metas[i];
    fd_jtok_str_t k;
    fd_jtok_obj_enter( j2 );
    while( fd_jtok_obj_next( j2, &k ) ) {
      if(      fd_jtok_str_eq( &k, "original_data_len" ) ) fd_jtok_ulong( j2, &m->original_data_len );
      else if( fd_jtok_str_eq( &k, "vm_key_addr"       ) ) fd_jtok_ulong( j2, &m->vm_key_addr       );
      else if( fd_jtok_str_eq( &k, "vm_lamports_addr"  ) ) fd_jtok_ulong( j2, &m->vm_lamports_addr  );
      else if( fd_jtok_str_eq( &k, "vm_owner_addr"     ) ) fd_jtok_ulong( j2, &m->vm_owner_addr     );
      else if( fd_jtok_str_eq( &k, "vm_data_addr"      ) ) fd_jtok_ulong( j2, &m->vm_data_addr      );
      else if( fd_jtok_str_eq( &k, "vm_addr"           ) ) { fd_jtok_ulong( j2, &m->vm_addr ); m->vm_addr_present = 1; }
    }
  }
  return fd_jtok_fini( j2 ) ? -1 : 0;
}

static int
parse_output( fd_alloc_t *       alloc,
              fd_jtok_t *        j,
              fixture_output_t * out ) {
  fd_jtok_str_t k;
  fd_jtok_obj_enter( j );
  while( fd_jtok_obj_next( j, &k ) ) {
    if( fd_jtok_str_eq( &k, "result" ) ) {
      long result = 0L;
      fd_jtok_long( j, &result );
      if( FD_UNLIKELY( result<INT_MIN || result>INT_MAX ) ) return -1;
      out->result = (int)result;
    }
    else if( fd_jtok_str_eq( &k, "buffer"                  ) ) { if( FD_UNLIKELY( b64_decode( j, &out->buffer, &out->buffer_len ) ) ) return -1; }
    else if( fd_jtok_str_eq( &k, "regions"                 ) ) { if( FD_UNLIKELY( parse_regions  ( alloc, j, out ) ) ) return -1; }
    else if( fd_jtok_str_eq( &k, "accounts_metadata"       ) ) { if( FD_UNLIKELY( parse_acc_metas( alloc, j, out ) ) ) return -1; }
    else if( fd_jtok_str_eq( &k, "instruction_data_offset" ) ) fd_jtok_ulong( j, &out->instr_data_offset );
  }
  return fd_jtok_err( j ) ? -1 : 0;
}

/* parse_fixture consumes the pending fixture object from j into fix.
   Returns 0 on success, -1 on failure. */

static int
parse_fixture( fd_alloc_t * alloc,
               fd_jtok_t *  j,
               fixture_t *  fix ) {
  fixture_input_t *  in  = &fix->input;
  fixture_output_t * out = &fix->output;
  int has_name = 0;

  fd_jtok_str_t k;
  fd_jtok_obj_enter( j );
  while( fd_jtok_obj_next( j, &k ) ) {
    if( fd_jtok_str_eq( &k, "name" ) ) {
      fd_jtok_str_t v = { NULL, 0UL };
      fd_jtok_str( j, &v );
      if( FD_UNLIKELY( fd_jtok_err( j ) ) ) return -1;
      in->name = fd_alloc_malloc( alloc, 1UL, v.sz + 1UL );
      if( FD_UNLIKELY( !in->name ) ) return -1;
      fd_memcpy( in->name, v.ptr, v.sz );
      in->name[ v.sz ] = '\0';
      has_name = 1;
    }
    else if( fd_jtok_str_eq( &k, "input"  ) ) { if( FD_UNLIKELY( parse_input ( alloc, j, in  ) ) ) return -1; }
    else if( fd_jtok_str_eq( &k, "output" ) ) { if( FD_UNLIKELY( parse_output( alloc, j, out ) ) ) return -1; }
  }
  if( FD_UNLIKELY( fd_jtok_err( j ) || !has_name ) ) return -1;

  if( out->result!=0 ) {
    out->buffer        = NULL;
    out->buffer_len    = 0UL;
    out->regions       = NULL;
    out->num_regions   = 0UL;
    out->acc_metas     = NULL;
    out->num_acc_metas = 0UL;
  }
  return 0;
}

static int
find_program_index( fixture_input_t const * in ) {
  for( ulong i=0; i<in->num_accounts; i++ ) {
    if( fd_memeq( in->accounts[i].pubkey.key, in->program_id.key, 32 ) ) return (int)i;
  }
  return -1;
}

/* Per-fixture context: txn_out is huge (10MB nonce_rollback_data buffer),
   so allocate via static. */
static fd_txn_in_t     g_txn_in[1];
static fd_txn_out_t    g_txn_out[1];
static fd_instr_info_t g_info[1];

static void
setup_instr_ctx( fixture_input_t const * in,
                 int                     program_idx,
                 fd_svm_mini_t *         mini,
                 fd_alloc_t *            alloc,
                 uchar ***               out_storage,
                 fd_exec_instr_ctx_t *   instr_ctx ) {

  fd_runtime_t * runtime = mini->runtime;

  /* Allocate per-account data buffers (lifetime: until cleanup_instr_ctx) */
  uchar ** storage = fd_alloc_malloc( alloc, alignof(uchar*), sizeof(uchar*) * (in->num_accounts ? in->num_accounts : 1UL) );
  FD_TEST( storage );

  fd_memset( g_txn_in,  0, sizeof(g_txn_in)  );
  fd_memset( g_txn_out, 0, sizeof(g_txn_out) );
  fd_memset( g_info,    0, sizeof(g_info)    );
  fd_memset( g_txn_out->accounts.keys,  0, sizeof(fd_pubkey_t)*MAX_TX_ACCOUNT_LOCKS );
  fd_memset( runtime->accounts.account, 0, sizeof(fd_acc_t)*MAX_TX_ACCOUNT_LOCKS );
  for( ulong i=0UL; i<MAX_TX_ACCOUNT_LOCKS; i++ ) {
    g_txn_out->accounts.account[i] = &runtime->accounts.account[ i ];
  }

  g_txn_out->accounts.cnt = in->num_accounts;

  for( ulong i=0UL; i<in->num_accounts; i++ ) {
    ulong dlen = in->accounts[i].data_len;
    uchar * data_buf = fd_alloc_malloc( alloc, FD_ACCOUNT_REC_ALIGN, dlen ? dlen : 1UL );
    FD_TEST( data_buf );
    if( dlen ) fd_memcpy( data_buf, in->accounts[i].data, dlen );
    storage[i] = data_buf;

    fd_acc_t * acc = g_txn_out->accounts.account[i];
    fd_memset( acc, 0, sizeof(*acc) );
    memcpy( acc->pubkey, in->accounts[i].pubkey.key, 32 );
    memcpy( acc->owner,  in->accounts[i].owner.key,  32 );
    acc->lamports   = in->accounts[i].lamports;
    acc->executable = in->accounts[i].executable;
    acc->data_len   = (uint)dlen;
    acc->data       = data_buf;
    acc->_writable  = 1;
    g_txn_out->accounts.is_writable[i] = 1U;
    acc->commit     = 0;

    memcpy( g_txn_out->accounts.keys[i].key, in->accounts[i].pubkey.key, 32 );

    runtime->accounts.refcnt[i] = 0UL;
  }

  g_info->program_id = (uchar)program_idx;
  if( in->instr_data_len ) fd_memcpy( g_info->data, in->instr_data, in->instr_data_len );
  g_info->data_sz  = (ushort)in->instr_data_len;
  g_info->acct_cnt = (ushort)in->num_instr_accounts;

  uchar seen[FD_TXN_ACCT_ADDR_MAX] = {0};
  for( ulong i=0UL; i<in->num_instr_accounts; i++ ) {
    fd_instr_info_setup_instr_account( g_info,
                                       seen,
                                       in->instr_accounts[i].index_in_transaction,
                                       (ushort)i,
                                       (ushort)i,
                                       in->instr_accounts[i].is_writable,
                                       in->instr_accounts[i].is_signer );
  }

  /* This test calls fd_bpf_loader_input_serialize_parameters directly,
     bypassing fd_instr_stack_push.  The serializer reads stack_sz to
     index the per-frame serialization scratch buffer, so set it to 1. */
  runtime->instr.stack_sz = 1;

  fd_memset( instr_ctx, 0, sizeof(fd_exec_instr_ctx_t) );
  instr_ctx->instr   = g_info;
  instr_ctx->txn_in  = g_txn_in;
  instr_ctx->txn_out = g_txn_out;
  instr_ctx->runtime = runtime;

  *out_storage = storage;
}

static void
cleanup_instr_ctx( fixture_input_t const * in,
                   fd_alloc_t *            alloc,
                   uchar **                storage ) {
  for( ulong i=0UL; i<in->num_accounts; i++ ) {
    fd_alloc_free( alloc, storage[i] );
  }
  fd_alloc_free( alloc, storage );
}

static int
run_fixture( fd_svm_mini_t * mini,
             fd_alloc_t *    alloc,
             fixture_t *     fix ) {

  fixture_input_t *  in  = &fix->input;
  fixture_output_t * out = &fix->output;

  int program_idx = find_program_index( in );
  FD_TEST( program_idx>=0 );

  FD_LOG_NOTICE(( "  %s: %lu accounts, virtual_address_space_adj=%d, direct_mapping=%d, direct_account_pointers=%d, is_deprecated=%d",
                  in->name, in->num_accounts, in->virtual_address_space_adj, in->direct_mapping,
                  in->direct_account_pointers_in_program_input, in->is_deprecated ));

  uchar **            storage = NULL;
  fd_exec_instr_ctx_t ctx[1];
  setup_instr_ctx( in, program_idx, mini, alloc, &storage, ctx );

  ulong                   serialized_sz = 0;
  ulong                   pre_lens[FD_TXN_INSTR_ACCT_MAX];
  fd_vm_input_region_t    regions[1000];
  uint                    region_cnt = 0;
  fd_vm_acc_region_meta_t acc_metas[FD_TXN_INSTR_ACCT_MAX];
  ulong                   idata_offset = 0;

  fd_memset( pre_lens,  0, sizeof(pre_lens)  );
  fd_memset( regions,   0, sizeof(regions)   );
  fd_memset( acc_metas, 0, sizeof(acc_metas) );

  uchar * serialized = ctx->runtime->bpf_loader_serialization.serialization_mem[ ctx->runtime->instr.stack_sz-1UL ];

  int result = fd_bpf_loader_input_serialize_parameters(
      ctx, pre_lens, regions, &region_cnt, acc_metas,
      in->virtual_address_space_adj, in->direct_mapping,
      in->direct_account_pointers_in_program_input,
      in->is_deprecated,
      &idata_offset, &serialized_sz );

  FD_LOG_NOTICE(( "  result=%d serialized_sz=%lu region_cnt=%u idata_offset=%lu",
                  result, serialized_sz, region_cnt, idata_offset ));

  int ok = 1;

  if( out->result==0 ) {
    if( !check_result( result, 0 ) ) ok = 0;
    else if( !check_buffer( serialized, serialized_sz, out->buffer, out->buffer_len ) ) ok = 0;
    else if( region_cnt!=out->num_regions ) {
      FD_LOG_WARNING(( "region count: got %u, expected %lu", region_cnt, out->num_regions ));
      ok = 0;
    }
    else if( idata_offset!=out->instr_data_offset ) {
      FD_LOG_WARNING(( "instr_data_offset: got %lu, expected %lu", idata_offset, out->instr_data_offset ));
      ok = 0;
    }
    else {
      for( uint i=0; i<region_cnt; i++ ) {
        if( !check_region( &regions[i], &out->regions[i], i ) ) { ok = 0; break; }
      }
      if( ok ) {
        for( ulong i=0; i<out->num_acc_metas; i++ ) {
          if( !check_acc_meta( &acc_metas[i], &out->acc_metas[i], i ) ) { ok = 0; break; }
        }
      }
    }
  } else {
    if( result==0 ) {
      FD_LOG_WARNING(( "expected error %d but got success", out->result ));
      ok = 0;
    }
  }

  cleanup_instr_ctx( in, alloc, storage );

  return ok ? 0 : -1;
}

int
main( int argc, char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );

  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  ulong root_idx = fd_svm_mini_reset( mini, params );
  fd_bank_t * bank = fd_svm_mini_bank( mini, root_idx );
  fd_features_disable_all( &bank->f.features );
  FD_FEATURE_SET_ACTIVE( &bank->f.features, remove_accounts_executable_flag_checks, 0UL );

  /* Stand up a private wksp and fd_alloc for fixture data — the
     multi-MB JSON file plus per-fixture buffers don't fit in the svm_mini
     wksp, which is sized exactly for runtime objects. */
  fd_wksp_t * fix_wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 16384UL,
                                                fd_shmem_cpu_idx( 0UL ), "fix_wksp", 0UL );
  FD_TEST( fix_wksp );
  void * alloc_mem = fd_wksp_alloc_laddr( fix_wksp, fd_alloc_align(), fd_alloc_footprint(), 99UL );
  FD_TEST( alloc_mem );
  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( alloc_mem, 99UL ), 0UL );
  FD_TEST( alloc );

  char const * fixtures_path = "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures.json";
  FD_LOG_NOTICE(( "Loading fixtures from: %s", fixtures_path ));

  ulong   sz   = 0;
  uchar * data = read_file( alloc, fixtures_path, &sz );
  if( FD_UNLIKELY( !data ) ) {
    FD_LOG_ERR(( "Failed to read fixtures file: %s", fixtures_path ));
  }

  fd_jtok_t j[1]; fd_jtok_init( j, data, sz );
  fd_jtok_arr_enter( j );
  if( FD_UNLIKELY( fd_jtok_err( j ) ) ) {
    FD_LOG_ERR(( "Failed to parse fixtures file as JSON array" ));
  }

  ulong fixture_cnt = 0UL;
  while( fd_jtok_arr_next( j ) ) {
    fixture_t fix[1];
    fd_memset( fix, 0, sizeof(fixture_t) );
    b64_scratch_used = 0UL;
    if( FD_UNLIKELY( parse_fixture( alloc, j, fix ) ) ) {
      FD_LOG_ERR(( "Failed to parse fixture %lu (json err %d at offset %lu)", fixture_cnt, fd_jtok_err( j ), fd_jtok_err_off( j ) ));
    }
    fixture_cnt++;

    FD_LOG_NOTICE(( "Testing: %s", fix->input.name ));
    int result = run_fixture( mini, alloc, fix );

    if( result==0 ) {
      FD_LOG_NOTICE(( "  PASS" ));
    } else {
      FD_LOG_ERR(( "  FAIL" ));
    }
  }
  if( FD_UNLIKELY( fd_jtok_fini( j ) ) ) {
    FD_LOG_ERR(( "Failed to parse fixtures file (json err %d at offset %lu)", fd_jtok_err( j ), fd_jtok_err_off( j ) ));
  }
  FD_LOG_NOTICE(( "Ran %lu fixtures", fixture_cnt ));

  fd_alloc_free( alloc, data );
  fd_wksp_free_laddr( fd_alloc_delete( fd_alloc_leave( alloc ) ) );
  fd_wksp_delete_anonymous( fix_wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}

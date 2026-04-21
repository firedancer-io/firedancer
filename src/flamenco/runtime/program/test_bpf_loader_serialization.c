#include "fd_bpf_loader_serialization.h"
#include "../fd_runtime.h"
#include "../fd_bank.h"
#include "../tests/fd_svm_mini.h"
#include "../../accdb/fd_accdb.h"
#include "../../fd_flamenco_base.h"
#include "../../../ballet/json/cJSON.h"
#include "../../../ballet/json/cJSON_alloc.h"
#include "../../../ballet/base64/fd_base64.h"
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

static long
decode_base64( char const * str, uchar * out, ulong out_max ) {
  if( FD_UNLIKELY( !str || !out ) ) return -1;
  ulong len = strlen( str );
  if( !len ) return 0;
  long decoded = fd_base64_decode( out, str, len );
  if( FD_UNLIKELY( decoded<0 || (ulong)decoded>out_max ) ) return -1;
  return decoded;
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

static int
parse_fixture( fd_alloc_t * alloc, char const * json_str, fixture_t * fix ) {
  cJSON * root = cJSON_Parse( json_str );
  if( FD_UNLIKELY( !root ) ) return -1;

  fixture_input_t *  in  = &fix->input;
  fixture_output_t * out = &fix->output;

  cJSON * name = cJSON_GetObjectItemCaseSensitive( root, "name" );
  if( FD_UNLIKELY( !name || !cJSON_IsString( name ) ) ) { cJSON_Delete( root ); return -1; }
  ulong name_len = strlen( name->valuestring );
  in->name = fd_alloc_malloc( alloc, 1UL, name_len + 1UL );
  fd_memcpy( in->name, name->valuestring, name_len + 1UL );

  cJSON * input = cJSON_GetObjectItemCaseSensitive( root, "input" );
  if( FD_UNLIKELY( !input ) ) { cJSON_Delete( root ); return -1; }

  cJSON * accounts = cJSON_GetObjectItemCaseSensitive( input, "accounts" );
  if( FD_UNLIKELY( !accounts || !cJSON_IsArray( accounts ) ) ) { cJSON_Delete( root ); return -1; }

  in->num_accounts = (ulong)cJSON_GetArraySize( accounts );
  in->accounts = fd_alloc_malloc( alloc, alignof(fixture_account_t), sizeof(fixture_account_t) * in->num_accounts );

  for( ulong i=0; i<in->num_accounts; i++ ) {
    cJSON * acc = cJSON_GetArrayItem( accounts, (int)i );
    fixture_account_t * a = &in->accounts[i];

    if( decode_base64( cJSON_GetObjectItemCaseSensitive( acc, "pubkey" )->valuestring, a->pubkey.key, 32 )!=32 ||
        decode_base64( cJSON_GetObjectItemCaseSensitive( acc, "owner"  )->valuestring, a->owner.key,  32 )!=32 ) {
      cJSON_Delete( root ); return -1;
    }

    a->lamports   = (ulong)cJSON_GetObjectItemCaseSensitive( acc, "lamports"   )->valuedouble;
    a->rent_epoch = (ulong)cJSON_GetObjectItemCaseSensitive( acc, "rent_epoch" )->valuedouble;
    a->executable = cJSON_IsTrue( cJSON_GetObjectItemCaseSensitive( acc, "executable" ) ) ? 1U : 0U;

    char const * data_str = cJSON_GetObjectItemCaseSensitive( acc, "data" )->valuestring;
    if( data_str && strlen( data_str ) ) {
      ulong max_len = strlen( data_str );
      a->data = fd_alloc_malloc( alloc, 1UL, max_len );
      long len = decode_base64( data_str, a->data, max_len );
      if( FD_UNLIKELY( len<0 ) ) { cJSON_Delete( root ); return -1; }
      a->data_len = (ulong)len;
    } else {
      a->data = NULL;
      a->data_len = 0UL;
    }
  }

  cJSON * instr_accs = cJSON_GetObjectItemCaseSensitive( input, "instruction_accounts" );
  in->num_instr_accounts = (ulong)cJSON_GetArraySize( instr_accs );
  in->instr_accounts = fd_alloc_malloc( alloc, alignof(fixture_instr_account_t),
                                        sizeof(fixture_instr_account_t) * in->num_instr_accounts );

  for( ulong i=0; i<in->num_instr_accounts; i++ ) {
    cJSON * ia = cJSON_GetArrayItem( instr_accs, (int)i );
    in->instr_accounts[i].index_in_transaction = (ushort)cJSON_GetObjectItemCaseSensitive( ia, "index_in_transaction" )->valueint;
    in->instr_accounts[i].is_signer   = cJSON_IsTrue( cJSON_GetObjectItemCaseSensitive( ia, "is_signer"   ) ) ? 1U : 0U;
    in->instr_accounts[i].is_writable = cJSON_IsTrue( cJSON_GetObjectItemCaseSensitive( ia, "is_writable" ) ) ? 1U : 0U;
  }

  char const * idata_str = cJSON_GetObjectItemCaseSensitive( input, "instruction_data" )->valuestring;
  if( idata_str && strlen( idata_str ) ) {
    ulong max_len = strlen( idata_str );
    in->instr_data = fd_alloc_malloc( alloc, 1UL, max_len );
    long len = decode_base64( idata_str, in->instr_data, max_len );
    if( FD_UNLIKELY( len<0 ) ) { cJSON_Delete( root ); return -1; }
    in->instr_data_len = (ulong)len;
  } else {
    in->instr_data = NULL;
    in->instr_data_len = 0UL;
  }

  if( decode_base64( cJSON_GetObjectItemCaseSensitive( input, "program_id" )->valuestring, in->program_id.key, 32 )!=32 ) {
    cJSON_Delete( root ); return -1;
  }

  in->virtual_address_space_adj = cJSON_IsTrue( cJSON_GetObjectItemCaseSensitive( input, "virtual_address_space_adjustments" ) ) ? 1U : 0U;
  in->direct_mapping            = cJSON_IsTrue( cJSON_GetObjectItemCaseSensitive( input, "account_data_direct_mapping"          ) ) ? 1U : 0U;
  in->is_deprecated             = cJSON_IsTrue( cJSON_GetObjectItemCaseSensitive( input, "is_deprecated_loader"                 ) ) ? 1U : 0U;

  cJSON * output = cJSON_GetObjectItemCaseSensitive( root, "output" );
  out->result = cJSON_GetObjectItemCaseSensitive( output, "result" )->valueint;

  if( out->result==0 ) {
    char const * buf_str = cJSON_GetObjectItemCaseSensitive( output, "buffer" )->valuestring;
    if( buf_str && strlen( buf_str ) ) {
      ulong max_len = strlen( buf_str );
      out->buffer = fd_alloc_malloc( alloc, 1UL, max_len );
      long len = decode_base64( buf_str, out->buffer, max_len );
      if( FD_UNLIKELY( len<0 ) ) { cJSON_Delete( root ); return -1; }
      out->buffer_len = (ulong)len;
    } else {
      out->buffer = NULL;
      out->buffer_len = 0UL;
    }

    cJSON * regions = cJSON_GetObjectItemCaseSensitive( output, "regions" );
    out->num_regions = (ulong)cJSON_GetArraySize( regions );
    out->regions = fd_alloc_malloc( alloc, alignof(fixture_region_t), sizeof(fixture_region_t) * out->num_regions );

    for( ulong i=0; i<out->num_regions; i++ ) {
      cJSON * r = cJSON_GetArrayItem( regions, (int)i );
      fixture_region_t * reg = &out->regions[i];

      reg->vm_addr     = (ulong)cJSON_GetObjectItemCaseSensitive( r, "vm_addr" )->valuedouble;
      reg->is_writable = cJSON_IsTrue( cJSON_GetObjectItemCaseSensitive( r, "is_writable" ) ) ? 1U : 0U;

      char const * data_str = cJSON_GetObjectItemCaseSensitive( r, "data" )->valuestring;
      if( data_str && strlen( data_str ) ) {
        ulong max_len = strlen( data_str );
        reg->data = fd_alloc_malloc( alloc, 1UL, max_len );
        long len = decode_base64( data_str, reg->data, max_len );
        if( FD_UNLIKELY( len<0 ) ) { cJSON_Delete( root ); return -1; }
        reg->data_len = (ulong)len;
      } else {
        reg->data = NULL;
        reg->data_len = 0UL;
      }
    }

    cJSON * acc_metas = cJSON_GetObjectItemCaseSensitive( output, "accounts_metadata" );
    out->num_acc_metas = (ulong)cJSON_GetArraySize( acc_metas );
    out->acc_metas = fd_alloc_malloc( alloc, alignof(fixture_acc_meta_t), sizeof(fixture_acc_meta_t) * out->num_acc_metas );

    for( ulong i=0; i<out->num_acc_metas; i++ ) {
      cJSON * m = cJSON_GetArrayItem( acc_metas, (int)i );
      out->acc_metas[i].original_data_len  = (ulong)cJSON_GetObjectItemCaseSensitive( m, "original_data_len"  )->valuedouble;
      out->acc_metas[i].vm_key_addr        = (ulong)cJSON_GetObjectItemCaseSensitive( m, "vm_key_addr"        )->valuedouble;
      out->acc_metas[i].vm_lamports_addr   = (ulong)cJSON_GetObjectItemCaseSensitive( m, "vm_lamports_addr"   )->valuedouble;
      out->acc_metas[i].vm_owner_addr      = (ulong)cJSON_GetObjectItemCaseSensitive( m, "vm_owner_addr"      )->valuedouble;
      out->acc_metas[i].vm_data_addr       = (ulong)cJSON_GetObjectItemCaseSensitive( m, "vm_data_addr"       )->valuedouble;
    }

    out->instr_data_offset = (ulong)cJSON_GetObjectItemCaseSensitive( output, "instruction_data_offset" )->valuedouble;
  } else {
    out->buffer        = NULL;
    out->buffer_len    = 0UL;
    out->regions       = NULL;
    out->num_regions   = 0UL;
    out->acc_metas     = NULL;
    out->num_acc_metas = 0UL;
  }

  cJSON_Delete( root );
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

  g_txn_out->accounts.cnt = in->num_accounts;

  for( ulong i=0UL; i<in->num_accounts; i++ ) {
    ulong dlen = in->accounts[i].data_len;
    uchar * data_buf = fd_alloc_malloc( alloc, FD_ACCOUNT_REC_ALIGN, dlen ? dlen : 1UL );
    FD_TEST( data_buf );
    if( dlen ) fd_memcpy( data_buf, in->accounts[i].data, dlen );
    storage[i] = data_buf;

    fd_accdb_entry_t * ent = &g_txn_out->accounts.account[i];
    fd_memset( ent, 0, sizeof(*ent) );
    memcpy( ent->pubkey, in->accounts[i].pubkey.key, 32 );
    memcpy( ent->owner,  in->accounts[i].owner.key,  32 );
    ent->lamports   = in->accounts[i].lamports;
    ent->executable = in->accounts[i].executable;
    ent->data_len   = (uint)dlen;
    ent->data       = data_buf;
    ent->_writable  = 1;
    ent->commit     = 0;

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

  FD_LOG_NOTICE(( "  %s: %lu accounts, virtual_address_space_adj=%d, direct_mapping=%d, is_deprecated=%d",
                  in->name, in->num_accounts, in->virtual_address_space_adj, in->direct_mapping, in->is_deprecated ));

  uchar **            storage = NULL;
  fd_exec_instr_ctx_t ctx[1];
  setup_instr_ctx( in, program_idx, mini, alloc, &storage, ctx );

  ulong                   serialized_sz = 0;
  ulong                   pre_lens[FD_INSTR_ACCT_MAX];
  fd_vm_input_region_t    regions[FD_INSTR_ACCT_MAX + 3];
  uint                    region_cnt = 0;
  fd_vm_acc_region_meta_t acc_metas[FD_INSTR_ACCT_MAX];
  ulong                   idata_offset = 0;

  fd_memset( pre_lens,  0, sizeof(pre_lens)  );
  fd_memset( regions,   0, sizeof(regions)   );
  fd_memset( acc_metas, 0, sizeof(acc_metas) );

  uchar * serialized = ctx->runtime->bpf_loader_serialization.serialization_mem[ ctx->runtime->instr.stack_sz-1UL ];

  int result = fd_bpf_loader_input_serialize_parameters(
      ctx, pre_lens, regions, &region_cnt, acc_metas,
      in->virtual_address_space_adj, in->direct_mapping,
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
     1.3MB JSON file plus per-fixture buffers don't fit in the svm_mini
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

  cJSON_alloc_install( alloc );

  ulong   sz   = 0;
  uchar * data = read_file( alloc, fixtures_path, &sz );
  if( FD_UNLIKELY( !data ) ) {
    FD_LOG_ERR(( "Failed to read fixtures file: %s", fixtures_path ));
  }

  cJSON * root = cJSON_Parse( (char const *)data );
  if( FD_UNLIKELY( !root || !cJSON_IsArray( root ) ) ) {
    FD_LOG_ERR(( "Failed to parse fixtures file as JSON array" ));
  }

  int fixture_cnt = cJSON_GetArraySize( root );
  FD_LOG_NOTICE(( "Found %d fixtures", fixture_cnt ));

  for( int i=0; i<fixture_cnt; i++ ) {
    cJSON * item = cJSON_GetArrayItem( root, i );
    char * json_str = cJSON_PrintUnformatted( item );

    fixture_t fix[1];
    fd_memset( fix, 0, sizeof(fixture_t) );
    if( FD_UNLIKELY( parse_fixture( alloc, json_str, fix ) ) ) {
      FD_LOG_ERR(( "Failed to parse fixture %d", i ));
    }
    cJSON_free( json_str );

    FD_LOG_NOTICE(( "Testing: %s", fix->input.name ));
    int result = run_fixture( mini, alloc, fix );

    if( result==0 ) {
      FD_LOG_NOTICE(( "  PASS" ));
    } else {
      FD_LOG_ERR(( "  FAIL" ));
    }
  }

  cJSON_Delete( root );
  fd_alloc_free( alloc, data );
  fd_wksp_free_laddr( fd_alloc_delete( fd_alloc_leave( alloc ) ) );
  fd_wksp_delete_anonymous( fix_wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}

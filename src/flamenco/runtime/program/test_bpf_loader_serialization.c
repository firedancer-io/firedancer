#include "fd_bpf_loader_serialization.h"
#include "../fd_borrowed_account.h"
#include "../fd_acc_mgr.h"
#include "../fd_runtime.h"
#include "../../fd_flamenco_base.h"
#include "../../../ballet/json/cJSON.h"
#include "../../../ballet/json/cJSON_alloc.h"
#include "../../../ballet/base64/fd_base64.h"
#include <stdio.h>

#define MM_INPUT_START 0x400000000UL

/* Fixture types */

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
  uchar                     stricter_abi;
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

/* Comparison helpers - return 1 on match, 0 on mismatch */

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
  return 1;
}

/* JSON parsing */

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

  /* Parse name */
  cJSON * name = cJSON_GetObjectItemCaseSensitive( root, "name" );
  if( FD_UNLIKELY( !name || !cJSON_IsString( name ) ) ) { cJSON_Delete( root ); return -1; }
  ulong name_len = strlen( name->valuestring );
  in->name = fd_alloc_malloc( alloc, 1UL, name_len + 1UL );
  fd_memcpy( in->name, name->valuestring, name_len + 1UL );

  /* Parse input */
  cJSON * input = cJSON_GetObjectItemCaseSensitive( root, "input" );
  if( FD_UNLIKELY( !input ) ) { cJSON_Delete( root ); return -1; }

  /* Accounts */
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

  /* Instruction accounts */
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

  /* Instruction data */
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

  /* Program ID */
  if( decode_base64( cJSON_GetObjectItemCaseSensitive( input, "program_id" )->valuestring, in->program_id.key, 32 )!=32 ) {
    cJSON_Delete( root ); return -1;
  }

  /* Feature flags */
  in->stricter_abi   = cJSON_IsTrue( cJSON_GetObjectItemCaseSensitive( input, "stricter_abi_and_runtime_constraints" ) ) ? 1U : 0U;
  in->direct_mapping = cJSON_IsTrue( cJSON_GetObjectItemCaseSensitive( input, "account_data_direct_mapping"          ) ) ? 1U : 0U;
  in->is_deprecated  = cJSON_IsTrue( cJSON_GetObjectItemCaseSensitive( input, "is_deprecated_loader"                 ) ) ? 1U : 0U;

  /* Parse output */
  cJSON * output = cJSON_GetObjectItemCaseSensitive( root, "output" );
  out->result = cJSON_GetObjectItemCaseSensitive( output, "result" )->valueint;

  if( out->result==0 ) {
    /* Buffer */
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

    /* Regions */
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

    /* Account metadata */
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

/* Test execution */

static int
find_program_index( fixture_input_t const * in ) {
  for( ulong i=0; i<in->num_accounts; i++ ) {
    if( fd_memeq( in->accounts[i].pubkey.key, in->program_id.key, 32 ) ) return (int)i;
  }
  return -1;
}

static void
setup_instr_ctx( fixture_input_t const * in,
                 int                     program_idx,
                 fd_alloc_t *            alloc,
                 fd_wksp_t *             wksp,
                 uchar ***               out_storage,
                 fd_txn_out_t **         out_txn_out,
                 fd_banks_t **           out_banks,
                 fd_exec_instr_ctx_t *   instr_ctx ) {

  ulong wksp_tag = 1UL;

  /* Account storage */
  uchar ** storage = fd_alloc_malloc( alloc, alignof(uchar*), sizeof(uchar*) * in->num_accounts );
  FD_TEST( storage );

  for( ulong i=0; i<in->num_accounts; i++ ) {
    ulong sz = sizeof(fd_account_meta_t) + in->accounts[i].data_len;
    storage[i] = fd_alloc_malloc( alloc, FD_ACCOUNT_REC_ALIGN, sz );
    FD_TEST( storage[i] );
    fd_memset( storage[i], 0, sz );

    fd_account_meta_t * meta = (fd_account_meta_t *)storage[i];
    fd_account_meta_init( meta );
    meta->dlen       = (uint)in->accounts[i].data_len;
    meta->lamports   = in->accounts[i].lamports;
    meta->executable = in->accounts[i].executable;
    fd_memcpy( meta->owner, in->accounts[i].owner.key, 32 );

    if( in->accounts[i].data_len ) {
      fd_memcpy( fd_account_meta_get_data( meta ), in->accounts[i].data, in->accounts[i].data_len );
    }
  }

  /* Transaction context */
  fd_txn_out_t * txn_out = fd_wksp_alloc_laddr( wksp, alignof(fd_txn_out_t), sizeof(fd_txn_out_t), wksp_tag++ );
  FD_TEST( txn_out );
  fd_memset( txn_out, 0, sizeof(fd_txn_out_t) );
  txn_out->accounts.accounts_cnt = in->num_accounts;

  for( ulong i=0; i<in->num_accounts; i++ ) {
    fd_account_meta_t * meta = (fd_account_meta_t *)storage[i];
    fd_txn_account_t * acc = &txn_out->accounts.accounts[i];
    void * mem = fd_txn_account_new( acc, &in->accounts[i].pubkey, meta, 1 );
    FD_TEST( fd_txn_account_join( mem ) );
    acc->starting_dlen     = in->accounts[i].data_len;
    acc->starting_lamports = in->accounts[i].lamports;
    fd_memcpy( txn_out->accounts.account_keys[i].key, in->accounts[i].pubkey.key, 32 );
  }

  /* Set up banks for feature flag checks */
  ulong banks_footprint = fd_banks_footprint( 1UL /* max_total_banks */, 1UL /* max_fork_width */ );
  void * banks_mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), banks_footprint, wksp_tag++ );
  FD_TEST( banks_mem );
  fd_banks_t * banks = fd_banks_join( fd_banks_new( banks_mem, 1UL, 1UL, 0, 42UL ) );
  FD_TEST( banks );

  /* Create the initial bank */
  fd_bank_t * bank = fd_banks_init_bank( banks );
  FD_TEST( bank );

  /* Initialize features - enable remove_accounts_executable_flag_checks so the feature check is short-circuited
     and we don't need to worry about executable accounts (which our fixtures don't have anyway) */
  fd_features_t * features = fd_bank_features_modify( bank );
  fd_features_disable_all( features );
  /* Enable this feature so fd_borrowed_account_is_executable_internal returns false immediately */
  FD_FEATURE_SET_ACTIVE( features, remove_accounts_executable_flag_checks, 0UL );

  /* Instruction info */
  static fd_txn_in_t   txn_in[1];
  static fd_instr_info_t info[1];
  fd_memset( txn_in, 0, sizeof(fd_txn_in_t) );
  fd_memset( info, 0, sizeof(fd_instr_info_t) );

  info->program_id = (uchar)program_idx;
  info->data       = in->instr_data;
  info->data_sz    = (ushort)in->instr_data_len;
  info->acct_cnt   = (ushort)in->num_instr_accounts;

  uchar seen[FD_INSTR_ACCT_MAX] = {0};
  for( ulong i=0; i<in->num_instr_accounts; i++ ) {
    ushort idx = in->instr_accounts[i].index_in_transaction;
    info->accounts[i].index_in_transaction = idx;
    info->accounts[i].index_in_caller      = (ushort)i;
    info->accounts[i].index_in_callee      = (ushort)i;
    info->accounts[i].is_signer            = in->instr_accounts[i].is_signer;
    info->accounts[i].is_writable          = in->instr_accounts[i].is_writable;
    info->is_duplicate[i] = seen[idx] ? 1 : 0;
    seen[idx] = 1;
  }

  fd_memset( instr_ctx, 0, sizeof(fd_exec_instr_ctx_t) );
  instr_ctx->instr   = info;
  instr_ctx->txn_in  = txn_in;
  instr_ctx->txn_out = txn_out;
  instr_ctx->bank    = bank;

  *out_storage = storage;
  *out_txn_out = txn_out;
  *out_banks   = banks;
}

static void
cleanup_instr_ctx( fixture_input_t const * in,
                   fd_alloc_t *            alloc,
                   uchar **                storage,
                   fd_txn_out_t *          txn_out,
                   fd_banks_t *            banks ) {
  for( ulong i=0; i<in->num_accounts; i++ ) {
    fd_txn_account_delete( fd_txn_account_leave( &txn_out->accounts.accounts[i] ) );
    fd_alloc_free( alloc, storage[i] );
  }
  fd_wksp_free_laddr( fd_banks_delete( fd_banks_leave( banks ) ) );
  fd_wksp_free_laddr( txn_out );
  fd_alloc_free( alloc, storage );
}

static int
run_fixture( fd_alloc_t * alloc,
             fd_wksp_t *  wksp,
             fixture_t *  fix ) {

  fixture_input_t *  in  = &fix->input;
  fixture_output_t * out = &fix->output;

  int program_idx = find_program_index( in );
  FD_TEST( program_idx>=0 );

  FD_LOG_NOTICE(( "  %s: %lu accounts, stricter=%d, dm=%d, deprecated=%d",
                  in->name, in->num_accounts, in->stricter_abi, in->direct_mapping, in->is_deprecated ));

  uchar **            storage = NULL;
  fd_txn_out_t *      txn_out = NULL;
  fd_banks_t *        banks   = NULL;
  fd_exec_instr_ctx_t ctx[1];
  setup_instr_ctx( in, program_idx, alloc, wksp, &storage, &txn_out, &banks, ctx );

  /* Call serialization */
  ulong                   serialized_sz = 0;
  ulong                   pre_lens[FD_INSTR_ACCT_MAX];
  fd_vm_input_region_t    regions[FD_INSTR_ACCT_MAX + 3];
  uint                    region_cnt = 0;
  fd_vm_acc_region_meta_t acc_metas[FD_INSTR_ACCT_MAX];
  ulong                   idata_offset = 0;

  fd_memset( pre_lens,  0, sizeof(pre_lens)  );
  fd_memset( regions,   0, sizeof(regions)   );
  fd_memset( acc_metas, 0, sizeof(acc_metas) );

  uchar * serialized = fd_alloc_malloc( alloc, FD_RUNTIME_EBPF_HOST_ALIGN, 64UL * 1024UL );
  FD_TEST( serialized );

  int result = fd_bpf_loader_input_serialize_parameters(
      ctx, pre_lens, regions, &region_cnt, acc_metas,
      in->stricter_abi, in->direct_mapping,
      in->is_deprecated,
      &idata_offset, &serialized_sz, serialized );

  FD_LOG_NOTICE(( "  result=%d serialized_sz=%lu region_cnt=%u idata_offset=%lu",
                  result, serialized_sz, region_cnt, idata_offset ));

  /* Compare */
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

  fd_alloc_free( alloc, serialized );
  cleanup_instr_ctx( in, alloc, storage, txn_out, banks );

  return ok ? 0 : -1;
}

static int
test_fixture( fd_alloc_t * alloc,
              fd_wksp_t *  wksp,
              char const * path ) {
  FD_LOG_NOTICE(( "Testing: %s", path ));

  cJSON_alloc_install( alloc );

  ulong   sz   = 0;
  uchar * data = read_file( alloc, path, &sz );
  if( FD_UNLIKELY( !data ) ) {
    FD_LOG_ERR(( "Failed to read: %s", path ));
    return -1;
  }

  fixture_t fix[1];
  fd_memset( fix, 0, sizeof(fixture_t) );
  if( FD_UNLIKELY( parse_fixture( alloc, (char const *)data, fix ) ) ) {
    FD_LOG_ERR(( "Failed to parse: %s", path ));
    return -1;
  }

  int result = run_fixture( alloc, wksp, fix );

  fd_alloc_free( alloc, data );

  if( result==0 ) {
    FD_LOG_NOTICE(( "  PASS" ));
  } else {
    FD_LOG_ERR(( "  FAIL" ));
  }
  return result;
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "normal" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 65536UL ); /* 256MB workspace */
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  FD_TEST( page_sz );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  void * alloc_mem = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 1UL );
  FD_TEST( alloc_mem );
  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( alloc_mem, 1UL ), 0UL );
  FD_TEST( alloc );

  char const * fixtures[] = {
    /* Deprecated loader tests */
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_single_account.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_single_account_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_single_account_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_two_accounts.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_two_accounts_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_two_accounts_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_three_accounts.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_three_accounts_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_three_accounts_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_five_accounts_three_dups.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_five_accounts_three_dups_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_five_accounts_three_dups_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_duplicate.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_duplicate_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_duplicate_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_zero_data.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_zero_data_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_zero_data_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_readonly.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_readonly_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_readonly_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_mixed_writable_readonly.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_mixed_writable_readonly_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_mixed_writable_readonly_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_mixed_empty_nonempty.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_mixed_empty_nonempty_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_mixed_empty_nonempty_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_dup_with_zero_data.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_dup_with_zero_data_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_dup_with_zero_data_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_readonly_dup.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_readonly_dup_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_readonly_dup_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_three_mixed_all.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_three_mixed_all_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/deprecated_three_mixed_all_dm.json",
    /* Aligned loader tests */
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_single_account.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_single_account_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_single_account_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_two_accounts.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_two_accounts_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_two_accounts_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_duplicate.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_duplicate_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_duplicate_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_zero_data.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_zero_data_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_zero_data_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_readonly.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_readonly_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_readonly_dm.json",
    /* Alignment edge case tests */
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_0.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_0_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_0_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_1.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_1_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_1_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_8.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_8_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_8_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_15.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_15_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_15_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_16.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_16_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_16_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_17.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_17_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_17_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_31.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_31_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_31_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_32.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_32_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_data_len_32_dm.json",
    /* More aligned loader tests */
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_multi_alignment.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_multi_alignment_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_multi_alignment_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_dup_between.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_dup_between_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_dup_between_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_mixed_writable_readonly.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_mixed_writable_readonly_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_mixed_writable_readonly_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_five_accounts_three_dups.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_five_accounts_three_dups_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_five_accounts_three_dups_dm.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_three_mixed_all.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_three_mixed_all_stricter.json",
    "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures/aligned_three_mixed_all_dm.json",
  };
  ulong fixture_cnt = sizeof(fixtures) / sizeof(fixtures[0]);

  for( ulong i=0; i<fixture_cnt; i++ ) {
    FD_TEST( test_fixture( alloc, wksp, fixtures[i] )==0 );
  }

  fd_alloc_delete( fd_alloc_leave( alloc ) );
  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

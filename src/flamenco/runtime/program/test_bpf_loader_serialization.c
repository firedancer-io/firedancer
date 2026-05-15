#include "fd_bpf_loader_serialization.h"
#include "../fd_acc_mgr.h"
#include "../fd_runtime.h"
#include "../fd_bank.h"
#include "../../fd_flamenco_base.h"
#include "../../accdb/fd_accdb_ref.h"
#include "../../../ballet/json/yyjson.h"
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

static inline char const *
json_str( yyjson_val const * obj, char const * key ) {
  return yyjson_get_str( yyjson_obj_get( obj, key ) );
}

static inline ulong
json_ulong( yyjson_val const * obj, char const * key ) {
  return yyjson_get_uint( yyjson_obj_get( obj, key ) );
}

static inline int
json_int( yyjson_val const * obj, char const * key ) {
  return yyjson_get_int( yyjson_obj_get( obj, key ) );
}

static inline uchar
json_bool( yyjson_val const * obj, char const * key ) {
  return yyjson_is_true( yyjson_obj_get( obj, key ) ) ? 1U : 0U;
}

static int
parse_fixture( fd_alloc_t * alloc, yyjson_val const * root, fixture_t * fix ) {
  if( FD_UNLIKELY( !root ) ) return -1;

  fixture_input_t *  in  = &fix->input;
  fixture_output_t * out = &fix->output;

  yyjson_val const * name = yyjson_obj_get( root, "name" );
  if( FD_UNLIKELY( !yyjson_is_str( name ) ) ) return -1;
  ulong name_len = yyjson_get_len( name );
  in->name = fd_alloc_malloc( alloc, 1UL, name_len + 1UL );
  fd_memcpy( in->name, yyjson_get_str( name ), name_len + 1UL );

  yyjson_val const * input = yyjson_obj_get( root, "input" );
  if( FD_UNLIKELY( !input ) ) return -1;

  yyjson_val const * accounts = yyjson_obj_get( input, "accounts" );
  if( FD_UNLIKELY( !yyjson_is_arr( accounts ) ) ) return -1;

  in->num_accounts = yyjson_arr_size( accounts );
  in->accounts = fd_alloc_malloc( alloc, alignof(fixture_account_t), sizeof(fixture_account_t) * in->num_accounts );

  for( ulong i=0; i<in->num_accounts; i++ ) {
    yyjson_val const * acc = yyjson_arr_get( accounts, i );
    fixture_account_t * a = &in->accounts[i];

    if( decode_base64( json_str( acc, "pubkey" ), a->pubkey.key, 32 )!=32 ||
        decode_base64( json_str( acc, "owner"  ), a->owner.key,  32 )!=32 ) {
      return -1;
    }

    a->lamports   = json_ulong( acc, "lamports"   );
    a->rent_epoch = json_ulong( acc, "rent_epoch" );
    a->executable = json_bool ( acc, "executable" );

    char const * data_str = json_str( acc, "data" );
    if( data_str && strlen( data_str ) ) {
      ulong max_len = strlen( data_str );
      a->data = fd_alloc_malloc( alloc, 1UL, max_len );
      long len = decode_base64( data_str, a->data, max_len );
      if( FD_UNLIKELY( len<0 ) ) return -1;
      a->data_len = (ulong)len;
    } else {
      a->data = NULL;
      a->data_len = 0UL;
    }
  }

  yyjson_val const * instr_accs = yyjson_obj_get( input, "instruction_accounts" );
  in->num_instr_accounts = yyjson_arr_size( instr_accs );
  in->instr_accounts = fd_alloc_malloc( alloc, alignof(fixture_instr_account_t),
                                        sizeof(fixture_instr_account_t) * in->num_instr_accounts );

  for( ulong i=0; i<in->num_instr_accounts; i++ ) {
    yyjson_val const * ia = yyjson_arr_get( instr_accs, i );
    in->instr_accounts[i].index_in_transaction = (ushort)json_int ( ia, "index_in_transaction" );
    in->instr_accounts[i].is_signer            =         json_bool( ia, "is_signer"            );
    in->instr_accounts[i].is_writable          =         json_bool( ia, "is_writable"          );
  }

  char const * idata_str = json_str( input, "instruction_data" );
  if( idata_str && strlen( idata_str ) ) {
    ulong max_len = strlen( idata_str );
    in->instr_data = fd_alloc_malloc( alloc, 1UL, max_len );
    long len = decode_base64( idata_str, in->instr_data, max_len );
    if( FD_UNLIKELY( len<0 ) ) return -1;
    in->instr_data_len = (ulong)len;
  } else {
    in->instr_data = NULL;
    in->instr_data_len = 0UL;
  }

  if( decode_base64( json_str( input, "program_id" ), in->program_id.key, 32 )!=32 ) return -1;

  in->virtual_address_space_adj                = json_bool( input, "virtual_address_space_adjustments"        );
  in->direct_mapping                           = json_bool( input, "account_data_direct_mapping"              );
  in->direct_account_pointers_in_program_input = json_bool( input, "direct_account_pointers_in_program_input" );
  in->is_deprecated                            = json_bool( input, "is_deprecated_loader"                     );

  yyjson_val const * output = yyjson_obj_get( root, "output" );
  out->result = json_int( output, "result" );

  if( out->result==0 ) {
    char const * buf_str = json_str( output, "buffer" );
    if( buf_str && strlen( buf_str ) ) {
      ulong max_len = strlen( buf_str );
      out->buffer = fd_alloc_malloc( alloc, 1UL, max_len );
      long len = decode_base64( buf_str, out->buffer, max_len );
      if( FD_UNLIKELY( len<0 ) ) return -1;
      out->buffer_len = (ulong)len;
    } else {
      out->buffer = NULL;
      out->buffer_len = 0UL;
    }

    yyjson_val const * regions = yyjson_obj_get( output, "regions" );
    out->num_regions = yyjson_arr_size( regions );
    out->regions = fd_alloc_malloc( alloc, alignof(fixture_region_t), sizeof(fixture_region_t) * out->num_regions );

    for( ulong i=0; i<out->num_regions; i++ ) {
      yyjson_val const * r = yyjson_arr_get( regions, i );
      fixture_region_t * reg = &out->regions[i];

      reg->vm_addr     = json_ulong( r, "vm_addr"     );
      reg->is_writable = json_bool ( r, "is_writable" );

      char const * data_str = json_str( r, "data" );
      if( data_str && strlen( data_str ) ) {
        ulong max_len = strlen( data_str );
        reg->data = fd_alloc_malloc( alloc, 1UL, max_len );
        long len = decode_base64( data_str, reg->data, max_len );
        if( FD_UNLIKELY( len<0 ) ) return -1;
        reg->data_len = (ulong)len;
      } else {
        reg->data = NULL;
        reg->data_len = 0UL;
      }
    }

    yyjson_val const * acc_metas = yyjson_obj_get( output, "accounts_metadata" );
    out->num_acc_metas = yyjson_arr_size( acc_metas );
    out->acc_metas = fd_alloc_malloc( alloc, alignof(fixture_acc_meta_t), sizeof(fixture_acc_meta_t) * out->num_acc_metas );

    for( ulong i=0; i<out->num_acc_metas; i++ ) {
      yyjson_val const * m = yyjson_arr_get( acc_metas, i );
      out->acc_metas[i].original_data_len  = json_ulong( m, "original_data_len"  );
      out->acc_metas[i].vm_key_addr        = json_ulong( m, "vm_key_addr"        );
      out->acc_metas[i].vm_lamports_addr   = json_ulong( m, "vm_lamports_addr"   );
      out->acc_metas[i].vm_owner_addr      = json_ulong( m, "vm_owner_addr"      );
      out->acc_metas[i].vm_data_addr       = json_ulong( m, "vm_data_addr"       );
      yyjson_val const * vm_addr_item      = yyjson_obj_get( m, "vm_addr" );
      if( vm_addr_item ) {
        out->acc_metas[i].vm_addr         = yyjson_get_uint( vm_addr_item );
        out->acc_metas[i].vm_addr_present = 1;
      } else {
        out->acc_metas[i].vm_addr         = 0UL;
        out->acc_metas[i].vm_addr_present = 0;
      }
    }

    out->instr_data_offset = json_ulong( output, "instruction_data_offset" );
  } else {
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

static void
setup_instr_ctx( fixture_input_t const *      in,
                 int                          program_idx,
                 fd_alloc_t *                 alloc,
                 fd_wksp_t *                  wksp,
                 uchar ***                    out_storage,
                 fd_txn_out_t **              out_txn_out,
                 fd_banks_t **                out_banks,
                 fd_runtime_t **              out_runtime,
                 fd_exec_instr_ctx_t *        instr_ctx ) {

  ulong wksp_tag = 1UL;

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
      fd_memcpy( fd_account_data( meta ), in->accounts[i].data, in->accounts[i].data_len );
    }
  }

  fd_txn_out_t * txn_out = fd_wksp_alloc_laddr( wksp, alignof(fd_txn_out_t), sizeof(fd_txn_out_t), wksp_tag++ );
  FD_TEST( txn_out );
  fd_memset( txn_out, 0, sizeof(fd_txn_out_t) );
  txn_out->accounts.cnt = in->num_accounts;

  for( ulong i=0; i<in->num_accounts; i++ ) {
    fd_account_meta_t * meta = (fd_account_meta_t *)storage[i];
    fd_accdb_rw_init_nodb( &txn_out->accounts.account[i], &in->accounts[i].pubkey, meta, FD_RUNTIME_ACC_SZ_MAX );
    fd_memcpy( txn_out->accounts.keys[i].key, in->accounts[i].pubkey.key, 32 );
  }

  ulong banks_footprint = fd_banks_footprint( 1UL, 1UL, 2048UL, 2048UL );
  void * banks_mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), banks_footprint, wksp_tag++ );
  FD_TEST( banks_mem );
  fd_banks_t * banks = fd_banks_join( fd_banks_new( banks_mem, 1UL, 1UL, 2048UL, 2048UL, 0, 42UL ) );
  FD_TEST( banks );

  fd_bank_t * bank = fd_banks_init_bank( banks );
  FD_TEST( bank );

  fd_features_t * features = &bank->f.features;
  fd_features_disable_all( features );
  FD_FEATURE_SET_ACTIVE( features, remove_accounts_executable_flag_checks, 0UL );

  fd_runtime_t * runtime = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_t), sizeof(fd_runtime_t), wksp_tag++ );
  FD_TEST( runtime );
  fd_memset( runtime, 0, sizeof(fd_runtime_t) );
  runtime->instr.stack_sz = 1;
  for( ulong i=0; i<in->num_accounts; i++ ) {
    runtime->accounts.starting_lamports[i] = in->accounts[i].lamports;
    runtime->accounts.starting_dlen[i]     = in->accounts[i].data_len;
    runtime->accounts.refcnt[i]            = 0UL;
  }

  static fd_txn_in_t     txn_in[1];
  static fd_instr_info_t info[1];
  fd_memset( txn_in, 0, sizeof(fd_txn_in_t) );
  fd_memset( info, 0, sizeof(fd_instr_info_t) );

  info->program_id = (uchar)program_idx;
  if( in->instr_data_len ) {
    fd_memcpy( info->data, in->instr_data, in->instr_data_len );
  }
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
  instr_ctx->instr      = info;
  instr_ctx->txn_in     = txn_in;
  instr_ctx->txn_out    = txn_out;
  instr_ctx->bank       = bank;
  instr_ctx->runtime    = runtime;

  *out_storage = storage;
  *out_txn_out = txn_out;
  *out_banks   = banks;
  *out_runtime = runtime;
}

static void
cleanup_instr_ctx( fixture_input_t const * in,
                   fd_alloc_t *            alloc,
                   uchar **                storage,
                   fd_txn_out_t *          txn_out,
                   fd_banks_t *            banks,
                   fd_runtime_t *          runtime ) {
  for( ulong i=0; i<in->num_accounts; i++ ) {
    fd_alloc_free( alloc, storage[i] );
  }
  fd_wksp_free_laddr( runtime );
  fd_wksp_free_laddr( banks );
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

  FD_LOG_NOTICE(( "  %s: %lu accounts, virtual_address_space_adj=%d, direct_mapping=%d, direct_account_pointers=%d, is_deprecated=%d",
                  in->name, in->num_accounts, in->virtual_address_space_adj, in->direct_mapping,
                  in->direct_account_pointers_in_program_input, in->is_deprecated ));

  uchar **           storage = NULL;
  fd_txn_out_t *     txn_out = NULL;
  fd_banks_t *       banks   = NULL;
  fd_runtime_t *     runtime = NULL;
  fd_exec_instr_ctx_t ctx[1];
  setup_instr_ctx( in, program_idx, alloc, wksp, &storage, &txn_out, &banks, &runtime, ctx );

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

  cleanup_instr_ctx( in, alloc, storage, txn_out, banks, runtime );

  return ok ? 0 : -1;
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "normal" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1100000UL );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  FD_TEST( page_sz );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  void * alloc_mem = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 1UL );
  FD_TEST( alloc_mem );
  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( alloc_mem, 1UL ), 0UL );
  FD_TEST( alloc );

  char const * fixtures_path = "src/flamenco/runtime/program/test_bpf_loader_serialization_fixtures.json";
  FD_LOG_NOTICE(( "Loading fixtures from: %s", fixtures_path ));

  ulong   sz   = 0;
  uchar * data = read_file( alloc, fixtures_path, &sz );
  if( FD_UNLIKELY( !data ) ) {
    FD_LOG_ERR(( "Failed to read fixtures file: %s", fixtures_path ));
  }

  yyjson_doc * json = yyjson_read( (char *)data, sz, YYJSON_READ_NOFLAG );
  yyjson_val const * root = yyjson_doc_get_root( json );
  if( FD_UNLIKELY( !yyjson_is_arr( root ) ) ) {
    FD_LOG_ERR(( "Failed to parse fixtures file as JSON array" ));
  }

  ulong fixture_cnt = yyjson_arr_size( root );
  FD_LOG_NOTICE(( "Found %lu fixtures", fixture_cnt ));

  for( ulong i=0; i<fixture_cnt; i++ ) {
    yyjson_val const * item = yyjson_arr_get( root, i );
    fixture_t fix[1];
    fd_memset( fix, 0, sizeof(fixture_t) );
    if( FD_UNLIKELY( parse_fixture( alloc, item, fix ) ) ) {
      FD_LOG_ERR(( "Failed to parse fixture %lu", i ));
    }

    FD_LOG_NOTICE(( "Testing: %s", fix->input.name ));
    int result = run_fixture( alloc, wksp, fix );

    if( result==0 ) {
      FD_LOG_NOTICE(( "  PASS" ));
    } else {
      FD_LOG_ERR(( "  FAIL" ));
    }
  }

  yyjson_doc_free( json );
  fd_alloc_free( alloc, data );

  fd_alloc_delete( fd_alloc_leave( alloc ) );
  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

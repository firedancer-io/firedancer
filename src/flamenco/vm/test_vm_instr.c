/* test_vm_instr executes the text-based instruction tests in
   src/flamenco/vm */

#include "fd_vm.h"
#include "fd_vm_base.h"
#include "fd_vm_private.h"
#include "test_vm_util.h"
#include "../runtime/context/fd_exec_slot_ctx.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

/* Parser *************************************************************/

/* Instruction tests are specified in a minimal text based grammar. */

#define PARSE_STATE_INPUT  (0)
#define PARSE_STATE_ASSERT (1)

#define STATUS_OK          (0)
#define STATUS_FAULT       (1)
#define STATUS_VERIFY_FAIL (2)

static char const *
test_status_str( int status ) {
  switch( status ) {
  case STATUS_OK:          return "Ok";
  case STATUS_FAULT:       return "Fault";
  case STATUS_VERIFY_FAIL: return "VerifyFail";
  default:                 return "unknown (!!!)";
  }
}

#define REG_CNT (12)

struct test_input {
  uchar const * input;  /* heap allocated */
  ulong         input_sz;
  uchar         op;
  uchar         dst : 4;
  uchar         src : 4;
  ushort        off;
  ulong         imm;
  ulong         reg[REG_CNT];
  uint          region_boundary[16]; /* This can be changed */
  uint          region_boundary_cnt;
};

typedef struct test_input test_input_t;

struct test_effects {
  int   status;
  int   force_exec;
  ulong reg[REG_CNT];
};

typedef struct test_effects test_effects_t;

struct test_fixture {
  ulong          line;
  test_input_t   input;
  test_effects_t effects;
};

typedef struct test_fixture test_fixture_t;

struct test_parser {
  char const *   path;
  char const *   cur;
  char const *   end;
  ulong          line;
  ulong          test_line;
  int            state;
  test_input_t   input;
  test_effects_t effects;
};

typedef struct test_parser test_parser_t;

/* parse_advance advances the tape by n characters.  Counts line numbers
   along the way. */

static void
parse_advance( test_parser_t * p,
               ulong           n ) {
  assert( p->cur+n <= p->end );
  for( ulong i=0UL; i<n; i++ ) {
    if( p->cur[i]=='\n' ) {
      p->line++;
    }
  }
  p->cur += n;
}

/* parse_assign_sep advances the tape until the next `=` token.
   Strips leading and trailing white space. */

static void
parse_assign_sep( test_parser_t * p ) {
  while( p->cur != p->end && fd_isspace( p->cur[0] ) ) {
    parse_advance( p, 1UL );
  }
  if( p->cur == p->end || p->cur[0] != '=' ) {
    FD_LOG_ERR(( "Expected '=' at %s(%lu)", p->path, p->line ));
  }
  parse_advance( p, 1UL );
  while( p->cur != p->end && fd_isspace( p->cur[0] ) ) {
    parse_advance( p, 1UL );
  }
}

/* parse_hex_buf reads a hex string.  Returns a libc heap allocated
   string containing the parsed binary. */

static uchar *
parse_hex_buf( test_parser_t * p,
               ulong *         psz ) {

  /* First pass: Count number of chars */

  ulong sz = 0UL;

  char const * peek = p->cur;
  while( peek + 1 < p->end ) {
    int c0 = peek[0];
    int c1 = peek[1];
    if( !fd_isxdigit( c0 ) || !fd_isxdigit( c1 ) ) break;
    peek += 2;
    sz   += 1;
  }

  uchar * buf = malloc( sz );
  assert( buf );

  /* Second pass: Deserialize */

  uchar * cur = buf;
  while( p->cur + 1 < p->end ) {
    int c0 = p->cur[0];
    int c1 = p->cur[1];
    if( !fd_isxdigit( c0 ) || !fd_isxdigit( c1 ) ) break;
    int hi = fd_isdigit( c0 ) ? c0 - '0' : tolower( c0 ) - 'a' + 10;
    int lo = fd_isdigit( c1 ) ? c1 - '0' : tolower( c1 ) - 'a' + 10;
    *(cur++) = (uchar)( ( hi << 4 ) | lo );
    parse_advance( p, 2UL );
  }

  *psz = sz;
  return buf;
}

/* parse_hex_int reads a hex u64. */

static ulong
parse_hex_int( test_parser_t * p ) {
  ulong val   = 0UL;
  int   empty = 1;
  while( p->cur != p->end ) {
    int c = p->cur[0];
    if( !fd_isxdigit( c ) ) break;
    int digit = fd_isdigit( c ) ? c - '0' : tolower( c ) - 'a' + 10;
    val <<= 4;
    val  |= (ulong)digit;
    empty = 0;
    parse_advance( p, 1UL );
  }
  if( FD_UNLIKELY( empty ) ) {
    FD_LOG_ERR(( "Expected hex integer at %s(%lu)", p->path, p->line ));
  }
  return val;
}

/* parse_token reads the next token into the parse state.  If a new
   test fixture is ready, returns out.  Otherwise (if more needs to be
   read or EOF is reached), returns NULL.  Aborts on parse failure.

   Valid tokens include:
   - `#`        Comment
   - `$`        New input
   - `:`        Assertion for input
   - `foo=bla`  Assignment */

static test_fixture_t *
parse_token( test_parser_t *  p,
             test_fixture_t * out ) {

  while( p->cur != p->end && fd_isspace( p->cur[0] ) ) {
    parse_advance( p, 1UL );
  }

  if( p->cur == p->end ) {
    out->line = p->line;
    if( p->state == PARSE_STATE_ASSERT ) {
      p->state = PARSE_STATE_INPUT;
      *out = (test_fixture_t) {
        .line    = p->test_line,
        .input   = p->input,
        .effects = p->effects
      };
      return out;
    } else {
      return NULL;
    }
  }

  switch( p->cur[0] ) {

  case '$': {  /* new input */
    int   prev_state = p->state;
    ulong prev_line  = p->test_line;
    p->state     = PARSE_STATE_INPUT;
    p->test_line = p->line;
    parse_advance( p, 1UL );
    if( prev_state == PARSE_STATE_ASSERT ) {
      *out = (test_fixture_t) {
        .line    = prev_line,
        .input   = p->input,
        .effects = p->effects
      };
      return out;
    }
    return NULL;
  }

  case '#': {  /* comment */
    while( p->cur != p->end ) {
      int c = p->cur[0];
      parse_advance( p, 1UL );
      if( c == '\n' ) return NULL;
    }
    return NULL;
  }

  case ':': {  /* assertion */
    p->state = PARSE_STATE_ASSERT;
    parse_advance( p, 1UL );
    for( ulong i=0UL; i<REG_CNT; i++ ) {
      p->effects.reg[i] = p->input.reg[i];
    }
    return NULL;
  }

  }

  /* Read word */

  char const * word = p->cur;
  while( p->cur != p->end ) {
    int c = p->cur[0];
    if( fd_isalnum( c ) || c == '_' ) {
      parse_advance( p, 1UL );
    } else {
      break;
    }
  }

  ulong word_len = (ulong)( p->cur - word );

  if( 0==strncmp( word, "input", word_len ) ) {

    parse_assign_sep( p );
    free( (void *)p->input.input );
    p->input.input = parse_hex_buf( p, &p->input.input_sz );
    p->input.region_boundary_cnt = 0U;

  } else if( 0==strncmp( word, "region_boundary", word_len ) ) {

    parse_assign_sep( p );
    p->input.region_boundary[ p->input.region_boundary_cnt ] = (uint)parse_hex_int( p );
    p->input.region_boundary_cnt++;

  } else if( 0==strncmp( word, "op", word_len ) ) {

    parse_assign_sep( p );
    ulong op = parse_hex_int( p );
    assert( op <= UCHAR_MAX );
    p->input.op = (uchar)op;

  } else if( 0==strncmp( word, "dst", word_len ) ) {

    parse_assign_sep( p );
    ulong reg = parse_hex_int( p );
    p->input.dst = (uchar)(reg & 0xf);

  } else if( 0==strncmp( word, "src", word_len ) ) {

    parse_assign_sep( p );
    ulong reg = parse_hex_int( p );
    p->input.src = (uchar)(reg & 0xf);

  } else if( 0==strncmp( word, "off", word_len ) ) {

    parse_assign_sep( p );
    ulong off = parse_hex_int( p );
    assert( off <= USHORT_MAX );
    p->input.off = (ushort)off;

  } else if( 0==strncmp( word, "imm", word_len ) ) {

    parse_assign_sep( p );
    p->input.imm = parse_hex_int( p );

  } else if( 0==strncmp( word, "ok", word_len ) ) {

    p->effects.status = STATUS_OK;

  } else if( 0==strncmp( word, "err", word_len ) ) {

    p->effects.status = STATUS_FAULT;

  } else if( 0==strncmp( word, "vfy", word_len ) ) {

    p->effects.status = STATUS_VERIFY_FAIL;
    p->effects.force_exec = 1;

  } else if( 0==strncmp( word, "vfyub", word_len ) ) {

    p->effects.status = STATUS_VERIFY_FAIL;
    p->effects.force_exec = 0;

  } else if( word_len >= 2 && word[0] == 'r' && fd_isdigit( word[1] ) ) {

    ulong reg = fd_cstr_to_uchar( word+1 );
    assert( reg < REG_CNT );
    parse_assign_sep( p );

    ulong * out = p->state == PARSE_STATE_ASSERT ? p->effects.reg : p->input.reg;
    out[ reg ] = parse_hex_int( p );

  } else {

    FD_LOG_ERR(( "Unexpected token '%.*s' at %s(%lu)", (int)word_len, word, p->path, p->line ));

  }

  return NULL;
}

static test_fixture_t *
parse_next( test_parser_t *  p,
            test_fixture_t * out ) {
  do {
    test_fixture_t * ret = parse_token( p, out );
    if( ret ) return ret;
  } while( p->cur != p->end );
  return NULL;
}

/* Execution **********************************************************/

static void
run_input2( test_effects_t * out,
            fd_vm_t *        vm,
            int              force_exec ) {

  if( fd_vm_validate( vm ) != FD_VM_SUCCESS ) {
    out->status = STATUS_VERIFY_FAIL;
    if( force_exec && fd_vm_exec_notrace( vm ) == FD_VM_SUCCESS ) {
      //TODO: we should mark these tests as vfyub
    }
    return;
  }

  if( fd_vm_exec_notrace( vm ) != FD_VM_SUCCESS ) {
    out->status = STATUS_FAULT;
    return;
  }

  *out = (test_effects_t) {
    .status = STATUS_OK,
    .reg    = {
      vm->reg[0],  vm->reg[1],  vm->reg[2],  vm->reg[3],
      vm->reg[4],  vm->reg[5],  vm->reg[6],  vm->reg[7],
      vm->reg[8],  vm->reg[9],  vm->reg[10], vm->reg[11]
    }
  };
}

static void
run_input( test_input_t const * input,
           test_effects_t *     out,
           fd_vm_t *            vm,
           ulong                sbpf_version,
           int                  force_exec ) {

  /* Assemble instructions */

  ulong text[3]  = {0};
  ulong text_cnt = 0UL;

  text[ text_cnt++ ] =
    fd_vm_instr( input->op, input->dst, input->src, (short)input->off, (uint)input->imm );
  if( input->op == FD_SBPF_OP_LDDW ) {
    text[ text_cnt++ ] =
      fd_vm_instr( 0, 0, 0, 0, (uint)( input->imm >> 32 ) );
  }
  text[ text_cnt++ ] =
    fd_vm_instr( FD_SBPF_OP_EXIT, 0, 0, 0, 0 );

  /* Set up VM */

  uchar * input_copy = malloc( input->input_sz );
  assert( input_copy );
  memcpy( input_copy, input->input, input->input_sz );

  /* Turn input into a single memory region */
  fd_vm_input_region_t input_region[32];

  if( !input->region_boundary_cnt ) {
    input_region[0] = (fd_vm_input_region_t){
      .vaddr_offset = 0UL,
      .haddr        = (ulong)input_copy,
      .region_sz    = (uint)input->input_sz,
      .is_writable  = 1U,
    };
  } else {
    for( uint i=0; i<input->region_boundary_cnt; ++i ) {
      ulong prev_offset = i ? input_region[ i-1 ].vaddr_offset : 0;
      ulong prev_sz     = i ? input_region[ i-1 ].region_sz    : 0;
      ulong cur_offset  = prev_offset + prev_sz;

      input_region[i] = (fd_vm_input_region_t){
        .vaddr_offset = cur_offset,
        .haddr        = (ulong)input_copy + cur_offset,
        .region_sz    = input->region_boundary[i] - (uint)cur_offset,
        .is_writable  = 1U,
      };
    }
  }

  fd_sbpf_calldests_t * calldests =
      fd_sbpf_calldests_join(
      fd_sbpf_calldests_new(
      aligned_alloc( fd_sbpf_calldests_align(), fd_sbpf_calldests_footprint( text_cnt ) ),
        text_cnt ) );

  fd_sbpf_syscalls_t * syscalls =
      fd_sbpf_syscalls_join(
      fd_sbpf_syscalls_new(
      aligned_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) ) );

  fd_valloc_t valloc = fd_libc_alloc_virtual();
  fd_exec_slot_ctx_t  * slot_ctx  = fd_valloc_malloc( valloc, FD_EXEC_SLOT_CTX_ALIGN,    FD_EXEC_SLOT_CTX_FOOTPRINT );

  fd_exec_instr_ctx_t * instr_ctx = test_vm_minimal_exec_instr_ctx( valloc, slot_ctx );

  int vm_ok = !!fd_vm_init(
      /* vm                 */ vm,
      /* instr_ctx          */ instr_ctx,
      /* heap_max           */ 0UL,
      /* entry_cu           */ 100UL,
      /* rodata             */ (uchar const *)text,
      /* rodata_sz          */ text_cnt * sizeof(ulong),
      /* text               */ text,
      /* text_cnt           */ text_cnt,
      /* text_off           */ 0UL,
      /* text_sz            */ text_cnt * sizeof(ulong),
      /* entry_pc           */ 0UL,
      /* calldests          */ calldests,
      /* sbpf_version       */ sbpf_version,
      /* syscalls           */ syscalls,
      /* trace              */ NULL,
      /* sha                */ NULL,
      /* mem_regions        */ input_region,
      /* mem_regions_cnt    */ input->region_boundary_cnt ? input->region_boundary_cnt : 1,
      /* mem_regions_accs   */ NULL,
      /* is_deprecated      */ 0,
      /* direct mapping     */ FD_FEATURE_ACTIVE( instr_ctx->txn_ctx->slot, &instr_ctx->txn_ctx->features, bpf_account_data_direct_mapping ),
      /* dump_syscall_to_pb */ 0
  );
  assert( vm_ok );

  for( uint i=0; i<REG_CNT; i++ ) {
    vm->reg[i] = input->reg[i];
  }

  run_input2( out, vm, force_exec );

  /* Clean up */
  fd_valloc_free( valloc, slot_ctx );
  test_vm_exec_instr_ctx_delete( instr_ctx, fd_libc_alloc_virtual() );
  free( fd_sbpf_syscalls_delete ( fd_sbpf_syscalls_leave ( syscalls  ) ) );
  free( fd_sbpf_calldests_delete( fd_sbpf_calldests_leave( calldests ) ) );
  free( input_copy );
}

/* run_fixture runs a test fixture.  Returns 1 if the local execution
   result matches the expected result.  Otherwise logs details about the
   mismatch and returns 0. */

static int
run_fixture( test_fixture_t const * f,
             char const *           src_file,
             fd_vm_t *              vm,
             ulong                  sbpf_version ) {

  int fail = 0;

  test_effects_t const * expected  = &f->effects;
  test_effects_t         actual[1] = {{0}};
  run_input( &f->input, actual, vm, sbpf_version, expected->force_exec );

  if( expected->status != actual->status ) {
    FD_LOG_WARNING(( "FAIL %s(%lu): Expected status %s, got %s",
                     src_file, f->line,
                     test_status_str( expected->status ),
                     test_status_str( actual  ->status ) ));
    fail = 1;
  }

  if( ( expected->status != STATUS_OK ) |
      ( actual  ->status != STATUS_OK ) ) {
    return fail;
  }

  for( uint i=0; i<REG_CNT; i++ ) {
    ulong reg_expected = expected->reg[i];
    ulong reg_actual   = actual  ->reg[i];
    if( reg_expected != reg_actual ) {
      FD_LOG_WARNING(( "FAIL %s(%lu): Expected r%u = %#lx, got %#lx",
                       src_file, f->line, i, reg_expected, reg_actual ));
      fail = 1;
    }
  }

  return fail;
}

/* Plumbing ***********************************************************/

static int
handle_file( char const * file_path,
             fd_vm_t *    vm,
             ulong        sbpf_version ) {

  int fd = open( file_path, O_RDONLY );
  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_ERR(( "open(%s) failed (%d-%s)", file_path, errno, fd_io_strerror( errno ) ));
  }

  struct stat st;
  if( FD_UNLIKELY( 0!=fstat( fd, &st ) ) ) {
    FD_LOG_ERR(( "stat(%s) failed (%d-%s)", file_path, errno, fd_io_strerror( errno ) ));
  }

  char * buf = malloc( (ulong)st.st_size );
  assert( buf );

  if( FD_UNLIKELY( st.st_size!=read( fd, buf, (ulong)st.st_size ) ) ) {
    FD_LOG_ERR(( "read(%s) failed (%d-%s)", file_path, errno, fd_io_strerror( errno ) ));
  }

  test_parser_t parser = {
    .path      = file_path,
    .cur       = buf,
    .end       = buf + st.st_size,
    .line      = 1UL,
    .test_line = 1UL,
    .state     = PARSE_STATE_INPUT
  };

  int fail = 0;
  for(;;) {
    test_fixture_t _f[1] = {{0}};
    test_fixture_t * f = NULL;
    f = parse_next( &parser, _f );
    if( !f ) break;
    fail += run_fixture( f, file_path, vm, sbpf_version );
  }

  if( FD_UNLIKELY( 0!=close( fd ) ) ) {
    FD_LOG_ERR(( "close(%d) failed (%d-%s)", fd, errno, fd_io_strerror( errno ) ));
  }

  free( (void *)parser.input.input );
  free( buf );

  return fail;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"                 );
  ulong        page_cnt       = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL                        );
  ulong        numa_idx       = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx(cpu_idx) );

  /* TODO set up a workspace */
  (void)_page_sz; (void)page_cnt; (void)numa_idx;

  static fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );

  /* Execute all arguments that don't look like flags */

  int   fail = 0;
  ulong executed_cnt = 0UL;
  int   literal      = 0;
  for( int i=1; i<argc; i++ ) {
    int flag = 0==strncmp( argv[i], "--", 2 );
    if( literal || !flag ) {
      fail += handle_file( argv[i], vm, TEST_VM_DEFAULT_SBPF_VERSION );
      executed_cnt += 1;
    } else {
      if( argv[i][2] == '\0' ) literal = 1;
      continue;
    }
  }

  /* No arguments given?  Execute default paths */

  if( !executed_cnt ) {
    {
      char const * default_paths[] = {
        "src/flamenco/vm/instr_test/v0/opcode.instr",
        "src/flamenco/vm/instr_test/v0/bitwise.instr",
        "src/flamenco/vm/instr_test/v0/int_math.instr",
        "src/flamenco/vm/instr_test/v0/jump.instr",
        "src/flamenco/vm/instr_test/v0/load.instr",
        "src/flamenco/vm/instr_test/v0/shift.instr",
        NULL
      };
      for( char const ** path=default_paths; *path; path++ ) {
        fail += handle_file( *path, vm, 0 );
      }
      if( !fail ) FD_LOG_NOTICE(( "v0 pass" ));
      else        FD_LOG_WARNING(( "v0 fail cnt %d", fail ));
    }

    {
      char const * default_paths[] = {
        "src/flamenco/vm/instr_test/v2/opcode.instr",
        "src/flamenco/vm/instr_test/v2/bitwise.instr",
        "src/flamenco/vm/instr_test/v2/int_math.instr",
        "src/flamenco/vm/instr_test/v2/jump.instr",
        "src/flamenco/vm/instr_test/v2/load.instr",
        "src/flamenco/vm/instr_test/v2/shift.instr",
        NULL
      };
      for( char const ** path=default_paths; *path; path++ ) {
        fail += handle_file( *path, vm, 2 );
      }
      if( !fail ) FD_LOG_NOTICE(( "v2 pass" ));
      else        FD_LOG_WARNING(( "v2 fail cnt %d", fail ));
    }
  }

  if( !fail ) FD_LOG_NOTICE(( "pass" ));
  else        FD_LOG_WARNING(( "fail cnt %d", fail ));

  fd_halt();
  return fail;
}

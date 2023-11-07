#include "../fd_flamenco.h"
#include "fd_types.h"

/* This test program ensures that fd_types_walk generates a correct
   sequence of AST walk instructions. */

/* fd_flamenco_type_step_t holds values recorded during an invocation
   to the fd_types_walk_fn_t callback function. */

struct fd_flamenco_type_step {
  uint level;
  int  type;
  char const * name;
  void const * data;
};

typedef struct fd_flamenco_type_step fd_flamenco_type_step_t;

/* The fd_flamenco_walk_recorder_t class provides the fd_types_walk_fn_t
   method, and holds a buffer of fd_flamenco_type_step_t values. */

#define STEPS_MAX (512UL)

struct fd_flamenco_walk_recorder {
  fd_flamenco_type_step_t steps[ STEPS_MAX ];
  ulong                   step_cnt;
};

typedef struct fd_flamenco_walk_recorder fd_flamenco_walk_recorder_t;

void
fd_flamenco_walk_recorder( void *       _self,
                           void const * arg,
                           char const * name,
                           int          type,
                           char const * type_name,
                           uint         level ) {

  (void)type_name;

  fd_flamenco_walk_recorder_t * self = (fd_flamenco_walk_recorder_t *)_self;

  FD_TEST( self->step_cnt < STEPS_MAX );

  self->steps[ self->step_cnt ] = (fd_flamenco_type_step_t) {
    .level = level,
    .type  = type,
    .name  = name,
    .data  = arg
  };
  self->step_cnt++;
}

/* Save instance of recorder in .bss due to stack size constraints.
   No need to zero initialize, as declared static / in .bss. */

static fd_flamenco_walk_recorder_t recorder[1];

/* Random vote account captured in a test ledger */

FD_IMPORT_BINARY( vote_account_bin, "src/flamenco/types/fixtures/vote_account.bin" );

/* Expected sequence of steps */

static const fd_flamenco_type_step_t vote_account_walk[] = {
  { .level=0, .type = FD_FLAMENCO_TYPE_MAP },
  { .level=1, .type = FD_FLAMENCO_TYPE_MAP,     .name = "current" },
  { .level=2, .type = FD_FLAMENCO_TYPE_HASH256, .name = "node_pubkey",
    .data = (void const *)( vote_account_bin+0x04 ) },
  { .level=2, .type = FD_FLAMENCO_TYPE_HASH256, .name = "authorized_withdrawer",
    .data = (void const *)( vote_account_bin+0x24 ) },
  { .level=2, .type = FD_FLAMENCO_TYPE_UCHAR,   .name = "commission",
    .data = (void const *)( vote_account_bin+0x44 ) },
  { .level=2, .type = FD_FLAMENCO_TYPE_ARR,     .name = "votes" },
  { .level=3, .type = FD_FLAMENCO_TYPE_MAP },
  { .level=4, .type = FD_FLAMENCO_TYPE_UCHAR,   .name = "latency" },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP,     .name = "lockout" },
  { .level=5, .type = FD_FLAMENCO_TYPE_ULONG,   .name = "slot" },
  { .level=5, .type = FD_FLAMENCO_TYPE_UINT,    .name = "confirmation_count" },
  { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=3, .type = FD_FLAMENCO_TYPE_ARR_END },
  { .level=2, .type = FD_FLAMENCO_TYPE_ULONG,   .name = "root_slot" },
  { .level=2, .type = FD_FLAMENCO_TYPE_MAP,     .name = "authorized_voters" },
  { .level=3, .type = FD_FLAMENCO_TYPE_MAP },
  { .level=4, .type = FD_FLAMENCO_TYPE_ULONG,   .name = "epoch" },
  { .level=4, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=3, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=2, .type = FD_FLAMENCO_TYPE_MAP,     .name = "prior_voters" },
  { .level=3, .type = FD_FLAMENCO_TYPE_ARR,     .name = "buf" },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP }, { .level=5, .type = FD_FLAMENCO_TYPE_HASH256, .name = "pubkey" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_start" }, { .level=5, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch_end" }, { .level=5, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=4, .type = FD_FLAMENCO_TYPE_ARR_END },
  { .level=3, .type = FD_FLAMENCO_TYPE_ULONG, .name = "idx" },
  { .level=3, .type = FD_FLAMENCO_TYPE_UCHAR, .name = "is_empty" },
  { .level=3, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=2, .type = FD_FLAMENCO_TYPE_ARR, .name = "epoch_credits" },
  { .level=3, .type = FD_FLAMENCO_TYPE_MAP },
  { .level=4, .type = FD_FLAMENCO_TYPE_ULONG, .name = "epoch" },
  { .level=4, .type = FD_FLAMENCO_TYPE_ULONG, .name = "credits" },
  { .level=4, .type = FD_FLAMENCO_TYPE_ULONG, .name = "prev_credits" },
  { .level=4, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=3, .type = FD_FLAMENCO_TYPE_ARR_END },
  { .level=2, .type = FD_FLAMENCO_TYPE_MAP, .name = "last_timestamp" },
  { .level=3, .type = FD_FLAMENCO_TYPE_ULONG, .name = "slot" },
  { .level=3, .type = FD_FLAMENCO_TYPE_ULONG, .name = "timestamp" },
  { .level=3, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=2, .type = FD_FLAMENCO_TYPE_MAP_END },
  { .level=1, .type = FD_FLAMENCO_TYPE_MAP_END },
  {0}
};


static void
test_vote_account_walk( void ) {

  FD_SCRATCH_SCOPED_FRAME;

  /* Decode bincode blob */

  fd_bincode_decode_ctx_t decode[1] = {{
    .data    = vote_account_bin,
    .dataend = vote_account_bin + vote_account_bin_sz,
    .valloc  = fd_scratch_virtual()
  }};
  fd_vote_state_versioned_t state[1];
  int err = fd_vote_state_versioned_decode( state, decode );
  FD_TEST( err==FD_BINCODE_SUCCESS );

  /* Walk with recorder */

  fd_vote_state_versioned_walk( recorder, state, fd_flamenco_walk_recorder, NULL, 0 );

  /* Diff by concurrent iterate */

  ulong i;
  for( i=0UL; i < recorder->step_cnt; i++ ) {

    fd_flamenco_type_step_t const * expect = &vote_account_walk[i];
    fd_flamenco_type_step_t const * actual = &recorder->steps  [i];

    if( (!expect->level) & (!expect->type) ) break;

    if( ( actual->level != expect->level )
      | ( actual->type  != expect->type  ) ) {

      FD_LOG_WARNING(( "Mismatch at step %lu", i ));
      FD_LOG_WARNING(( "Expected\n"
                       "  level: %u\n"
                       "  type:  %#x\n"
                       "  name:  %s\n",
                       expect->level,
                       expect->type,
                       expect->name ));
      FD_LOG_WARNING(( "Actual\n"
                       "  level: %u\n"
                       "  type:  %#x\n"
                       "  name:  %s\n",
                       recorder->steps[i].level,
                       recorder->steps[i].type,
                       recorder->steps[i].name ));
      FD_LOG_ERR(( "fail" ));
    }
  }
  FD_TEST( ( i==recorder->step_cnt       )
         & ( !vote_account_walk[i].level ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  static uchar scratch_mem [ 1<<25 ];  /* 32 MiB */
  static ulong scratch_fmem[ 4UL ] __attribute((aligned(FD_SCRATCH_FMEM_ALIGN)));
  fd_scratch_attach( scratch_mem, scratch_fmem, 1UL<<25, 4UL );

  test_vote_account_walk();

  FD_LOG_NOTICE(( "pass" ));
  FD_TEST( fd_scratch_frame_used()==0UL );
  fd_scratch_detach( NULL );
  fd_flamenco_halt();
  fd_halt();
  return 0;
}

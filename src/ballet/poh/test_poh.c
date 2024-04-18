#include "../fd_ballet.h"

/* Ensure that calling fd_poh_append with zero iterations is nop. */
static void
test_poh_append_nop( void ) {
  uchar poh[FD_SHA256_HASH_SZ] = {0};

  /* Make up a pattern */
  uchar want[FD_SHA256_HASH_SZ];
  for( ulong i=0UL; i<FD_SHA256_HASH_SZ; i++ ) want[i] = (uchar)(0x40UL+i);
  fd_memcpy( &poh, want, FD_SHA256_HASH_SZ );

  /* Call fd_poh_append with zero iters */
  fd_poh_append( &poh, 0UL );

  /* PoH state should be untouched */
  FD_TEST( !memcmp( &poh, want, FD_SHA256_HASH_SZ ) );
}

/* Ensure that one round of fd_poh_append matches the simple hashing API. */
static void
test_poh_append_one( void ) {
  /* Make up a pattern */
  uchar pre[FD_SHA256_HASH_SZ];
  for( ulong i=0UL; i<FD_SHA256_HASH_SZ; i++ ) pre[i] = (uchar)(0x40UL+i);

  /* One round of PoH append */
  uchar poh[FD_SHA256_HASH_SZ] = {0};
  fd_memcpy( &poh, pre, FD_SHA256_HASH_SZ );
  fd_poh_append( &poh, 1UL );

  /* SHA-256 simple API */
  fd_sha256_t sha;
  fd_sha256_init( &sha );
  fd_sha256_append( &sha, pre, sizeof(pre) );
  uchar expected[FD_SHA256_HASH_SZ];
  fd_sha256_fini( &sha, &expected );

  if( FD_UNLIKELY( memcmp( &poh, expected, FD_SHA256_HASH_SZ ) ) ) {
    FD_LOG_ERR(( "FAIL (test_poh_append_one)"
                 "\n\tGot"
                 "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                 "\n\tExpected"
                 "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
                 FD_LOG_HEX16_FMT_ARGS( poh      ), FD_LOG_HEX16_FMT_ARGS( poh     +16 ),
                 FD_LOG_HEX16_FMT_ARGS( expected ), FD_LOG_HEX16_FMT_ARGS( expected+16 ) ));
  }
}

/* Ensure that fd_poh_mixin matches the simple hashing API. */
static void
test_poh_mixin( void ) {
  /* Make up a pattern */
  uchar pre[FD_SHA256_HASH_SZ];
  for( ulong i=0UL; i<FD_SHA256_HASH_SZ; i++ ) pre[i]  =(uchar)(0x40UL+i);

  uchar mixin[FD_SHA256_HASH_SZ];
  for( ulong i=0UL; i<FD_SHA256_HASH_SZ; i++ ) mixin[i]=(uchar)(0x60UL+i);

  /* Execute a PoH mixin */
  uchar poh[FD_SHA256_HASH_SZ] = {0};
  fd_memcpy( &poh, pre, FD_SHA256_HASH_SZ );
  fd_poh_mixin( &poh, mixin );

  /* SHA-256 simple API */
  fd_sha256_t sha;
  fd_sha256_init( &sha );
  fd_sha256_append( &sha, pre,   sizeof(pre)   );
  fd_sha256_append( &sha, mixin, sizeof(mixin) );
  uchar expected[FD_SHA256_HASH_SZ];
  fd_sha256_fini( &sha, &expected );

  if( FD_UNLIKELY( memcmp( &poh, expected, FD_SHA256_HASH_SZ ) ) ) {
    FD_LOG_ERR(( "FAIL (test_poh_mixin)"
                 "\n\tGot"
                 "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                 "\n\tExpected"
                 "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
                 FD_LOG_HEX16_FMT_ARGS( poh      ), FD_LOG_HEX16_FMT_ARGS( poh     +16 ),
                 FD_LOG_HEX16_FMT_ARGS( expected ), FD_LOG_HEX16_FMT_ARGS( expected+16 ) ));
  }
}

struct fd_poh_test_step {
  /* mixin: Value to pass to fd_poh_mixin */
  uchar mixin[FD_SHA256_HASH_SZ] __attribute__((aligned(32)));

  /* n: number of iterations to pass to fd_poh_append.
     If 0, call fd_poh_mixin instead.
     If -1, reached end of list. */
  int n;
};

typedef struct fd_poh_test_step fd_poh_test_step_t;

struct fd_poh_test_vector {
  uchar pre [32]  __attribute__((aligned(32)));
  uchar post[32]  __attribute__((aligned(32)));
  char const * name;
  fd_poh_test_step_t const * steps;
};

typedef struct fd_poh_test_vector fd_poh_test_vector_t;

static void
test_poh_vector( fd_poh_test_vector_t const * t ) {
  uchar poh[32];
  memcpy( poh, t->pre, 32UL );
  for( fd_poh_test_step_t const * step = t->steps; step->n >= 0; step++ ) {
    if( FD_UNLIKELY( step->n == 0 ) ) {
      fd_poh_mixin( &poh, step->mixin );
    } else {
      fd_poh_append( &poh, (ulong)step->n );
    }
  }

  if( FD_UNLIKELY( memcmp( &poh, &t->post, FD_SHA256_HASH_SZ ) ) ) {
    FD_LOG_ERR(( "FAIL (%s)"
                 "\n\tGot"
                 "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                 "\n\tExpected"
                 "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
                 t->name,
                 FD_LOG_HEX16_FMT_ARGS( poh     ), FD_LOG_HEX16_FMT_ARGS( poh    +16 ),
                 FD_LOG_HEX16_FMT_ARGS( t->post ), FD_LOG_HEX16_FMT_ARGS( t->post+16 ) ));
  } else {
    FD_LOG_NOTICE(( "OK (%s)", t->name ));
  }
}

#define _(v) ((uchar)0x##v)

// Source: https://github.com/solana-foundation/specs/blob/main/core/poh.md

static fd_poh_test_step_t const solana_mainnet_block_0_steps[] = {
  { .n = 800000 },
  { .n = -1 }
};

static fd_poh_test_step_t const solana_mainnet_block_1_steps[] = {
  { .n =  14612 },
  { .mixin = { _(c9),_(5f),_(2f),_(13),_(a9),_(a7),_(7f),_(32),_(b1),_(43),_(79),_(76),_(c4),_(cf),_(fe),_(30),_(29),_(29),_(8a),_(49),_(bf),_(37),_(00),_(7f),_(8e),_(45),_(d7),_(93),_(a5),_(20),_(f3),_(0b) } },
  { .n = 210347 },
  { .mixin = { _(1a),_(ae),_(eb),_(36),_(61),_(1f),_(48),_(4d),_(98),_(46),_(83),_(a3),_(db),_(92),_(69),_(f2),_(29),_(2d),_(d9),_(bb),_(81),_(bd),_(ab),_(82),_(b2),_(8c),_(45),_(62),_(5d),_(9a),_(bd),_(59) } },
  { .n = 428775 },
  { .mixin = { _(db),_(31),_(e8),_(61),_(b3),_(10),_(f4),_(49),_(54),_(40),_(3e),_(34),_(5b),_(6b),_(ee),_(b3),_(de),_(d3),_(40),_(84),_(b9),_(06),_(94),_(bc),_(ca),_(a2),_(34),_(53),_(06),_(d3),_(66),_(e1) } },
  { .n = 146263 },
  { .n = -1 }
};

static fd_poh_test_vector_t const poh_test_vectors[] = {
  {
    .name  = "Solana mainnet block 0",
    .pre   = { _(45),_(29),_(69),_(98),_(a6),_(f8),_(e2),_(a7),_(84),_(db),_(5d),_(9f),_(95),_(e1),_(8f),_(c2),_(3f),_(70),_(44),_(1a),_(10),_(39),_(44),_(68),_(01),_(08),_(98),_(79),_(b0),_(8c),_(7e),_(f0) },
    .post  = { _(39),_(73),_(e3),_(30),_(c2),_(9b),_(83),_(1f),_(3f),_(cb),_(0e),_(49),_(37),_(4e),_(d8),_(d0),_(38),_(8f),_(41),_(0a),_(23),_(e4),_(eb),_(f2),_(33),_(28),_(50),_(50),_(36),_(ef),_(bd),_(03) },
    .steps = solana_mainnet_block_0_steps
  },
  {
    .name  = "Solana mainnet block 1",
    .pre   = { _(39),_(73),_(e3),_(30),_(c2),_(9b),_(83),_(1f),_(3f),_(cb),_(0e),_(49),_(37),_(4e),_(d8),_(d0),_(38),_(8f),_(41),_(0a),_(23),_(e4),_(eb),_(f2),_(33),_(28),_(50),_(50),_(36),_(ef),_(bd),_(03) },
    .post  = { _(8e),_(e2),_(06),_(07),_(dc),_(f1),_(d9),_(39),_(3c),_(f5),_(a2),_(f2),_(c9),_(f7),_(ba),_(be),_(16),_(7d),_(bd),_(d2),_(67),_(49),_(1b),_(51),_(3c),_(73),_(d2),_(cb),_(f8),_(74),_(13),_(f5) },
    .steps = solana_mainnet_block_1_steps
  },
  { .name = NULL }
};

#undef _

static void
bench_poh_sequential( void ) {
  uchar poh[FD_SHA256_HASH_SZ] = {0};

  ulong batch_sz = 1024;

  /* warmup */
  ulong iter = 1000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) fd_poh_append( &poh, batch_sz );
  dt = fd_log_wallclock() - dt;

  /* for real */
  iter = 100000UL;
  dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) fd_poh_append( &poh, batch_sz );
  dt = fd_log_wallclock() - dt;

  ulong hashes = iter*batch_sz;
  double secs = (double)dt / 1e9;
  FD_LOG_NOTICE(( "PoH sequential: ~%.3f MH/s", ((double)hashes/secs)/1e6 ));
}

int main( int argc,
          char ** argv ) {
  fd_boot( &argc, &argv );

  test_poh_append_nop();
  test_poh_append_one();

  test_poh_mixin();

  for( fd_poh_test_vector_t const * v = poh_test_vectors; v->name; v++ ) {
    test_poh_vector( v );
  }

  bench_poh_sequential();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

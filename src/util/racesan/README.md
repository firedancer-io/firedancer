# racesan: data race detector

racesan is a fuzzer for shared memory concurrent algorithms.
It mainly serves to test Firedancer database components on x86 (TSO).

racesan currently offers two modes of testing "targets" (instrumented
concurrent algorithms)

- fault injection: inject modifications while a target is running
- interleaving: race targets against each other

Developers can use racesan to write tests proving that concurrent
algorithms have sound logic.  However, racesan is unable to detect true
hardware data races (e.g. cache coherence-related bugs, torn reads).

Internally, racesan uses various compiler tricks to create interleavings
of prod algorithms and injected test code.  Namely, userland context
switching (`ucontext.h`) and callbacks hidden in macros.

## Context

Unlike Valgrind DRD or ThreadSanitizer, racesan ...

- requires code changes to target code
- works with low-level concurrency primitives (compiler fences, volatile
  accesses, `_mm_mfence()`, ...)
- provides less complete detection (detects logic errors but not true
  data races)
- is single-threaded
- is deterministic

## Usage

To use racesan, insert _hooks_ at critical sections of your shared
memory concurrent algorithms.

Consider this silly compare-and-swap based adder example:

```c
static void
cas_inc( uint * p ) {
  for(;;) {
    uint v = FD_VOLATILE_CONST( *p );
    if( FD_LIKELY( __sync_bool_compare_and_swap( p, v, v+1U ) ) ) break;
    FD_LOG_WARNING(( "overrun, retrying" ));
  }
}
```

This algorithm loads a number, adds one to it, and writes it back.
In production, a data race can occur between the load and the store.

We want to emulate this possible data race with racesan.  So, we add
a hook just after the load.  The instrumented version now looks as
follows.  racesan can now mock concurrent access to `*p` by running
logic at the hook point.

```c
static void
cas_inc( uint * p ) {
  for(;;) {
    uint v = FD_VOLATILE_CONST( *p );
    fd_racesan_hook( "cas_inc:post_load" );
    if( FD_LIKELY( __sync_bool_compare_and_swap( p, v, v+1U ) ) ) break;
    FD_LOG_WARNING(( "overrun, retrying" ));
  }
}
```

The name of the hook (`"cas_inc:post_load"`) is arbitrary.  Per
convention, we use `<algorithm name>:<critical section name>`.

## Methods

### Fault Injection (callback style)

Let's inject a data race.  The simplest way to do this is to inject a
callback that's invoked any time a hook is executed.  Since the
`cas_inc` algorithm runs indefinitely, the callback routine keeps some
state to only run once.

```c
static uint g_seq; /* shared variable */

/* The error inject routine.  This looks racy on first sight, but
   racesan guarantees that logic in fault inject routines always runs
   atomically. */

static void
inject_cas_inc_fault( void * ctx, ulong name_hash ) {
  (void)ctx;
  (void)name_hash;
  static uint injected = 0;
  if( !injected ) { /* Inject a racy increment once */
    FD_VOLATILE( g_seq ) = FD_VOLATILE_CONST( g_seq )+1U;
    injected = 1;
  }
}

void
test_cas_inc( void ) {
  fd_racesan_t racesan[1];
  FD_TEST( fd_racesan_new( racesan, NULL ) );

  fd_racesan_inject( racesan, "cas_inc:post_load", inject_cas_inc_fault );

  /* Set up initial state */
  FD_VOLATILE( g_seq ) = 0U;

  /* Run the target algorithm with hooks injected */
  FD_RACESAN_INJECT_BEGIN( racesan ) {
    cas_inc( &g_seq );
  }
  FD_RACESAN_INJECT_END;

  /* Verify resulting state */
  FD_TEST( FD_VOLATILE_CONST( g_seq )==2U );

  fd_racesan_delete( racesan );
}
```

### Fault injection (async style)

Another way to write this test is to suspend the target whenever it
reaches a hook.

```c
static uint g_seq; /* shared variable */

/* The async target.  Suspends using longjmp */

static void
cas_inc_async( void * ctx ) {
  (void)ctx;
  cas_inc( &g_seq );
}

void
test_cas_inc_async( void ) {
  fd_racesan_async_t async[1];
  FD_TEST( fd_racesan_async_new( async, cas_inc_async, NULL ) );

  FD_VOLATILE( g_seq ) = 0U;

  /* Start up target */
  FD_TEST( fd_racesan_async_step( async ) );
  FD_TEST( fd_racesan_async_hook_name_eq( async, "cas_inc:post_load" ) );
  /* At this point, target has loaded g_seq, but not yet stored it back */

  /* Inject race */
  FD_TEST( FD_VOLATILE_CONST( g_seq )==0U );
  FD_TEST( FD_VOLATILE( g_seq )==1U );

  /* Ensure that target recovers and does another iteration */
  FD_TEST( fd_racesan_async_step( async ) );
  FD_TEST( fd_racesan_async_hook_name_eq( async, "cas_inc:post_load" ) );
  FD_TEST( !fd_racesan_async_step( async ) ); /* done */

  FD_TEST( FD_VOLATILE_CONST( g_seq )==2U );

  fd_racesan_async_delete( async );
  fd_racesan_delete( racesan );
}
```

### Interleaving

racesan allows racing algorithms against one another.

Races between real routines are typically more complex than
what can practically be modelled with fault injection.

Consider the following scenario:
- Routine 1: atomically multiply number by 2
- Routine 2: atomically increment number by 1
- Initial state: number is 5

Valid results are 11 (routine 1 first) and 12 (routine 2 first).  Data
races between the algorithms could shadow effects, producing invalid
outcomes like 6 or 10.

```c
static uint g_seq; /* shared variable */

static void
cas_dbl_async( void * ctx ) {
  (void)ctx;
  for(;;) {
    uint v = FD_VOLATILE_CONST( g_seq );
    fd_racesan_hook( "cas_dbl:post_load" );
    if( FD_LIKELY( __sync_bool_compare_and_swap( &g_seq, v, (v<<1) ) ) ) break;
    FD_LOG_WARNING(( "overrun, retrying" ));
  }
}

static void
cas_inc_async( void * ctx ) {
  (void)ctx;
  for(;;) {
    uint v = FD_VOLATILE_CONST( g_seq );
    fd_racesan_hook( "cas_inc:post_load" );
    if( FD_LIKELY( __sync_bool_compare_and_swap( &g_seq, v, v+1U ) ) ) break;
    FD_LOG_WARNING(( "overrun, retrying" ));
  }
}

void
test_cas_race( void ) {
  fd_racesan_weave_t weave[1];
  FD_TEST( fd_racesan_weave_new( weave ) );

  fd_racesan_async_t async_dbl[1];
  FD_TEST( fd_racesan_async_new( async_dbl, cas_dbl_async, NULL ) );
  fd_racesan_weave_add( weave, async_dbl );

  fd_racesan_async_t async_inc[1];
  FD_TEST( fd_racesan_async_new( async_inc, cas_inc_async, NULL ) );
  fd_racesan_weave_add( weave, async_inc );

  /* Run random interleavings */
  ulong iter     = (ulong)1e6;
  ulong step_max = 1024UL;
  for( ulong rem=iter; rem; rem-- ) {
    FD_VOLATILE( g_seq ) = 5U;
    fd_racesan_weave_exec_rand( weave, rem, step_max );
    uint res = FD_VOLATILE_CONST( g_seq );
    FD_TEST( res==11U || res==12U );
  }

  fd_racesan_weave_delete( weave );
  fd_racesan_async_delete( async_dbl );
  fd_racesan_async_delete( async_inc );
}
```

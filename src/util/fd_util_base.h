#ifndef HEADER_fd_src_util_fd_util_base_h
#define HEADER_fd_src_util_fd_util_base_h

/* Base development environment */

/* Versioning macros **************************************************/

/* FD_VERSION_{MAJOR,MINOR,PATCH} programmatically specify the
   firedancer version. */

#define FD_VERSION_MAJOR 0
#define FD_VERSION_MINOR 0
#define FD_VERSION_PATCH 0

/* Build target capabilities ******************************************/

/* Different build targets often have different levels of support for
   various language and hardware features.  The presence of various
   features can be tested at preprocessor, compile, or run time via the
   below capability macros.

   Code that does not exploit any of these capabilities written within
   the base development environment should be broadly portable across a
   range of build targets ranging from on-chain virtual machines to
   commodity hosts to custom hardware.

   As such, highly portable yet high performance code is possible by
   writing generic implementations that do not exploit any of the below
   capabilities as a portable fallback along with build target specific
   optimized implementations that are invoked when the build target
   supports the appropriate capabilities.
   
   The base development itself provide lots of functionality to help
   with implementing portable fallbacks while making very minimal
   assumptions about the build targets and zero use of 3rd party
   libraries (these might make unknown additional assumptions about the
   build target, including availability of a quality implementation of
   the library on the build target). */

/* FD_HAS_HOSTED:  If the build target is hosted (e.g. resides on a host
   with a POSIX-ish environment ... practically speaking, stdio.h,
   stdlib.h, unistd.h, et al more or less behave normally ...
   pedantically XOPEN_SOURCE=700), FD_HAS_HOSTED will be 1.  It will be
   zero otherwise. */

#ifndef FD_HAS_HOSTED
#define FD_HAS_HOSTED 0
#endif

/* FD_HAS_ATOMIC:  If the build target supports atomic operations
   between threads accessing a common memory region (include threads
   that reside in different processes on a host communicating via a
   shared memory region with potentially different local virtual
   mappings).  Practically speaking, does atomic compare-and-swap et al
   work? */

#ifndef FD_HAS_ATOMIC
#define FD_HAS_ATOMIC 0
#endif

/* FD_HAS_THREADS:  If the build target supports a POSIX-ish notion of
   threads (e.g. practically speaking, global variables declared within
   a compile unit are visible to more than one thread of execution,
   pthreads.h / threading parts of C standard, the atomics parts of the
   C standard, ... more or less work normally), FD_HAS_THREADS will be
   1.  It will be zero otherwise.  FD_HAS_THREADS implies FD_HAS_HOSTED
   and FD_HAS_ATOMIC. */

#ifndef FD_HAS_THREADS
#define FD_HAS_THREADS 0
#endif

/* FD_HAS_INT128:  If the build target supports reasonably efficient
   128-bit wide integer operations, define FD_HAS_INT128 to 1 to enable
   use of them in implementations. */

#ifndef FD_HAS_INT128
#define FD_HAS_INT128 0
#endif

/* FD_HAS_DOUBLE:  If the build target supports reasonably efficient
   IEEE 754 64-bit wide double precision floating point options, define
   FD_HAS_DOUBLE to 1 to enable use of them in implementations.  Note
   that even if the build target does not, va_args handling in the C /
   C++ language requires promotion of a float in an va_arg list to a
   double.  Thus, C / C++ language that support IEEE 754 float also
   implies a minimum level of support for double (though not necessarily
   efficient or IEEE 754).  That is, even if a target does not have
   FD_HAS_DOUBLE, there might still be limited use of double in va_arg
   list handling. */

#ifndef FD_HAS_DOUBLE
#define FD_HAS_DOUBLE 0
#endif

/* FD_HAS_X86:  If the build target supports x86 specific features and
   can benefit from x86 specific optimizations, define FD_HAS_X86.  Code
   needing more specific target features (Intel / AMD / SSE / AVX2 /
   AVX512 / etc) can specialize further as necessary with even more
   precise capabilities (that in turn imply FD_HAS_X86). */

#ifndef FD_HAS_X86
#define FD_HAS_X86 0
#endif

/* Base development environment ***************************************/

/* The functionality provided by these vanilla headers are always
   available within the base development environment.  Notably, stdio.h
   / stdlib.h / et at are not included here as these make lots of
   assumptions about the build target that may not be true (especially
   for on-chain and custom hardware use).  Code should prefer the fd
   util equivalents for such functionality when possible. */

#include <stdalign.h>
#include <string.h>
#include <limits.h>
#include <float.h>

/* Work around some library naming irregularites */
/* FIXME: Consider this for FLOAT/FLT, DOUBLE/DBL too? */

#define  SHORT_MIN  SHRT_MIN
#define  SHORT_MAX  SHRT_MAX
#define USHORT_MAX USHRT_MAX

/* Primitive types ****************************************************/

/* These typedefs provide single token regularized names for all the
   primitive types in the base development environment:

     char !
     schar !   short   int   long   int128 !!
     uchar    ushort  uint  ulong  uint128 !!
     float
     double !!!

   ! Does not assume the sign of char.  A naked char should be treated
     as cstr character and mathematical operations should be avoided on
     them.  This is less than ideal as the patterns for integer types in
     the C/C++ language spec itself are far more consistent with a nake
     char naturally being treated as signed (see above).  But there are
     lots of conflicts between architectures, languages and standard
     libraries about this so any use of a naked char shouldn't assume
     the sign ...  sigh.

   !! Only available if FD_HAS_INT128 is defined

   !!! Should only used if FD_HAS_DOUBLE is defined but see note in
       FD_HAS_DOUBLE about C/C++ silent promotions of float to double in
       va_arg lists.

   Note also that these token names more naturally interoperate with
   integer constant declarations, type generic code generation
   techniques, with printf-style format strings than the stdint.h /
   inttypes.h handling.

   To minimize portability issues, unexpected silent type conversion
   issues, align with typical developer implicit usage, align with
   typical build target usage, ..., assumes char / short / int / long
   are 8 / 16 / 32 / 64 twos complement integers and float is IEEE-754
   single precision.  Further assumes little endian, truncating signed
   integer divison and sign extending (arithmetic) signed right shift.
   Also, except for int128/uint128, assumes that aligned access to these
   will be naturally atomic.  Lastly assumes that unaligned access to
   these is functionally valid but does not assume that unaligned access
   to these is efficient or atomic.

   For values meant to be held in registers, code should prefer long /
   ulong types (improves asm generation given the prevalence of 64-bit
   targets and also to avoid lots of tricky bugs with silent promotions
   in the language ... e.g. ushort should ideally only be used for
   in-memory representations).

   These are currently not prefixed given how often they are used.  If
   this becomes problematic prefixes can be added as necessary.
   Specifically, C++ allows typedefs to be defined multiple times so
   long as they are equivalent.  Inequivalent collisions are not
   supported but should be rare (e.g. if a 3rd party header thinks
   "ulong" should be something other an "unsigned long", the 3rd party
   header probably should be nuked from orbit).  C11 and forward also
   allow multiple equivalent typedefs.  C99 and earlier don't but this
   is typically only a warning and then only if pedantic warnings are
   enabled.  Thus, if we want to support users using C99 and earlier who
   want to do a strict compile and have a superfluous collision with
   these types in other libraries, uncomment the below (or do something
   equivalent for the compiler). */

//#pragma GCC diagnostic push
//#pragma GCC diagnostic ignored "-Wpedantic"

typedef signed char schar; /* See above note of sadness */

typedef unsigned char  uchar;
typedef unsigned short ushort;
typedef unsigned int   uint;
typedef unsigned long  ulong;

#if FD_HAS_INT128

__extension__ typedef          __int128  int128;
__extension__ typedef unsigned __int128 uint128;

#define UINT128_MAX (~(uint128)0)
#define  INT128_MAX ((int128)(UINT128_MAX>>1))
#define  INT128_MIN (-INT128_MAX-(int128)1)

#endif

//#pragma GCC diagnostic pop

/* Compiler tricks ****************************************************/

/* FD_STRINGIFY,FD_CONCAT{2,3,4}:  Various macros for token
   stringification and pasting.  FD_STRINGIFY returns the argument as a
   cstr (e.g. FD_STRINGIFY(foo) -> "foo").  FD_CONCAT* pastes the tokens
   together into a single token (e.g.  FD_CONCAT3(a,b,c) -> abc).  The
   EXPAND variants first expend their arguments and then do the token
   operation (e.g.  FD_EXPAND_THEN_STRINGIFY(__LINE__) -> "104" if done
   on line 104 of the source code file). */

#define FD_STRINGIFY(x)#x
#define FD_CONCAT2(a,b)a##b
#define FD_CONCAT3(a,b,c)a##b##c
#define FD_CONCAT4(a,b,c,d)a##b##c##d

#define FD_EXPAND_THEN_STRINGIFY(x)FD_STRINGIFY(x)
#define FD_EXPAND_THEN_CONCAT2(a,b)FD_CONCAT2(a,b)
#define FD_EXPAND_THEN_CONCAT3(a,b,c)FD_CONCAT3(a,b,c)
#define FD_EXPAND_THEN_CONCAT4(a,b,c,d)FD_CONCAT4(a,b,c,d)

/* FD_SRC_LOCATION returns a const cstr holding the line of code where
   FD_SRC_LOCATION was used. */

#define FD_SRC_LOCATION __FILE__ "(" FD_EXPAND_THEN_STRINGIFY(__LINE__) ")"

/* FD_STATIC_ASSERT tests at compile time if c is non-zero.  If not,
   it aborts the compile with an error.  err itself should be a token
   (e.g. not a string, no whitespace, etc). */

#define FD_STATIC_ASSERT(c,err) \
typedef char FD_EXPAND_THEN_CONCAT4(static_assert_failed_at_line_,__LINE__,_with_error_,err)[ (2*!!(c))-1 ]

/* FD_PROTOTYPES_{BEGIN,END}:  Headers that might be included in C++
   source should encapsulate the prototypes of code and globals
   contained in compilation units compiled as C with a
   FD_PROTOTYPE_{BEGIN,END} pair. */

#ifdef __cplusplus
#define FD_PROTOTYPES_BEGIN extern "C" {
#else
#define FD_PROTOTYPES_BEGIN
#endif

#ifdef __cplusplus
#define FD_PROTOTYPES_END }
#else
#define FD_PROTOTYPES_END
#endif

/* FD_RESTRICT is a pointer modifier for to designate a pointer as
   restricted.  Hoops jumped because C++-17 still doesn't understand
   restrict ... sigh */

#ifndef FD_RESTRICT
#ifdef __cplusplus
#define FD_RESTRICT __restrict
#else
#define FD_RESTRICT restrict
#endif
#endif

/* Optimizer hints ****************************************************/

/* FD_{LIKELY,UNLIKELY}(c):  Evaluates c and returns whether it is
   logical true/false as long (1L/0L).  It also hints to the optimizer
   whether it should optimize for the case of c evaluating as
   true/false. */

#define FD_LIKELY(c)   __builtin_expect( !!(c), 1L )
#define FD_UNLIKELY(c) __builtin_expect( !!(c), 0L )

/* FD_FN_PURE hints to the optimizer that the function, roughly
   speaking, does not have side effects.  As such, the compiler can
   replace a call to the function with the result of an earlier call to
   that function provide the inputs and memory used hasn't changed. */

#define FD_FN_PURE __attribute__((pure))

/* FD_FN_CONST is like pure but also, even stronger, indicates that the
   function does not depend on the state of memory. */

#define FD_FN_CONST __attribute__((const))

/* FD_FN_UNUSED indicates that it is okay if the function with static
   linkage is not used.  Allows working around -Winline in header only
   APIs where the compiler decides not to actually inline the function.
   (This belief, frequently promulagated by anti-macro cults, that "An
   Inline Function is As Fast As a Macro" ... an entire section in gcc's
   documentation devoted to it in fact ... remains among the biggest
   lies in computer science.  Yes, an inline function is as fast as a
   macro ... when the compiler actually decides to treat the inline
   keyword more than just for entertainment purposes only.  Which, as
   -Winline proves, it frequently doesn't.  Sigh ... force_inline like
   compiler extensions might be an alternative here but they have their
   own portability issues.) */

#define FD_FN_UNUSED __attribute__((unused))

/* FD_COMPILER_FORGET(var):  Tells the compiler that it shouldn't use
   any knowledge it has about the provided register-compatible variable
   var for optimizations going forward (i.e. the variable has changed in
   a deterministic but unknown-to-the-compiler way where the actual
   change is the identity operation).  Useful for inhibiting various
   branch nest misoptimizations (compilers unfortunately tend to
   radically underestimate the impact in raw average performance and
   jitter and the probability of branch mispredicts or the cost to the
   CPU of having lots of branches).  This is not asm volatile (use
   UNPREDICTABEL below for that) and has no clobbers.  So if var is not
   used after the forget, the compiler can optimize the FORGET away
   (along with operations preceeding it used to produce var). */

#define FD_COMPILER_FORGET(var) __asm__( "# FD_COMPILER_FORGET(" #var ")@" FD_SRC_LOCATION : "+r" (var) )

/* FD_COMPILER_UNPREDICTABLE(var):  Same as FD_COMPILER_FORGET(var) but
   the provided variable has changed in a non-deterministic way from the
   compiler's POV (e.g. the value in the variable on output should not
   be treated as a compile time constant even if it is one
   linguistically).  Useful for suppressing unwanted
   compile-time-const-based optimizations like hoisting operations with
   useful CPU side effects out of a critical loop. */

#define FD_COMPILER_UNPREDICTABLE(var) __asm__ __volatile__( "# FD_COMPILER_UNPREDICTABLE(" #var ")@" FD_SRC_LOCATION : "+r" (var) )

/* fd_type_pun(p), fd_type_pun_const(p):  These allow use of type
   punning while keeping strict aliasing optimizations enabled (e.g.
   some UNIX APIs, like sockaddr related APIs are dependent on type
   punning).  These allow these API's to be used cleanly while keeping
   strict aliasing optimizations enabled and strict alias checking done. */

static inline void *
fd_type_pun( void * p ) {
  __asm__( "# fd_type_pun @" FD_SRC_LOCATION : "+r" (p) :: "memory" );
  return p;
}

static inline void const *
fd_type_pun_const( void const * p ) {
  __asm__( "# fd_type_pun_const @" FD_SRC_LOCATION : "+r" (p) :: "memory" );
  return p;
}

/* FD_ADDRESS_OF_PACKED_MEMBER(x):  Linguistically does &(x) but without
   recent compiler complaints that &x might be unaligned if x is a
   member of a packed datastructure.  (Often needed for interfacing with
   hardware / packets / etc.) */

#define FD_ADDRESS_OF_PACKED_MEMBER( x ) (__extension__({                                      \
    char * _fd_aopm = (char *)&(x);                                                            \
    __asm__( "# FD_ADDRESS_OF_PACKED_MEMBER(" #x ") @" FD_SRC_LOCATION : "+r" (_fd_aopm) :: ); \
    (__typeof__(&(x)))_fd_aopm;                                                                \
  }))

/* Atomic tricks ******************************************************/

/* FD_COMPILER_MFENCE():  Tells the compiler that that it can't move any
   memory operations (load or store) from before the MFENCE to after the
   MFENCE (and vice versa).  The processor itself might still reorder
   around the fence though (that requires platform specific fences). */

#define FD_COMPILER_MFENCE() __asm__ __volatile__( "# FD_COMPILER_MFENCE()@" FD_SRC_LOCATION ::: "memory" )

/* FD_SPIN_PAUSE():  Yields the logical core of the calling thread to
   the other logical cores sharing the same underlying physical core for
   a few clocks without yielding it to the operating system scheduler.
   Typically useful for shared memory spin polling loops, especially if
   hyperthreading is in use. */

#if FD_HAS_X86
#define FD_SPIN_PAUSE() __builtin_ia32_pause()
#else
#define FD_SPIN_PAUSE() ((void)0)
#endif

/* FD_VOLATILE_CONST(x):  Tells the compiler is not able to predict the
   value obtained by dereferencing x and that deferencing x might have
   other side effects (e.g. maybe another thread could change the value
   and the compiler has no way of knowing this).  Generally speaking,
   the volatile keyword is broken linguistically.  Volatility is not a
   property of the variable but of the deferencing of a variable (e.g.
   what is volatile from the POV of a reader of a shared variable is not
   necessarily volatile from the POV a writer of that shared variable in
   a different thread). */

#define FD_VOLATILE_CONST(x) (*((volatile const __typeof__((x)) *)&(x)))

/* FD_VOLATILE(x): tells the compiler is not able to predict the effect
   of modifying x and that deferencing x might have other side effects
   (e.g. maybe another thread is spinning on x waiting for its value to
   change and the compiler has no way of knowing this). */

#define FD_VOLATILE(x) (*((volatile __typeof__((x)) *)&(x)))

#if FD_HAS_ATOMIC

/* FD_ATOMIC_FETCH_AND_{ADD,SUB,OR,AND,XOR}(p,v):

   FD_ATOMIC_FETCH_AND_ADD(p,v) does
     f = *p;
     *p = f + v
     return f;
   as a single atomic operation.  Similarly for the other variants. */

#define FD_ATOMIC_FETCH_AND_ADD(p,v) __sync_fetch_and_add( (p), (v) )
#define FD_ATOMIC_FETCH_AND_SUB(p,v) __sync_fetch_and_sub( (p), (v) )
#define FD_ATOMIC_FETCH_AND_OR( p,v) __sync_fetch_and_or(  (p), (v) )
#define FD_ATOMIC_FETCH_AND_AND(p,v) __sync_fetch_and_and( (p), (v) )
#define FD_ATOMIC_FETCH_AND_XOR(p,v) __sync_fetch_and_xor( (p), (v) )

/* FD_ATOMIC_{ADD,SUB,OR,AND,XOR}_AND_FETCH(p,v):

   FD_ATOMIC_{ADD,SUB,OR,AND,XOR}_AND_FETCH(p,v) does
     r = *p + v;
     *p = r;
     return r;
   as a single atomic operation.  Similarly for the other variants. */

#define FD_ATOMIC_ADD_AND_FETCH(p,v) __sync_add_and_fetch( (p), (v) )
#define FD_ATOMIC_SUB_AND_FETCH(p,v) __sync_sub_and_fetch( (p), (v) )
#define FD_ATOMIC_OR_AND_FETCH( p,v) __sync_or_and_fetch(  (p), (v) )
#define FD_ATOMIC_AND_AND_FETCH(p,v) __sync_and_and_fetch( (p), (v) )
#define FD_ATOMIC_XOR_AND_FETCH(p,v) __sync_xor_and_fetch( (p), (v) )

/* FD_ATOMIC_CAS(p,c,s): 

   o = FD_ATOMIC_CAS(p,c,s) conceptually does:
     o = *p;
     if( o==c ) *p = s;
     return o
   as a single atomic operation. */

#define FD_ATOMIC_CAS(p,c,s) __sync_val_compare_and_swap( (p), (c), (s) )

#endif

/* FD_TLS:  This indicates that the variable should be thread local.

   FD_ONCE_{BEGIN,END}:  The block:

     FD_ONCE_BEGIN {
       ... code ...
     } FD_ONCE_END

   linguistically behaves like:

     do {
       ... code ...
     } while(0)

   But provides a low overhead guarantee that:
     - The block will be executed by at most once over all threads
       in a process (i.e. the set of threads which share global
       variables).
     - No thread in a process that encounters the block will continue
       past it until it has executed once.

   This implies that caller promises a ONCE block will execute in a
   finite time.  (Meant for doing simple lightweight initializations.)

   It is okay to nest ONCE blocks.  The thread that executes the
   outermost will execute all the nested once as part of executing the
   outermost.

   A ONCE implicitly provides a compiler memory fence to reduce the risk
   that the compiler will assume that operations done in the once block
   on another thread have not been done (e.g. propagating pre-once block
   variable values into post-once block code).  It is up to the user to
   provide any necessary hardware fencing (usually not necessary).

   FD_THREAD_ONCE_{BEGIN,END}:  The block:

     FD_THREAD_ONCE_BEGIN {
       ... code ...
     } FD_THREAD_ONCE_END;

   is similar except the guarantee is that the block only covers the
   invoking thread and it does not provide any fencing.  If a thread
   once begin is nested inside a once begin, that thread once begin will
   only be executed on the thread that executes the thread once begin.
   It is similarly okay to nest ONCE block inside a THREAD_ONCE block. */

#if FD_HAS_THREADS /* Potentially more than one thread in the process */

#ifndef FD_TLS
#define FD_TLS __thread
#endif

#define FD_ONCE_BEGIN do {                                                \
    FD_COMPILER_MFENCE();                                                 \
    static volatile int _fd_once_block_state = 0;                         \
    for(;;) {                                                             \
      int _fd_once_block_tmp = _fd_once_block_state;                      \
      if( FD_LIKELY( _fd_once_block_tmp>0 ) ) break;                      \
      if( FD_LIKELY( !_fd_once_block_tmp ) &&                             \
          FD_LIKELY( !FD_ATOMIC_CAS( &_fd_once_block_state, 0, -1 ) ) ) { \
        do

#define FD_ONCE_END               \
        while(0);                 \
        FD_COMPILER_MFENCE();     \
        _fd_once_block_state = 1; \
        break;                    \
      }                           \
      FD_SPIN_PAUSE();            \
    }                             \
  } while(0)

#define FD_THREAD_ONCE_BEGIN do {                        \
    static FD_TLS int _fd_thread_once_block_state = 0;   \
    if( FD_UNLIKELY( !_fd_thread_once_block_state ) ) {  \
      do

#define FD_THREAD_ONCE_END             \
      while(0);                        \
      _fd_thread_once_block_state = 1; \
    }                                  \
  } while(0)

#else /* Only one thread in the process */

#ifndef FD_TLS
#define FD_TLS /**/
#endif

#define FD_ONCE_BEGIN do {                       \
    static int _fd_once_block_state = 0;         \
    if( FD_UNLIKELY( !_fd_once_block_state ) ) { \
      do

#define FD_ONCE_END             \
      while(0);                 \
      _fd_once_block_state = 1; \
    }                           \
  } while(0)

#define FD_THREAD_ONCE_BEGIN FD_ONCE_BEGIN
#define FD_THREAD_ONCE_END   FD_ONCE_END

#endif

FD_PROTOTYPES_BEGIN

/* fd_memcpy(d,s,sz):  On modern x86 in some circumstances, rep mov will
   be faster than memcpy under the hood (basically due to RFO /
   read-for-ownership optimizations in the cache protocol under the hood
   that aren't easily done from the ISA ... see Intel docs on enhanced
   rep mov).  Compile time configurable though as this is not always
   true.  So application can tune to taste.  Hard to beat rep mov for
   code density though (2 bytes) and pretty hard to beat in situations
   needing a completely generic memcpy.  But it can be beaten in
   specialized situations for the usual reasons. */

/* FIXME: CONSIDER MEMSET AND MEMCMP TOO! */
/* FIXME: CONSIDER MEMCPY RELATED FUNC ATTRS */

#ifndef FD_USE_ARCH_MEMCPY
#define FD_USE_ARCH_MEMCPY 1
#endif

#if FD_HAS_X86 && FD_USE_ARCH_MEMCPY

static inline void *
fd_memcpy( void       * FD_RESTRICT d,
           void const * FD_RESTRICT s,
           ulong                    sz ) {
  void * p = d;
  __asm__ __volatile__( "rep movsb" : "+D" (p), "+S" (s), "+c" (sz) :: "memory" );
  return d;
}

#else

static inline void *
fd_memcpy( void       * FD_RESTRICT d,
           void const * FD_RESTRICT s,
           ulong                    sz ) {
  return memcpy( d, s, sz );
}

#endif

/* fd_hash(seed,buf,sz), fd_hash_memcpy(seed,d,s,sz):  High quality
   (full avalanche) high speed variable length buffer -> 64-bit hash
   function (memcpy_hash is often as fast as plain memcpy).  Based on
   the xxhash-r39 (open source BSD licensed) implementation.  In-place
   and out-of-place variants provided (out-of-place variant assumes dst
   and src do not overlap).  Caller promises valid input arguments,
   cannot fail given valid inputs arguments.  sz==0 is fine. */

FD_FN_PURE ulong
fd_hash( ulong        seed,
         void const * buf,
         ulong        sz );

ulong
fd_hash_memcpy( ulong                    seed,
                void       * FD_RESTRICT d,
                void const * FD_RESTRICT s,
                ulong                    sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_fd_util_base_h */


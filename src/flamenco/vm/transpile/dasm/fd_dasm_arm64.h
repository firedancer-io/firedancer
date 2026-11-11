#ifndef HEADER_fd_src_flamenco_vm_transpile_dasm_fd_dasm_arm64_h
#define HEADER_fd_src_flamenco_vm_transpile_dasm_fd_dasm_arm64_h

/* AArch64 passes of fd_dasm.  Derived from DynASM.

   Copyright (C) 2005-2026 Mike Pall. All rights reserved.
   Released under the MIT license, see NOTICE.

   The action list is an array of 32 bit words.  A word whose upper
   half is below FD_DASM_ACTION_CNT is an action: the upper half is the
   action number, the lower half its parameter.  Any other word is an
   instruction, copied to the output.  Actions that patch an operand
   apply to the instruction right before them.

   Each fd_dasm_put appends to the buffer: the action list offset of
   the chunk, then for each action of the chunk its buffer elements. */

#include "fd_dasm.h"

/* Keep in sync with fd_dasm_arm64.py */

#define FD_DASM_STOP       (0) /* ends a chunk */
#define FD_DASM_ESC        (1) /* next word is an instruction that looks like an action */
#define FD_DASM_ALIGN      (2) /* param: alignment-1.  1 buffer element: code offset bound */
/* param: branch kind in bits 11+, label number in bits 0-10.  1 buffer
   element: label position */
#define FD_DASM_REL_LG     (3)
/* param: label number.  1 buffer element: code offset of the label */
#define FD_DASM_LABEL_LG   (4)
/* Actions from here on take an int argument, stored in 1 buffer element */
#define FD_DASM_REL_PC     (5) /* param: branch kind.  Argument is the label index */
#define FD_DASM_LABEL_PC   (6)
#define FD_DASM_IMM        (7) /* param: bit 15 signed, bits 10-14 scale, bits 5-9 width, bits 0-4 shift */
#define FD_DASM_IMM6       (8) /* bit number of tbz/tbnz */
#define FD_DASM_IMM12      (9) /* add/sub immediate: 12 bits, optionally shifted left by 12 */
#define FD_DASM_IMM13W    (10) /* 32 bit logical immediate */
#define FD_DASM_IMM13X    (11) /* 64 bit logical immediate (2 arguments: low, high) */
#define FD_DASM_IMML      (12) /* load/store offset.  param: log2 access size */
#define FD_DASM_IMMV      (13) /* data word */
#define FD_DASM_VREG      (14) /* register number.  param: shift */
#define FD_DASM_ACTION_CNT (15)

/* Label numbers: [1,9] forward reference to a local label, [11,19]
   definition of or backward reference to local label n-10, [20,2047]
   global label.  Label n uses label table entry n-10 (n if n<10). */

/* Branch kinds */

#define FD_DASM_REL_B26  (0x0000) /* b, bl */
#define FD_DASM_REL_B19  (0x0800) /* b.cond, cbz, cbnz, ldr literal */
#define FD_DASM_REL_B14  (0x1000) /* tbz, tbnz */
#define FD_DASM_REL_ADR  (0x2000)
#define FD_DASM_REL_ADRP (0x3000)

FD_PROTOTYPES_BEGIN

/* fd_dasm_imm12 returns the 13 bit encoding of n as an add/sub
   immediate, or -1 if n is not encodable. */

FD_FN_CONST static inline int
fd_dasm_imm12( uint n ) {
  if( (n>>12)==0U         ) return (int)n;
  if( (n&0xff000fffU)==0U ) return (int)( (n>>12) | 0x1000U );
  return -1;
}

/* fd_dasm_imm13 returns the 13 bit N:immr:imms encoding of n as a
   logical immediate, or -1 if n is not encodable.  n is the 64 bit
   pattern (for a 32 bit operation, the 32 bit pattern repeated twice).

   Encodable patterns are a run of ones, rotated, repeated every
   2/4/8/16/32/64 bits. */

FD_FN_CONST static inline int
fd_dasm_imm13( ulong n ) {
  int inv = 0;
  if( n&1UL ) { n = ~n; inv = 1; }
  if( !n ) return -1;
  /* n is now 0..01..10..0 repeated.  a is the lowest set bit, b the
     lowest clear bit above it, c the lowest set bit of the next repeat */
  ulong a  = n & (0UL-n);
  ulong b  = (n+a) & (0UL-(n+a));
  ulong c  = (n+a-b) & (0UL-(n+a-b));
  int   xa = fd_ulong_find_lsb( a );
  int   xb = b ? fd_ulong_find_lsb( b ) : 64;
  int   w  = 64;
  int   s  = 0xfff;
  ulong m  = 1UL;
  if( c ) {
    w = fd_ulong_find_lsb( c ) - xa;
    if(      w==32 ) m = 0x0000000100000001UL;
    else if( w==16 ) m = 0x0001000100010001UL;
    else if( w== 8 ) m = 0x0101010101010101UL;
    else if( w== 4 ) m = 0x1111111111111111UL;
    else if( w== 2 ) m = 0x5555555555555555UL;
    else return -1;
    s = ( -2*w & 0x3f ) - 1;
  }
  if( (b-a)*m!=n ) return -1;
  if( inv ) return ( (w-xb)<<6 ) | ( s+w+xa-xb );
  return           ( (w-xa)<<6 ) | ( s+xb-xa );
}

/* fd_dasm_put appends the chunk at action list offset start.  arg are
   the chunk's int arguments in action order (NULL if none). */

static void
fd_dasm_put( fd_dasm_t * d,
             int         start,
             int const * arg ) {
  if( FD_UNLIKELY( d->err ) ) return;
  if( FD_UNLIKELY( d->pos > d->buf_cnt-FD_DASM_PUT_POS_MAX ) ) { fd_dasm_fail( d, FD_DASM_ERR_FULL, start ); return; }

# define CK( cond, err ) do { if( FD_UNLIKELY( !(cond) ) ) { fd_dasm_fail( d, (err), start ); return; } } while(0)

  uint const * p   = (uint const *)d->actions + start;
  int *        b   = d->buf;
  int          pos = d->pos;
  int          ofs = d->ofs;

  b[ pos++ ] = start;
  for(;;) {
    uint ins    = *p++;
    uint action = ins>>16;
    if( action>=FD_DASM_ACTION_CNT ) { ofs += 4; continue; }

    int n = action>=FD_DASM_REL_PC ? *arg++ : 0;
    switch( action ) {

    case FD_DASM_STOP:
      d->pos = pos;
      d->ofs = ofs;
      return;

    case FD_DASM_ESC:
      p++; ofs += 4;
      break;

    case FD_DASM_ALIGN:
      ofs += (int)( ins&255U );
      b[ pos++ ] = ofs;
      break;

    case FD_DASM_REL_LG: {
      int   num = (int)( ins&2047U );
      int   fwd = num<10;
      int * pl  = d->lglabels + ( fwd ? num : num-10 );
      CK( num>=20 || fwd || *pl<0, FD_DASM_ERR_LABEL );
      fd_dasm_label_ref( b, pl, pos++, fwd );
      break;
    }
    case FD_DASM_REL_PC:
      CK( (uint)n<d->pc_cnt, FD_DASM_ERR_LABEL );
      fd_dasm_label_ref( b, d->pclabels+n, pos++, 0 );
      break;

    case FD_DASM_LABEL_LG:
      fd_dasm_label_def( b, d->lglabels + (int)( ins&2047U ) - 10, pos );
      b[ pos++ ] = ofs;
      break;
    case FD_DASM_LABEL_PC:
      CK( (uint)n<d->pc_cnt, FD_DASM_ERR_LABEL );
      fd_dasm_label_def( b, d->pclabels+n, pos );
      b[ pos++ ] = ofs;
      break;

    case FD_DASM_IMM: {
      int scale = (int)( (ins>>10)&31U );
      int bits  = (int)( (ins>> 5)&31U );
      CK( ( n & ((1<<scale)-1) )==0, FD_DASM_ERR_IMM );
      n >>= scale;
      if( ins&0x8000U ) CK( ( ( n + (1<<(bits-1)) )>>bits )==0, FD_DASM_ERR_IMM );
      else              CK( ( n>>bits )==0,                     FD_DASM_ERR_IMM );
      b[ pos++ ] = n;
      break;
    }
    case FD_DASM_IMM6:
      CK( (n>>6)==0, FD_DASM_ERR_IMM );
      b[ pos++ ] = n;
      break;
    case FD_DASM_IMM12:
      CK( fd_dasm_imm12( (uint)n )!=-1, FD_DASM_ERR_IMM );
      b[ pos++ ] = n;
      break;
    case FD_DASM_IMM13W:
      CK( fd_dasm_imm13( ((ulong)(uint)n<<32) | (ulong)(uint)n )!=-1, FD_DASM_ERR_IMM );
      b[ pos++ ] = n;
      break;
    case FD_DASM_IMM13X: {
      int hi = *arg++;
      CK( fd_dasm_imm13( ((ulong)(uint)hi<<32) | (ulong)(uint)n )!=-1, FD_DASM_ERR_IMM );
      b[ pos++ ] = n;
      b[ pos++ ] = hi;
      break;
    }
    case FD_DASM_IMML: {
      int scale = (int)( ins&3U );
      CK( ( !( n & ((1<<scale)-1) ) && (uint)(n>>scale)<4096U ) || (uint)(n+256)<512U, FD_DASM_ERR_IMM );
      b[ pos++ ] = n;
      break;
    }
    case FD_DASM_IMMV:
      ofs += 4;
      b[ pos++ ] = n;
      break;
    case FD_DASM_VREG:
      CK( (uint)n<32U, FD_DASM_ERR_REG );
      b[ pos++ ] = n;
      break;
    }
  }

# undef CK
}

/* fd_dasm_link resolves labels and returns the final code size in *sz.
   Returns FD_DASM_SUCCESS or the first error since fd_dasm_init. */

static int
fd_dasm_link( fd_dasm_t * d,
              ulong *     sz ) {
  *sz = 0UL;
  if( FD_UNLIKELY( d->err ) ) return d->err;
  int err = fd_dasm_link_check( d );
  if( FD_UNLIKELY( err ) ) return err;

  uint const * actions = (uint const *)d->actions;
  int *        b       = d->buf;
  int          end     = d->pos;
  int          ofs     = 0; /* bytes saved so far by alignment needing less than the bound (<=0) */

  for( int pos=1; pos<end; ) {
    uint const * p = actions + b[ pos++ ];
    for(;;) {
      uint ins    = *p++;
      uint action = ins>>16;
      if( action>=FD_DASM_ACTION_CNT ) continue;
      if( action==FD_DASM_STOP ) break;
      switch( action ) {
      case FD_DASM_ESC:      p++;                                         break;
      case FD_DASM_ALIGN:    ofs -= ( b[ pos++ ]+ofs ) & (int)(ins&255U); break;
      case FD_DASM_LABEL_LG:
      case FD_DASM_LABEL_PC: b[ pos++ ] += ofs;                           break;
      case FD_DASM_IMM13X:   pos += 2;                                    break;
      default:               pos++;                                       break;
      }
    }
  }

  d->ofs += ofs;
  *sz = (ulong)d->ofs;
  return FD_DASM_SUCCESS;
}

/* fd_dasm_encode writes the machine code to out (4 byte aligned), which
   has room for the size returned by fd_dasm_link.  Returns
   FD_DASM_SUCCESS or an error. */

static int
fd_dasm_encode( fd_dasm_t * d,
                uchar *     out ) {
  if( FD_UNLIKELY( d->err ) ) return d->err;

# define CK( cond, err ) do { if( FD_UNLIKELY( !(cond) ) ) return fd_dasm_fail( d, (err), start ); } while(0)

  uint const * actions = (uint const *)d->actions;
  int const *  buf     = d->buf;
  int const *  b       = buf + 1;
  int const *  end     = buf + d->pos;
  uint *       cp      = (uint *)out;

  while( b!=end ) {
    int          start = *b++;
    uint const * p     = actions + start;
    for(;;) {
      uint ins    = *p++;
      uint action = ins>>16;
      if( action>=FD_DASM_ACTION_CNT ) { *cp++ = ins; continue; }
      if( action==FD_DASM_STOP ) break;
      if( action==FD_DASM_ESC  ) { *cp++ = *p++; continue; }
      int n = *b++;
      switch( action ) {

      case FD_DASM_ALIGN:
        while( (ulong)( (uchar *)cp-out ) & (ulong)(ins&255U) ) *cp++ = 0xd503201fU; /* nop */
        break;

      case FD_DASM_REL_LG:
      case FD_DASM_REL_PC: {
        /* The instruction to patch is cp[-1] */
        n = buf[ n ] - (int)( (uchar *)cp-out ) + 4;
        uint un = (uint)n;
        switch( ins&0x3800U ) {
        case FD_DASM_REL_B26:
          CK( (n&3)==0 && ( (n+0x08000000)>>28 )==0, FD_DASM_ERR_REL );
          cp[-1] |= (un>>2) & 0x03ffffffU;
          break;
        case FD_DASM_REL_B19:
          CK( (n&3)==0 && ( (n+0x00100000)>>21 )==0, FD_DASM_ERR_REL );
          cp[-1] |= (un<<3) & 0x00ffffe0U;
          break;
        case FD_DASM_REL_B14:
          CK( (n&3)==0 && ( (n+0x00008000)>>16 )==0, FD_DASM_ERR_REL );
          cp[-1] |= (un<<3) & 0x0007ffe0U;
          break;
        case FD_DASM_REL_ADR:
          CK( ( (n+0x00100000)>>21 )==0, FD_DASM_ERR_REL );
          cp[-1] |= ( (un<<3) & 0x00ffffe0U ) | ( (un&3U)<<29 );
          break;
        default: /* FD_DASM_REL_ADRP */
          cp[-1] |= ( (un>>9) & 0x00ffffe0U ) | ( ((un>>12)&3U)<<29 );
          break;
        }
        break;
      }

      case FD_DASM_LABEL_LG:
      case FD_DASM_LABEL_PC:
        break;

      case FD_DASM_IMM:
        cp[-1] |= ( (uint)n & ( (1U<<((ins>>5)&31U))-1U ) ) << (ins&31U);
        break;
      case FD_DASM_IMM6:
        cp[-1] |= ( ((uint)n&31U)<<19 ) | ( ((uint)n&32U)<<26 );
        break;
      case FD_DASM_IMM12:
        cp[-1] |= (uint)fd_dasm_imm12( (uint)n )<<10;
        break;
      case FD_DASM_IMM13W:
        cp[-1] |= (uint)fd_dasm_imm13( ((ulong)(uint)n<<32) | (ulong)(uint)n )<<10;
        break;
      case FD_DASM_IMM13X:
        cp[-1] |= (uint)fd_dasm_imm13( ((ulong)(uint)*b++<<32) | (ulong)(uint)n )<<10;
        break;
      case FD_DASM_IMML: {
        int scale = (int)( ins&3U );
        cp[-1] |= ( !( n & ((1<<scale)-1) ) && (uint)(n>>scale)<4096U ) ?
                  ( ( (uint)n<<(10-scale) ) | 0x01000000U ) : ( ((uint)n&511U)<<12 );
        break;
      }
      case FD_DASM_IMMV:
        *cp++ = (uint)n;
        break;
      case FD_DASM_VREG:
        cp[-1] |= ( (uint)n&31U ) << (ins&31U);
        break;
      }
    }
  }

# undef CK

  if( FD_UNLIKELY( (long)( (uchar *)cp-out )!=(long)d->ofs ) ) return fd_dasm_fail( d, FD_DASM_ERR_PHASE, 0 );
  return FD_DASM_SUCCESS;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_transpile_dasm_fd_dasm_arm64_h */

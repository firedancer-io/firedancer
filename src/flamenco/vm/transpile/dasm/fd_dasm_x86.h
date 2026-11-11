#ifndef HEADER_fd_src_flamenco_vm_transpile_dasm_fd_dasm_x86_h
#define HEADER_fd_src_flamenco_vm_transpile_dasm_fd_dasm_x86_h

/* x86-64 passes of fd_dasm.  Derived from DynASM.

   Copyright (C) 2005-2026 Mike Pall. All rights reserved.
   Released under the MIT license, see NOTICE.

   The action list is a byte string.  Bytes below FD_DASM_DISP are
   machine code, copied to the output.  The rest are actions.  Some are
   followed by an action byte, some consume an int argument of
   fd_dasm_put, and some store ints in the buffer for the later passes.

   Each fd_dasm_put appends to the buffer: the action list offset of
   the chunk, then for each action of the chunk its buffer elements. */

#include "fd_dasm.h"

/* Keep in sync with fd_dasm_x86.py */

/* int argument, 1 buffer element (the argument) */
#define FD_DASM_DISP     (240) /* ModRM displacement: none if 0 (and base allows), disp8 if it fits, else disp32 */
#define FD_DASM_IMM_S    (241) /* int8 */
#define FD_DASM_IMM_B    (242) /* uint8 */
#define FD_DASM_IMM_W    (243) /* uint16 */
#define FD_DASM_IMM_D    (244) /* 32 bits */
#define FD_DASM_IMM_WB   (245) /* int8 if it fits (and opcode+=2), else 16 bits */
#define FD_DASM_IMM_DB   (246) /* int8 if it fits (and opcode+=2), else 32 bits */
/* action byte, int argument, 1 buffer element.  Patches a register
   number into the previous byte.  Action byte bits:
     7:5  target field (see below)
     4:3  count of earlier arguments of this instruction that, together
          with this one, decide whether the REX/VEX prefix shrinks
     2:0  distance from here back to that prefix
   Buffer element is the register number, |0x10 if the prefix shrinks. */
#define FD_DASM_VREG     (247)
/* action byte (label number) for LG, int argument (label index) for
   PC.  2 buffer elements: label position; code offset bound in put,
   then number of bytes saved by using the short branch form in link */
#define FD_DASM_REL_LG   (248)
#define FD_DASM_REL_PC   (249)
/* action byte for LG, int argument for PC.  1 buffer element: code
   offset of the label */
#define FD_DASM_LABEL_LG (250)
#define FD_DASM_LABEL_PC (251)
/* action byte (alignment-1).  1 buffer element: code offset bound */
#define FD_DASM_ALIGN    (252)
/* action byte: a machine code byte >= FD_DASM_DISP */
#define FD_DASM_ESC      (253)
/* marks the position after a ModRM byte whose mod field depends on a
   following FD_DASM_DISP */
#define FD_DASM_MARK     (254)
/* ends a chunk */
#define FD_DASM_STOP     (255)

/* Label numbers: [1,9] backward reference to a local label, [10,246]
   global label, [247,255] forward reference to local label n-246. */

#define FD_DASM_LOCAL_FWD (246)

/* FD_DASM_VREG target fields */

#define FD_DASM_VREG_RM    (0x00) /* ModRM.rm of a memory operand (rsp/r12 need a SIB byte) */
#define FD_DASM_VREG_B     (0x20) /* ModRM.rm of a register operand, SIB.base, or opcode low bits */
#define FD_DASM_VREG_INDEX (0x40) /* SIB.index */
#define FD_DASM_VREG_REG   (0x80) /* ModRM.reg */
#define FD_DASM_VREG_VEX   (0xa0) /* VEX.vvvv */
#define FD_DASM_VREG_IMM   (0xc0) /* high 4 bits of an immediate byte */

#define FD_DASM_FITS_INT8( n ) ( (((n)+128)&-256)==0 )

FD_PROTOTYPES_BEGIN

/* fd_dasm_put appends the chunk at action list offset start.  arg are
   the chunk's int arguments in action order (NULL if none). */

static void
fd_dasm_put( fd_dasm_t * d,
             int         start,
             int const * arg ) {
  if( FD_UNLIKELY( d->err ) ) return;
  if( FD_UNLIKELY( d->pos > d->buf_cnt-FD_DASM_PUT_POS_MAX ) ) { fd_dasm_fail( d, FD_DASM_ERR_FULL, start ); return; }

# define CK( cond, err ) do { if( FD_UNLIKELY( !(cond) ) ) { fd_dasm_fail( d, (err), start ); return; } } while(0)

  uchar const * p   = (uchar const *)d->actions + start;
  int *         b   = d->buf;
  int           pos = d->pos;
  int           ofs = d->ofs;
  int           mrm = -1; /* ModRM byte (or base register) deciding whether a zero FD_DASM_DISP can be dropped */

  b[ pos++ ] = start;
  for(;;) {
    int action = *p++;
    if( action<FD_DASM_DISP ) { ofs++; continue; }

    switch( action ) {

    case FD_DASM_DISP: {
      int n = *arg++; b[ pos++ ] = n;
      if( n==0 ) {
        if( mrm<0 ) mrm = p[-2];
        if( (mrm&7)!=5 ) { mrm = -1; break; } /* rbp/r13 as base always need a displacement */
      }
      ofs += FD_DASM_FITS_INT8( n ) ? 1 : 4;
      mrm = -1;
      break;
    }
    case FD_DASM_IMM_S: {
      int n = *arg++; b[ pos++ ] = n;
      CK( FD_DASM_FITS_INT8( n ), FD_DASM_ERR_IMM );
      ofs++; mrm = -1;
      break;
    }
    case FD_DASM_IMM_B: {
      int n = *arg++; b[ pos++ ] = n;
      CK( (n&-256)==0, FD_DASM_ERR_IMM );
      ofs++; mrm = -1;
      break;
    }
    case FD_DASM_IMM_W: {
      int n = *arg++; b[ pos++ ] = n;
      CK( (n&-65536)==0, FD_DASM_ERR_IMM );
      ofs += 2; mrm = -1;
      break;
    }
    case FD_DASM_IMM_D: {
      b[ pos++ ] = *arg++;
      ofs += 4; mrm = -1;
      break;
    }
    case FD_DASM_IMM_WB: {
      int n = *arg++; b[ pos++ ] = n;
      if( FD_DASM_FITS_INT8( n ) ) ofs++;
      else { CK( (n&-65536)==0, FD_DASM_ERR_IMM ); ofs += 2; }
      mrm = -1;
      break;
    }
    case FD_DASM_IMM_DB: {
      int n = *arg++; b[ pos++ ] = n;
      ofs += FD_DASM_FITS_INT8( n ) ? 1 : 4;
      mrm = -1;
      break;
    }

    case FD_DASM_VREG: {
      int n = *arg++; b[ pos++ ] = n;
      int t = *p++;
      CK( (n&-16)==0, FD_DASM_ERR_REG );
      CK( n!=4 || (t&0xe0)!=FD_DASM_VREG_INDEX, FD_DASM_ERR_REG ); /* rsp is not an index */
      if( t<FD_DASM_VREG_INDEX && p[0]==FD_DASM_DISP ) mrm = n;     /* base register */
      if( t<FD_DASM_VREG_B     && (n&7)==4           ) ofs++;       /* SIB byte */
      int cnt = (t>>3)&3;
      if( cnt ) {
        for( int i=1; i<cnt; i++ ) n |= b[ pos-1-i ];
        if( n<=7 ) { b[ pos-1 ] |= 0x10; ofs--; }
      }
      break;
    }

    case FD_DASM_REL_LG:
    case FD_DASM_REL_PC: {
      int * pl; int fwd = 0;
      if( action==FD_DASM_REL_LG ) {
        int n = *p++;
        if( n>FD_DASM_LOCAL_FWD ) { n -= FD_DASM_LOCAL_FWD; fwd = 1; }
        pl = d->lglabels + n;
        CK( n>=10 || fwd || *pl<0, FD_DASM_ERR_LABEL );
      } else {
        uint n = (uint)*arg++;
        CK( n<d->pc_cnt, FD_DASM_ERR_LABEL );
        pl = d->pclabels + n;
      }
      fd_dasm_label_ref( b, pl, pos, fwd );
      pos++;
      ofs += 4;
      b[ pos++ ] = ofs;
      break;
    }

    case FD_DASM_LABEL_LG:
    case FD_DASM_LABEL_PC: {
      int * pl;
      if( action==FD_DASM_LABEL_LG ) {
        pl = d->lglabels + *p++;
      } else {
        uint n = (uint)*arg++;
        CK( n<d->pc_cnt, FD_DASM_ERR_LABEL );
        pl = d->pclabels + n;
      }
      fd_dasm_label_def( b, pl, pos );
      b[ pos++ ] = ofs;
      break;
    }

    case FD_DASM_ALIGN:
      ofs += *p++;
      b[ pos++ ] = ofs;
      break;

    case FD_DASM_ESC:
      p++; ofs++;
      break;

    case FD_DASM_MARK:
      mrm = p[-2];
      if( (mrm&7)==4 ) { /* base register is in the SIB byte */
        uchar const * q = p;
        if( *q==FD_DASM_VREG ) q += 2;
        if( *q==FD_DASM_ESC  ) q++;
        mrm = *q;
      }
      break;

    case FD_DASM_STOP:
      d->pos = pos;
      d->ofs = ofs;
      return;
    }
  }

# undef CK
}

/* fd_dasm_link resolves labels, shortens branches where possible, and
   returns the final code size in *sz.  Returns FD_DASM_SUCCESS or the
   first error since fd_dasm_init. */

static int
fd_dasm_link( fd_dasm_t * d,
              ulong *     sz ) {
  *sz = 0UL;
  if( FD_UNLIKELY( d->err ) ) return d->err;
  int err = fd_dasm_link_check( d );
  if( FD_UNLIKELY( err ) ) return err;

  uchar const * actions = (uchar const *)d->actions;
  int *         b       = d->buf;
  int           end     = d->pos;
  int           ofs     = 0; /* bytes saved so far (<=0) */

  for( int pos=1; pos<end; ) {
    uchar const * p  = actions + b[ pos++ ];
    int           op = 0; /* previous machine code byte */
    for(;;) {
      int action = *p++;
      if( action<FD_DASM_DISP ) { op = action; continue; }
      if( action==FD_DASM_STOP ) break;
      switch( action ) {
      case FD_DASM_REL_LG: p++; __attribute__((fallthrough));
      case FD_DASM_REL_PC: {
        /* jmp rel32 (E9) can become jmp rel8 (EB), jcc rel32 (0F 8x)
           can become jcc rel8 (7x) */
        int shrink = op==0xe9 ? 3 : ( (op&0xf0)==0x80 ? 4 : 0 );
        if( shrink ) {
          int lpos = b[ pos ];
          int lofs = b[ lpos ];
          if( lpos<pos ) lofs -= ofs; /* backward label was already adjusted */
          lofs -= b[ pos+1 ];
          if( lofs>=-128-shrink && lofs<=127 ) ofs -= shrink;
          else                                 shrink = 0;
        }
        b[ pos+1 ] = shrink;
        pos += 2;
        break;
      }
      case FD_DASM_VREG: p++; __attribute__((fallthrough));
      case FD_DASM_DISP:  case FD_DASM_IMM_S:  case FD_DASM_IMM_B: case FD_DASM_IMM_W:
      case FD_DASM_IMM_D: case FD_DASM_IMM_WB: case FD_DASM_IMM_DB:
        pos++;
        break;
      case FD_DASM_LABEL_LG: p++; __attribute__((fallthrough));
      case FD_DASM_LABEL_PC:
        b[ pos++ ] += ofs;
        break;
      case FD_DASM_ALIGN:
        ofs -= ( b[ pos++ ]+ofs ) & *p++;
        break;
      case FD_DASM_ESC:
        op = *p++;
        break;
      case FD_DASM_MARK:
        break;
      }
    }
  }

  d->ofs += ofs;
  *sz = (ulong)d->ofs;
  return FD_DASM_SUCCESS;
}

/* fd_dasm_encode writes the machine code to out, which has room for
   the size returned by fd_dasm_link.  Returns FD_DASM_SUCCESS or an
   error. */

static int
fd_dasm_encode( fd_dasm_t * d,
                uchar *     out ) {
  if( FD_UNLIKELY( d->err ) ) return d->err;

  uchar const * actions = (uchar const *)d->actions;
  int const *   buf     = d->buf;
  int const *   b       = buf + 1;
  int const *   end     = buf + d->pos;
  uchar *       cp      = out;

  while( b!=end ) {
    uchar const * p    = actions + *b++;
    uchar *       mark = NULL; /* position after the ModRM byte, or after the opcode for IMM_WB/IMM_DB */
    for(;;) {
      int action = *p++;
      if( action<FD_DASM_DISP ) { *cp++ = (uchar)action; continue; }
      if( action==FD_DASM_STOP ) break;
      int n = action<=FD_DASM_ALIGN ? *b++ : 0;
      switch( action ) {

      case FD_DASM_DISP: {
        if( !mark ) mark = cp;
        uchar * mm = mark;
        if( *p!=FD_DASM_IMM_DB && *p!=FD_DASM_IMM_WB ) mark = NULL;
        if( n==0 ) {
          int base = mm[-1]&7;
          if( base==4 ) base = mm[0]&7;
          if( base!=5 ) { mm[-1] = (uchar)( mm[-1]-0x80 ); break; } /* mod=00: no displacement */
        }
        if( !FD_DASM_FITS_INT8( n ) ) goto imm32;
        mm[-1] = (uchar)( mm[-1]-0x40 ); /* mod=01: disp8 */
        goto imm8;
      }

      case FD_DASM_IMM_S:
      case FD_DASM_IMM_B:
      imm8:
        *cp++ = (uchar)n;
        break;

      case FD_DASM_IMM_DB:
      case FD_DASM_IMM_WB:
        if( FD_DASM_FITS_INT8( n ) ) {
          if( !mark ) mark = cp;
          mark[-2] = (uchar)( mark[-2]+2 ); /* imm8 form of the opcode */
          mark = NULL;
          goto imm8;
        }
        mark = NULL;
        if( action==FD_DASM_IMM_WB ) goto imm16;
        __attribute__((fallthrough));
      case FD_DASM_IMM_D:
      imm32:
        FD_STORE( uint, cp, (uint)n ); cp += 4;
        break;

      case FD_DASM_IMM_W:
      imm16:
        FD_STORE( ushort, cp, (ushort)n ); cp += 2;
        break;

      case FD_DASM_VREG: {
        int     t  = *p++;
        uchar * ex = cp - (t&7); /* REX or VEX prefix */
        if( (n&8) && t<FD_DASM_VREG_VEX ) {
          /* Set REX.B/X/R, or clear the inverted VEX equivalent */
          if( *ex & 0x80 ) ex[1] = (uchar)( ex[1] ^ ( 0x20<<(t>>6) ) );
          else             ex[0] = (uchar)( ex[0] ^ ( 1   <<(t>>6) ) );
          n &= 7;
        } else if( n&0x10 ) {
          /* Drop the REX prefix, or turn 3 byte VEX into 2 byte VEX */
          if( *ex & 0x80 ) {
            ex[0] = 0xc5;
            ex[1] = (uchar)( (ex[1]&0x80) | ex[2] );
            ex += 2;
          }
          while( ++ex<cp ) ex[-1] = *ex;
          if( mark ) mark--;
          cp--;
          n &= 7;
        }
        if(      t>=FD_DASM_VREG_IMM   ) n <<= 4;
        else if( t>=FD_DASM_VREG_INDEX ) n <<= 3;
        else if( n==4 && t<FD_DASM_VREG_B ) {
          /* rsp/r12 as base need a SIB byte */
          cp[-1] = (uchar)( cp[-1]^n );
          *cp++  = 0x20;
        }
        cp[-1] = (uchar)( cp[-1]^n );
        break;
      }

      case FD_DASM_REL_LG: p++; __attribute__((fallthrough));
      case FD_DASM_REL_PC: {
        int shrink = *b++;
        n = buf[ n ] - ( (int)(cp-out) + 4 - shrink );
        if( !shrink ) goto imm32;
        if( shrink==4 ) { cp--; cp[-1] = (uchar)( cp[0]-0x10 ); } /* 0F 8x -> 7x */
        else            cp[-1] = 0xeb;                            /* E9 -> EB */
        goto imm8;
      }

      case FD_DASM_LABEL_LG: p++; break;
      case FD_DASM_LABEL_PC: break;

      case FD_DASM_ALIGN:
        n = *p++;
        while( (cp-out) & n ) *cp++ = 0x90; /* nop */
        break;

      case FD_DASM_ESC:  *cp++ = *p++; break;
      case FD_DASM_MARK: mark = cp;    break;
      }
    }
  }

  if( FD_UNLIKELY( (long)(cp-out)!=(long)d->ofs ) ) return fd_dasm_fail( d, FD_DASM_ERR_PHASE, 0 );
  return FD_DASM_SUCCESS;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_transpile_dasm_fd_dasm_x86_h */

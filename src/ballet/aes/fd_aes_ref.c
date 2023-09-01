/* fd_aes_ref.c was imported from the OpenSSL project circa 2023-Aug.
   Original source file:  crypto/aes/aes_core.c */

/*
 * Copyright 2002-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * rijndael-alg-fst.c
 *
 * @version 3.0 (December 2000)
 *
 * Optimised ANSI C code for the Rijndael cipher (now AES)
 *
 * @author Vincent Rijmen
 * @author Antoon Bosselaers
 * @author Paulo Barreto
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Note: rewritten a little bit to provide error control and an OpenSSL-
   compatible API */

#include <assert.h>
#include <stdlib.h>
#include "fd_aes_private.h"

typedef union {
  uchar b[8];
  uint w[2];
  ulong d;
} uni;

/*
 * Compute w := (w * x) mod (x^8 + x^4 + x^3 + x^1 + 1)
 * Therefore the name "xtime".
 */
static void
XtimeWord( uint * w ) {
  uint a, b;

  a = *w;
  b = a & 0x80808080u;
  a ^= b;
  b -= b >> 7;
  b &= 0x1B1B1B1Bu;
  b ^= a << 1;
  *w = b;
}

static void
XtimeLong( ulong * w ) {
  ulong a, b;

  a = *w;
  b = a & (ulong)(0x8080808080808080);
  a ^= b;
  b -= b >> 7;
  b &= (ulong)(0x1B1B1B1B1B1B1B1B);
  b ^= a << 1;
  *w = b;
}

/*
 * This computes w := S * w ^ -1 + c, where c = {01100011}.
 * Instead of using GF(2^8) mod (x^8+x^4+x^3+x+1} we do the inversion
 * in GF(GF(GF(2^2)^2)^2) mod (X^2+X+8)
 * and GF(GF(2^2)^2) mod (X^2+X+2)
 * and GF(2^2) mod (X^2+X+1)
 * The first part of the algorithm below transfers the coordinates
 * {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80} =>
 * {1,Y,Y^2,Y^3,Y^4,Y^5,Y^6,Y^7} with Y=0x41:
 * {0x01,0x41,0x66,0x6c,0x56,0x9a,0x58,0xc4}
 * The last part undoes the coordinate transfer and the final affine
 * transformation S:
 * b[i] = b[i] + b[(i+4)%8] + b[(i+5)%8] + b[(i+6)%8] + b[(i+7)%8] + c[i]
 * in one step.
 * The multiplication in GF(2^2^2^2) is done in ordinary coords:
 * A = (a0*1 + a1*x^4)
 * B = (b0*1 + b1*x^4)
 * AB = ((a0*b0 + 8*a1*b1)*1 + (a1*b0 + (a0+a1)*b1)*x^4)
 * When A = (a0,a1) is given we want to solve AB = 1:
 * (a) 1 = a0*b0 + 8*a1*b1
 * (b) 0 = a1*b0 + (a0+a1)*b1
 * => multiply (a) by a1 and (b) by a0
 * (c) a1 = a1*a0*b0 + (8*a1*a1)*b1
 * (d) 0 = a1*a0*b0 + (a0*a0+a1*a0)*b1
 * => add (c) + (d)
 * (e) a1 = (a0*a0 + a1*a0 + 8*a1*a1)*b1
 * => therefore
 * b1 = (a0*a0 + a1*a0 + 8*a1*a1)^-1 * a1
 * => and adding (a1*b0) to (b) we get
 * (f) a1*b0 = (a0+a1)*b1
 * => therefore
 * b0 = (a0*a0 + a1*a0 + 8*a1*a1)^-1 * (a0+a1)
 * Note this formula also works for the case
 * (a0+a1)*a0 + 8*a1*a1 = 0
 * if the inverse element for 0^-1 is mapped to 0.
 * Repeat the same for GF(2^2^2) and GF(2^2).
 * We get the following algorithm:
 * inv8(a0,a1):
 *   x0 = a0^a1
 *   [y0,y1] = mul4([x0,a1],[a0,a1]); (*)
 *   y1 = mul4(8,y1);
 *   t = inv4(y0^y1);
 *   [b0,b1] = mul4([x0,a1],[t,t]); (*)
 *   return [b0,b1];
 * The non-linear multiplies (*) can be done in parallel at no extra cost.
 */
static void
SubWord( uint * w ) {
  uint x, y, a1, a2, a3, a4, a5, a6;

  x = *w;
  y = ((x & 0xFEFEFEFEu) >> 1) | ((x & 0x01010101u) << 7);
  x &= 0xDDDDDDDDu;
  x ^= y & 0x57575757u;
  y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
  x ^= y & 0x1C1C1C1Cu;
  y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
  x ^= y & 0x4A4A4A4Au;
  y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
  x ^= y & 0x42424242u;
  y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
  x ^= y & 0x64646464u;
  y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
  x ^= y & 0xE0E0E0E0u;
  a1 = x;
  a1 ^= (x & 0xF0F0F0F0u) >> 4;
  a2 = ((x & 0xCCCCCCCCu) >> 2) | ((x & 0x33333333u) << 2);
  a3 = x & a1;
  a3 ^= (a3 & 0xAAAAAAAAu) >> 1;
  a3 ^= (((x << 1) & a1) ^ ((a1 << 1) & x)) & 0xAAAAAAAAu;
  a4 = a2 & a1;
  a4 ^= (a4 & 0xAAAAAAAAu) >> 1;
  a4 ^= (((a2 << 1) & a1) ^ ((a1 << 1) & a2)) & 0xAAAAAAAAu;
  a5 = (a3 & 0xCCCCCCCCu) >> 2;
  a3 ^= ((a4 << 2) ^ a4) & 0xCCCCCCCCu;
  a4 = a5 & 0x22222222u;
  a4 |= a4 >> 1;
  a4 ^= (a5 << 1) & 0x22222222u;
  a3 ^= a4;
  a5 = a3 & 0xA0A0A0A0u;
  a5 |= a5 >> 1;
  a5 ^= (a3 << 1) & 0xA0A0A0A0u;
  a4 = a5 & 0xC0C0C0C0u;
  a6 = a4 >> 2;
  a4 ^= (a5 << 2) & 0xC0C0C0C0u;
  a5 = a6 & 0x20202020u;
  a5 |= a5 >> 1;
  a5 ^= (a6 << 1) & 0x20202020u;
  a4 |= a5;
  a3 ^= a4 >> 4;
  a3 &= 0x0F0F0F0Fu;
  a2 = a3;
  a2 ^= (a3 & 0x0C0C0C0Cu) >> 2;
  a4 = a3 & a2;
  a4 ^= (uint)(a4 & 0x0A0A0A0A0Au) >> 1u;
  a4 ^= (((a3 << 1) & a2) ^ ((a2 << 1) & a3)) & 0x0A0A0A0Au;
  a5 = a4 & 0x08080808u;
  a5 |= a5 >> 1;
  a5 ^= (a4 << 1) & 0x08080808u;
  a4 ^= a5 >> 2;
  a4 &= 0x03030303u;
  a4 ^= (a4 & 0x02020202u) >> 1;
  a4 |= a4 << 2;
  a3 = a2 & a4;
  a3 ^= (a3 & 0x0A0A0A0Au) >> 1;
  a3 ^= (((a2 << 1) & a4) ^ ((a4 << 1) & a2)) & 0x0A0A0A0Au;
  a3 |= a3 << 4;
  a2 = ((a1 & 0xCCCCCCCCu) >> 2) | ((a1 & 0x33333333u) << 2);
  x = a1 & a3;
  x ^= (x & 0xAAAAAAAAu) >> 1;
  x ^= (((a1 << 1) & a3) ^ ((a3 << 1) & a1)) & 0xAAAAAAAAu;
  a4 = a2 & a3;
  a4 ^= (a4 & 0xAAAAAAAAu) >> 1;
  a4 ^= (((a2 << 1) & a3) ^ ((a3 << 1) & a2)) & 0xAAAAAAAAu;
  a5 = (x & 0xCCCCCCCCu) >> 2;
  x ^= ((a4 << 2) ^ a4) & 0xCCCCCCCCu;
  a4 = a5 & 0x22222222u;
  a4 |= a4 >> 1;
  a4 ^= (a5 << 1) & 0x22222222u;
  x ^= a4;
  y = ((x & 0xFEFEFEFEu) >> 1) | ((x & 0x01010101u) << 7);
  x &= 0x39393939u;
  x ^= y & 0x3F3F3F3Fu;
  y = ((y & 0xFCFCFCFCu) >> 2) | ((y & 0x03030303u) << 6);
  x ^= y & 0x97979797u;
  y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
  x ^= y & 0x9B9B9B9Bu;
  y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
  x ^= y & 0x3C3C3C3Cu;
  y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
  x ^= y & 0xDDDDDDDDu;
  y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
  x ^= y & 0x72727272u;
  x ^= 0x63636363u;
  *w = x;
}

static void
SubLong( ulong * w ) {
  ulong x, y, a1, a2, a3, a4, a5, a6;

  x = *w;
  y = ((x & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((x & (0x0101010101010101UL)) << 7);
  x &= (0xDDDDDDDDDDDDDDDDUL);
  x ^= y & (0x5757575757575757UL);
  y = ((y & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((y & (0x0101010101010101UL)) << 7);
  x ^= y & (0x1C1C1C1C1C1C1C1CUL);
  y = ((y & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((y & (0x0101010101010101UL)) << 7);
  x ^= y & (0x4A4A4A4A4A4A4A4AUL);
  y = ((y & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((y & (0x0101010101010101UL)) << 7);
  x ^= y & (0x4242424242424242UL);
  y = ((y & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((y & (0x0101010101010101UL)) << 7);
  x ^= y & (0x6464646464646464UL);
  y = ((y & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((y & (0x0101010101010101UL)) << 7);
  x ^= y & (0xE0E0E0E0E0E0E0E0UL);
  a1 = x;
  a1 ^= (x & (0xF0F0F0F0F0F0F0F0UL)) >> 4;
  a2 = ((x & (0xCCCCCCCCCCCCCCCCUL)) >> 2) | ((x & (0x3333333333333333UL)) << 2);
  a3 = x & a1;
  a3 ^= (a3 & (0xAAAAAAAAAAAAAAAAUL)) >> 1;
  a3 ^= (((x << 1) & a1) ^ ((a1 << 1) & x)) & (0xAAAAAAAAAAAAAAAAUL);
  a4 = a2 & a1;
  a4 ^= (a4 & (0xAAAAAAAAAAAAAAAAUL)) >> 1;
  a4 ^= (((a2 << 1) & a1) ^ ((a1 << 1) & a2)) & (0xAAAAAAAAAAAAAAAAUL);
  a5 = (a3 & (0xCCCCCCCCCCCCCCCCUL)) >> 2;
  a3 ^= ((a4 << 2) ^ a4) & (0xCCCCCCCCCCCCCCCCUL);
  a4 = a5 & (0x2222222222222222UL);
  a4 |= a4 >> 1;
  a4 ^= (a5 << 1) & (0x2222222222222222UL);
  a3 ^= a4;
  a5 = a3 & (0xA0A0A0A0A0A0A0A0UL);
  a5 |= a5 >> 1;
  a5 ^= (a3 << 1) & (0xA0A0A0A0A0A0A0A0UL);
  a4 = a5 & (0xC0C0C0C0C0C0C0C0UL);
  a6 = a4 >> 2;
  a4 ^= (a5 << 2) & (0xC0C0C0C0C0C0C0C0UL);
  a5 = a6 & (0x2020202020202020UL);
  a5 |= a5 >> 1;
  a5 ^= (a6 << 1) & (0x2020202020202020UL);
  a4 |= a5;
  a3 ^= a4 >> 4;
  a3 &= (0x0F0F0F0F0F0F0F0FUL);
  a2 = a3;
  a2 ^= (a3 & (0x0C0C0C0C0C0C0C0CUL)) >> 2;
  a4 = a3 & a2;
  a4 ^= (a4 & (0x0A0A0A0A0A0A0A0AUL)) >> 1;
  a4 ^= (((a3 << 1) & a2) ^ ((a2 << 1) & a3)) & (0x0A0A0A0A0A0A0A0AUL);
  a5 = a4 & (0x0808080808080808UL);
  a5 |= a5 >> 1;
  a5 ^= (a4 << 1) & (0x0808080808080808UL);
  a4 ^= a5 >> 2;
  a4 &= (0x0303030303030303UL);
  a4 ^= (a4 & (0x0202020202020202UL)) >> 1;
  a4 |= a4 << 2;
  a3 = a2 & a4;
  a3 ^= (a3 & (0x0A0A0A0A0A0A0A0AUL)) >> 1;
  a3 ^= (((a2 << 1) & a4) ^ ((a4 << 1) & a2)) & (0x0A0A0A0A0A0A0A0AUL);
  a3 |= a3 << 4;
  a2 = ((a1 & (0xCCCCCCCCCCCCCCCCUL)) >> 2) | ((a1 & (0x3333333333333333UL)) << 2);
  x = a1 & a3;
  x ^= (x & (0xAAAAAAAAAAAAAAAAUL)) >> 1;
  x ^= (((a1 << 1) & a3) ^ ((a3 << 1) & a1)) & (0xAAAAAAAAAAAAAAAAUL);
  a4 = a2 & a3;
  a4 ^= (a4 & (0xAAAAAAAAAAAAAAAAUL)) >> 1;
  a4 ^= (((a2 << 1) & a3) ^ ((a3 << 1) & a2)) & (0xAAAAAAAAAAAAAAAAUL);
  a5 = (x & (0xCCCCCCCCCCCCCCCCUL)) >> 2;
  x ^= ((a4 << 2) ^ a4) & (0xCCCCCCCCCCCCCCCCUL);
  a4 = a5 & (0x2222222222222222UL);
  a4 |= a4 >> 1;
  a4 ^= (a5 << 1) & (0x2222222222222222UL);
  x ^= a4;
  y = ((x & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((x & (0x0101010101010101UL)) << 7);
  x &= (0x3939393939393939UL);
  x ^= y & (0x3F3F3F3F3F3F3F3FUL);
  y = ((y & (0xFCFCFCFCFCFCFCFCUL)) >> 2) | ((y & (0x0303030303030303UL)) << 6);
  x ^= y & (0x9797979797979797UL);
  y = ((y & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((y & (0x0101010101010101UL)) << 7);
  x ^= y & (0x9B9B9B9B9B9B9B9BUL);
  y = ((y & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((y & (0x0101010101010101UL)) << 7);
  x ^= y & (0x3C3C3C3C3C3C3C3CUL);
  y = ((y & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((y & (0x0101010101010101UL)) << 7);
  x ^= y & (0xDDDDDDDDDDDDDDDDUL);
  y = ((y & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((y & (0x0101010101010101UL)) << 7);
  x ^= y & (0x7272727272727272UL);
  x ^= (0x6363636363636363UL);
  *w = x;
}

/*
 * This computes w := (S^-1 * (w + c))^-1
 */
static void
InvSubLong( ulong * w ) {
  ulong x, y, a1, a2, a3, a4, a5, a6;

  x = *w;
  x ^= (0x6363636363636363UL);
  y = ((x & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((x & (0x0101010101010101UL)) << 7);
  x &= (0xFDFDFDFDFDFDFDFDUL);
  x ^= y & (0x5E5E5E5E5E5E5E5EUL);
  y = ((y & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((y & (0x0101010101010101UL)) << 7);
  x ^= y & (0xF3F3F3F3F3F3F3F3UL);
  y = ((y & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((y & (0x0101010101010101UL)) << 7);
  x ^= y & (0xF5F5F5F5F5F5F5F5UL);
  y = ((y & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((y & (0x0101010101010101UL)) << 7);
  x ^= y & (0x7878787878787878UL);
  y = ((y & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((y & (0x0101010101010101UL)) << 7);
  x ^= y & (0x7777777777777777UL);
  y = ((y & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((y & (0x0101010101010101UL)) << 7);
  x ^= y & (0x1515151515151515UL);
  y = ((y & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((y & (0x0101010101010101UL)) << 7);
  x ^= y & (0xA5A5A5A5A5A5A5A5UL);
  a1 = x;
  a1 ^= (x & (0xF0F0F0F0F0F0F0F0UL)) >> 4;
  a2 = ((x & (0xCCCCCCCCCCCCCCCCUL)) >> 2) | ((x & (0x3333333333333333UL)) << 2);
  a3 = x & a1;
  a3 ^= (a3 & (0xAAAAAAAAAAAAAAAAUL)) >> 1;
  a3 ^= (((x << 1) & a1) ^ ((a1 << 1) & x)) & (0xAAAAAAAAAAAAAAAAUL);
  a4 = a2 & a1;
  a4 ^= (a4 & (0xAAAAAAAAAAAAAAAAUL)) >> 1;
  a4 ^= (((a2 << 1) & a1) ^ ((a1 << 1) & a2)) & (0xAAAAAAAAAAAAAAAAUL);
  a5 = (a3 & (0xCCCCCCCCCCCCCCCCUL)) >> 2;
  a3 ^= ((a4 << 2) ^ a4) & (0xCCCCCCCCCCCCCCCCUL);
  a4 = a5 & (0x2222222222222222UL);
  a4 |= a4 >> 1;
  a4 ^= (a5 << 1) & (0x2222222222222222UL);
  a3 ^= a4;
  a5 = a3 & (0xA0A0A0A0A0A0A0A0UL);
  a5 |= a5 >> 1;
  a5 ^= (a3 << 1) & (0xA0A0A0A0A0A0A0A0UL);
  a4 = a5 & (0xC0C0C0C0C0C0C0C0UL);
  a6 = a4 >> 2;
  a4 ^= (a5 << 2) & (0xC0C0C0C0C0C0C0C0UL);
  a5 = a6 & (0x2020202020202020UL);
  a5 |= a5 >> 1;
  a5 ^= (a6 << 1) & (0x2020202020202020UL);
  a4 |= a5;
  a3 ^= a4 >> 4;
  a3 &= (0x0F0F0F0F0F0F0F0FUL);
  a2 = a3;
  a2 ^= (a3 & (0x0C0C0C0C0C0C0C0CUL)) >> 2;
  a4 = a3 & a2;
  a4 ^= (a4 & (0x0A0A0A0A0A0A0A0AUL)) >> 1;
  a4 ^= (((a3 << 1) & a2) ^ ((a2 << 1) & a3)) & (0x0A0A0A0A0A0A0A0AUL);
  a5 = a4 & (0x0808080808080808UL);
  a5 |= a5 >> 1;
  a5 ^= (a4 << 1) & (0x0808080808080808UL);
  a4 ^= a5 >> 2;
  a4 &= (0x0303030303030303UL);
  a4 ^= (a4 & (0x0202020202020202UL)) >> 1;
  a4 |= a4 << 2;
  a3 = a2 & a4;
  a3 ^= (a3 & (0x0A0A0A0A0A0A0A0AUL)) >> 1;
  a3 ^= (((a2 << 1) & a4) ^ ((a4 << 1) & a2)) & (0x0A0A0A0A0A0A0A0AUL);
  a3 |= a3 << 4;
  a2 = ((a1 & (0xCCCCCCCCCCCCCCCCUL)) >> 2) | ((a1 & (0x3333333333333333UL)) << 2);
  x = a1 & a3;
  x ^= (x & (0xAAAAAAAAAAAAAAAAUL)) >> 1;
  x ^= (((a1 << 1) & a3) ^ ((a3 << 1) & a1)) & (0xAAAAAAAAAAAAAAAAUL);
  a4 = a2 & a3;
  a4 ^= (a4 & (0xAAAAAAAAAAAAAAAAUL)) >> 1;
  a4 ^= (((a2 << 1) & a3) ^ ((a3 << 1) & a2)) & (0xAAAAAAAAAAAAAAAAUL);
  a5 = (x & (0xCCCCCCCCCCCCCCCCUL)) >> 2;
  x ^= ((a4 << 2) ^ a4) & (0xCCCCCCCCCCCCCCCCUL);
  a4 = a5 & (0x2222222222222222UL);
  a4 |= a4 >> 1;
  a4 ^= (a5 << 1) & (0x2222222222222222UL);
  x ^= a4;
  y = ((x & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((x & (0x0101010101010101UL)) << 7);
  x &= (0xB5B5B5B5B5B5B5B5UL);
  x ^= y & (0x4040404040404040UL);
  y = ((y & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((y & (0x0101010101010101UL)) << 7);
  x ^= y & (0x8080808080808080UL);
  y = ((y & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((y & (0x0101010101010101UL)) << 7);
  x ^= y & (0x1616161616161616UL);
  y = ((y & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((y & (0x0101010101010101UL)) << 7);
  x ^= y & (0xEBEBEBEBEBEBEBEBUL);
  y = ((y & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((y & (0x0101010101010101UL)) << 7);
  x ^= y & (0x9797979797979797UL);
  y = ((y & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((y & (0x0101010101010101UL)) << 7);
  x ^= y & (0xFBFBFBFBFBFBFBFBUL);
  y = ((y & (0xFEFEFEFEFEFEFEFEUL)) >> 1) | ((y & (0x0101010101010101UL)) << 7);
  x ^= y & (0x7D7D7D7D7D7D7D7DUL);
  *w = x;
}

static void
ShiftRows( ulong * state ) {
  uchar s[4];
  uchar *s0;
  int r;

  s0 = (uchar *)state;
  for (r = 0; r < 4; r++) {
    s[0] = s0[0*4 + r];
    s[1] = s0[1*4 + r];
    s[2] = s0[2*4 + r];
    s[3] = s0[3*4 + r];
    s0[0*4 + r] = s[(r+0) % 4];
    s0[1*4 + r] = s[(r+1) % 4];
    s0[2*4 + r] = s[(r+2) % 4];
    s0[3*4 + r] = s[(r+3) % 4];
  }
}

static void
InvShiftRows( ulong * state ) {
  uchar s[4];
  uchar *s0;
  int r;

  s0 = (uchar *)state;
  for (r = 0; r < 4; r++) {
    s[0] = s0[0*4 + r];
    s[1] = s0[1*4 + r];
    s[2] = s0[2*4 + r];
    s[3] = s0[3*4 + r];
    s0[0*4 + r] = s[(4-r) % 4];
    s0[1*4 + r] = s[(5-r) % 4];
    s0[2*4 + r] = s[(6-r) % 4];
    s0[3*4 + r] = s[(7-r) % 4];
  }
}

static void
MixColumns( ulong * state ) {
  uni s1;
  uni s;
  int c;

  for (c = 0; c < 2; c++) {
    s1.d = state[c];
    s.d = s1.d;
    s.d ^= ((s.d & (0xFFFF0000FFFF0000UL)) >> 16)
            | ((s.d & (0x0000FFFF0000FFFFUL)) << 16);
    s.d ^= ((s.d & (0xFF00FF00FF00FF00UL)) >> 8)
            | ((s.d & (0x00FF00FF00FF00FFUL)) << 8);
    s.d ^= s1.d;
    XtimeLong(&s1.d);
    s.d ^= s1.d;
    s.b[0] ^= s1.b[1];
    s.b[1] ^= s1.b[2];
    s.b[2] ^= s1.b[3];
    s.b[3] ^= s1.b[0];
    s.b[4] ^= s1.b[5];
    s.b[5] ^= s1.b[6];
    s.b[6] ^= s1.b[7];
    s.b[7] ^= s1.b[4];
    state[c] = s.d;
  }
}

static void InvMixColumns(ulong * state)
{
  uni s1;
  uni s;
  int c;

  for (c = 0; c < 2; c++) {
    s1.d = state[c];
    s.d = s1.d;
    s.d ^= ((s.d & (0xFFFF0000FFFF0000UL)) >> 16)
            | ((s.d & (0x0000FFFF0000FFFFUL)) << 16);
    s.d ^= ((s.d & (0xFF00FF00FF00FF00UL)) >> 8)
            | ((s.d & (0x00FF00FF00FF00FFUL)) << 8);
    s.d ^= s1.d;
    XtimeLong(&s1.d);
    s.d ^= s1.d;
    s.b[0] ^= s1.b[1];
    s.b[1] ^= s1.b[2];
    s.b[2] ^= s1.b[3];
    s.b[3] ^= s1.b[0];
    s.b[4] ^= s1.b[5];
    s.b[5] ^= s1.b[6];
    s.b[6] ^= s1.b[7];
    s.b[7] ^= s1.b[4];
    XtimeLong(&s1.d);
    s1.d ^= ((s1.d & (0xFFFF0000FFFF0000UL)) >> 16)
            | ((s1.d & (0x0000FFFF0000FFFFUL)) << 16);
    s.d ^= s1.d;
    XtimeLong(&s1.d);
    s1.d ^= ((s1.d & (0xFF00FF00FF00FF00UL)) >> 8)
            | ((s1.d & (0x00FF00FF00FF00FFUL)) << 8);
    s.d ^= s1.d;
    state[c] = s.d;
  }
}

static void
AddRoundKey( ulong *       state,
             ulong const * w ) {
  state[0] ^= w[0];
  state[1] ^= w[1];
}

static void
Cipher( uchar const * in,
        uchar *       out,
        ulong const * w,
        int           nr ) {
  ulong state[2];
  int i;

  memcpy(state, in, 16);

  AddRoundKey(state, w);

  for (i = 1; i < nr; i++) {
    SubLong(&state[0]);
    SubLong(&state[1]);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, w + i*2);
  }

  SubLong(&state[0]);
  SubLong(&state[1]);
  ShiftRows(state);
  AddRoundKey(state, w + nr*2);

  memcpy(out, state, 16);
}

static void
InvCipher( uchar const * in,
           uchar *       out,
           ulong const * w,
           int           nr ) {
  ulong state[2];
  int i;

  memcpy(state, in, 16);

  AddRoundKey(state, w + nr*2);

  for (i = nr - 1; i > 0; i--) {
    InvShiftRows(state);
    InvSubLong(&state[0]);
    InvSubLong(&state[1]);
    AddRoundKey(state, w + i*2);
    InvMixColumns(state);
  }

  InvShiftRows(state);
  InvSubLong(&state[0]);
  InvSubLong(&state[1]);
  AddRoundKey(state, w);

  memcpy(out, state, 16);
}

static void
RotWord( uint * x ) {
  uchar *w0;
  uchar tmp;

  w0 = (uchar *)x;
  tmp = w0[0];
  w0[0] = w0[1];
  w0[1] = w0[2];
  w0[2] = w0[3];
  w0[3] = tmp;
}

static void
KeyExpansion( uchar const * key,
              ulong *       w,
              int           nr,
              int           nk ) {
  uint rcon;
  uni prev;
  uint temp;
  int i, n;

  memcpy( w, key, (ulong)nk*4UL );
  memcpy( &rcon, "\1\0\0\0", 4  );
  n = nk/2;
  prev.d = w[n-1];
  for (i = n; i < (nr+1)*2; i++) {
    temp = prev.w[1];
    if (i % n == 0) {
      RotWord(&temp);
      SubWord(&temp);
      temp ^= rcon;
      XtimeWord(&rcon);
    } else if (nk > 6 && i % n == 2) {
      SubWord(&temp);
    }
    prev.d = w[i-n];
    prev.w[0] ^= temp;
    prev.w[1] ^= prev.w[0];
    w[i] = prev.d;
  }
}

/**
 * Expand the cipher key into the encryption key schedule.
 */
int
fd_aes_ref_set_encrypt_key( uchar const *  userKey,
                            ulong const    bits,
                            fd_aes_key_t * key ) {
  ulong *rk;

  if (!userKey || !key)
      return -1;
  if (bits != 128 && bits != 192 && bits != 256)
      return -2;

  rk = (ulong *)fd_type_pun( key->rd_key );  /* strict aliasing violation */

  if (bits == 128)
      key->rounds = 10;
  else if (bits == 192)
      key->rounds = 12;
  else
      key->rounds = 14;

  KeyExpansion(userKey, rk, key->rounds, (int)(bits/32UL) );
  return 0;
}

/**
 * Expand the cipher key into the decryption key schedule.
 */
int
fd_aes_ref_set_decrypt_key( uchar const *  userKey,
                            ulong const    bits,
                            fd_aes_key_t * key )
{
  return fd_aes_ref_set_encrypt_key(userKey, bits, key);
}

/*
 * Encrypt a single block
 * in and out can overlap
 */
void
fd_aes_ref_encrypt_core( uchar const *        in,
                         uchar *              out,
                         fd_aes_key_t const * key ) {

  assert(in && out && key);
  ulong const * rk = (ulong *)fd_type_pun_const( key->rd_key );

  Cipher(in, out, rk, key->rounds);
}

/*
 * Decrypt a single block
 * in and out can overlap
 */
void
fd_aes_ref_decrypt_core( uchar const *        in,
                         uchar *              out,
                         fd_aes_key_t const * key ) {

  assert(in && out && key);
  ulong const * rk = (ulong const *)fd_type_pun_const( key->rd_key );

  InvCipher(in, out, rk, key->rounds );
}

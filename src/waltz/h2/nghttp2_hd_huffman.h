/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef NGHTTP2_HD_HUFFMAN_H
#define NGHTTP2_HD_HUFFMAN_H

//#ifdef HAVE_CONFIG_H
//#  include <config.h>
//#endif /* HAVE_CONFIG_H */

//#include <nghttp2/nghttp2.h>
#include <stdint.h>
#include <stddef.h>

typedef enum {
  /* FSA accepts this state as the end of huffman encoding
     sequence. */
  NGHTTP2_HUFF_ACCEPTED = 1 << 14,
  /* This state emits symbol */
  NGHTTP2_HUFF_SYM = 1 << 15,
} nghttp2_huff_decode_flag;

typedef struct {
  /* fstate is the current huffman decoding state, which is actually
     the node ID of internal huffman tree with
     nghttp2_huff_decode_flag OR-ed.  We have 257 leaf nodes, but they
     are identical to root node other than emitting a symbol, so we
     have 256 internal nodes [1..255], inclusive.  The node ID 256 is
     a special node and it is a terminal state that means decoding
     failed. */
  uint16_t fstate;
  /* symbol if NGHTTP2_HUFF_SYM flag set */
  uint8_t sym;
} nghttp2_huff_decode;

typedef nghttp2_huff_decode huff_decode_table_type[16];

typedef struct {
  /* fstate is the current huffman decoding state. */
  uint16_t fstate;
} nghttp2_hd_huff_decode_context;

typedef struct {
  /* The number of bits in this code */
  uint32_t nbits;
  /* Huffman code aligned to LSB */
  uint32_t code;
} nghttp2_huff_sym;

extern const nghttp2_huff_sym huff_sym_table[];
extern const nghttp2_huff_decode huff_decode_table[][16];

void nghttp2_hd_huff_decode_context_init(nghttp2_hd_huff_decode_context *ctx);

typedef struct {
  ///* This points to the beginning of the buffer. The effective range
  //   of buffer is [begin, end). */
  //uint8_t *begin;
  ///* This points to the memory one byte beyond the end of the
  //   buffer. */
  //uint8_t *end;
  ///* The position indicator for effective start of the buffer. pos <=
  //   last must be hold. */
  //uint8_t *pos;
  /* The position indicator for effective one beyond of the end of the
     buffer. last <= end must be hold. */
  uint8_t *last;
  ///* Mark arbitrary position in buffer [begin, end) */
  //uint8_t *mark;
} nghttp2_buf;

typedef long nghttp2_ssize;

typedef enum {
  /**
   * Header block inflate/deflate error.
   */
  NGHTTP2_ERR_HEADER_COMP = -523,
} nghttp2_error;

/*
 * Decodes the given data |src| with length |srclen|.  The |ctx| must
 * be initialized by nghttp2_hd_huff_decode_context_init(). The result
 * will be written to |buf|.  This function assumes that |buf| has the
 * enough room to store the decoded byte string.
 *
 * The caller must set the |fin| to nonzero if the given input is the
 * final block.
 *
 * This function returns the number of read bytes from the |in|.
 *
 * If this function fails, it returns one of the following negative
 * return codes:
 *
 * NGHTTP2_ERR_NOMEM
 *     Out of memory.
 * NGHTTP2_ERR_HEADER_COMP
 *     Decoding process has failed.
 */
nghttp2_ssize nghttp2_hd_huff_decode(nghttp2_hd_huff_decode_context *ctx,
                                     nghttp2_buf *buf, const uint8_t *src,
                                     size_t srclen, int fin);

#endif /* NGHTTP2_HD_HUFFMAN_H */

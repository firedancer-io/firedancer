// QUIC parsers

// TODO add platform optimized versions of these
// e.g. 32 bit unaligned fetch w/ byte swap on intel
#define FD_TEMPL_PARSE_IMPL_uint8(p) ( (uint8_t)((p)[0]) )
#define FD_TEMPL_PARSE_IMPL_uint16(p) (        \
    ( (uint16_t)((p)[0]) << (uint16_t)0x08 ) + \
    ( (uint16_t)((p)[1]) << (uint16_t)0x00 )  )
#define FD_TEMPL_PARSE_IMPL_uint32(p) (        \
    ( (uint32_t)((p)[0]) << (uint32_t)0x18 ) + \
    ( (uint32_t)((p)[1]) << (uint32_t)0x10 ) + \
    ( (uint32_t)((p)[2]) << (uint32_t)0x08 ) + \
    ( (uint32_t)((p)[3]) << (uint32_t)0x00 ) )
#define FD_TEMPL_PARSE_IMPL_uint64(p) (        \
    ( (uint64_t)((p)[0]) << (uint64_t)0x38 ) + \
    ( (uint64_t)((p)[1]) << (uint64_t)0x30 ) + \
    ( (uint64_t)((p)[2]) << (uint64_t)0x28 ) + \
    ( (uint64_t)((p)[3]) << (uint64_t)0x20 ) + \
    ( (uint64_t)((p)[4]) << (uint64_t)0x18 ) + \
    ( (uint64_t)((p)[5]) << (uint64_t)0x10 ) + \
    ( (uint64_t)((p)[6]) << (uint64_t)0x08 ) + \
    ( (uint64_t)((p)[7]) << (uint64_t)0x00 ) )

/* assigns parsed value
   result is the size of the type */
#define FD_TEMPL_PARSE(TYPE,VAR,p) \
  ( ( (VAR) = (__typeof__((VAR)))FD_TEMPL_PARSE_IMPL_##TYPE((p)) ), sizeof(fd_quic_##TYPE) )


// returns bytes consumed
#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                                  \
  size_t fd_quic_decode_##NAME( fd_quic_##NAME##_t * FD_RESTRICT out,    \
                                uchar const * FD_RESTRICT        buf,    \
                                size_t                           sz ) {  \
    (void)out; (void)buf; (void)sz;                                      \
    size_t cur_byte = 0;                                                 \
    size_t cur_bit = 0; (void)cur_bit;                                   \
    size_t tmp_len = 0; (void)tmp_len;                                   \
    unsigned varint_sizes[4] = { 6, 14, 30, 62 }; (void)varint_sizes;    \
    unsigned varint_bits; (void)varint_bits;
    // TODO check min size here

// consumes single aligned byte in input
#define FD_TEMPL_MBR_FRAME_TYPE(NAME,ID_LO,ID_HI)                        \
    out->NAME = buf[cur_byte];                                           \
    cur_byte++;


// consumes aligned bytes in input, sets cur_bit to 0
#define FD_TEMPL_MBR_ELEM(NAME,TYPE)                                         \
    cur_byte += (cur_bit != 0);                                              \
    cur_bit = 0;                                                             \
    if( cur_byte + sizeof(fd_quic_##TYPE) > sz ) return FD_QUIC_PARSE_FAIL;  \
    cur_byte += FD_TEMPL_PARSE(TYPE,out->NAME,buf+cur_byte);


// always aligned
// packet numbers have special parsing, due to being protected by
// header protection
// stores the offset for packet processing
#define FD_TEMPL_MBR_ELEM_PKTNUM(NAME,TYPE)                              \
    cur_byte += (cur_bit != 0);                                          \
    cur_bit = 0;                                                         \
    if( cur_byte >= sz ) return FD_QUIC_PARSE_FAIL;                      \
    out->NAME##_pnoff = (unsigned)cur_byte;                              \


// consumes varint
// always aligned
// most significant two bits represent the width of the int
// remaining bits are all data bits
#define FD_TEMPL_MBR_ELEM_VARINT(NAME,TYPE)                                             \
    cur_byte += (cur_bit != 0);                                                         \
    cur_bit = 0;                                                                        \
    if( cur_byte >= sz ) return FD_QUIC_PARSE_FAIL;                                     \
    varint_bits = varint_sizes[ buf[cur_byte] >> 6u ];                                  \
    cur_bit += 2;                                                                       \
    FD_TEMPL_MBR_ELEM_BITS(NAME,TYPE,varint_bits);


// consumes unaligned bits in input
#define FD_TEMPL_MBR_ELEM_BITS(NAME,TYPE,BITS)                                          \
    if( BITS + cur_bit > ( ( sz - cur_byte ) * 8 ) ) {                                  \
      return FD_QUIC_PARSE_FAIL;                                                        \
    }                                                                                   \
    out->NAME = (fd_quic_##TYPE)fd_quic_parse_bits( (buf + cur_byte), cur_bit, BITS );  \
    cur_bit += BITS;                                                                    \
    cur_byte += cur_bit >> 3;                                                           \
    cur_bit &= 7;

#define FD_TEMPL_MBR_ELEM_BITS_TYPE(NAME,TYPE,BITS,CODE) \
          FD_TEMPL_MBR_ELEM_BITS(NAME,TYPE,BITS)


// VAR currently assumed to be aligned bytes
#define FD_TEMPL_MBR_ELEM_VAR(NAME,BITS_MIN,BITS_MAX,LEN_NAME)                       \
    cur_byte += (cur_bit != 0);                                                      \
    cur_bit = 0;                                                                     \
    tmp_len = out->LEN_NAME;                                                         \
    if( ( (signed)tmp_len * 8 < (signed)BITS_MIN ) || ( tmp_len * 8 > BITS_MAX ) ) { \
      FD_DEBUG( "buffer overflow parsing variable length field."                     \
            "  field: " #NAME                                                        \
            "  BITS_MIN: %lu"                                                        \
            "  BITS_MAX: %lu"                                                        \
            "  " #LEN_NAME ": %lu"                                                   \
            "  tmp_len*8: %lu\n",                                                    \
            (unsigned long)BITS_MIN,                                                 \
            (unsigned long)BITS_MAX,                                                 \
            (unsigned long)out->LEN_NAME,                                            \
            (unsigned long)( tmp_len * 8 ) );                                        \
      return FD_QUIC_PARSE_FAIL;                                                     \
    }                                                                                \
    for( size_t j = 0; j < tmp_len; ++j ) {                                          \
        out->NAME[j] = buf[cur_byte+j];                                              \
    }                                                                                \
    cur_byte += tmp_len;


// VAR currently assumed to be aligned bytes
#define FD_TEMPL_MBR_ELEM_VAR_RAW(NAME,BITS_MIN,BITS_MAX,LEN_NAME)                   \
    cur_byte += (cur_bit != 0);                                                      \
    cur_bit = 0;                                                                     \
    tmp_len = out->LEN_NAME;                                                         \
    if( ( (signed)tmp_len * 8 < (signed)BITS_MIN ) || ( tmp_len * 8 > BITS_MAX ) ) { \
      FD_DEBUG( "buffer overflow parsing variable length field."                     \
            "  field: " #NAME                                                        \
            "  BITS_MIN: %lu"                                                        \
            "  BITS_MAX: %lu"                                                        \
            "  " #LEN_NAME ": %lu"                                                   \
            "  tmp_len*8: %lu\n",                                                    \
            (unsigned long)BITS_MIN,                                                 \
            (unsigned long)BITS_MAX,                                                 \
            (unsigned long)out->LEN_NAME,                                            \
            (unsigned long)( tmp_len * 8 ) );                                        \
      return FD_QUIC_PARSE_FAIL;                                                     \
    }                                                                                \
    out->NAME = &buf[cur_byte];                                                      \
    cur_byte += tmp_len;


/* ARRAY is an array of elements, each of the same size,
   with length implied by the packet size */
#define FD_TEMPL_MBR_ELEM_ARRAY(NAME,TYPE,BYTES_MIN,BYTES_MAX)        \
    cur_byte += (cur_bit != 0);                                       \
    cur_bit = 0;                                                      \
    tmp_len = sz - cur_byte;                                          \
    if( tmp_len > BYTES_MAX ) tmp_len = BYTES_MAX;                    \
    if( tmp_len % sizeof(fd_quic_##TYPE) ) return FD_QUIC_PARSE_FAIL; \
    tmp_len /= sizeof(fd_quic_##TYPE);                                \
    out->NAME##_len = (__typeof__(out->NAME##_len))tmp_len;           \
    for( size_t j = 0; j < tmp_len; ++j ) {                           \
      cur_byte += FD_TEMPL_PARSE(TYPE,out->NAME[j],buf+cur_byte);     \
    }

/* FIXED is an array of elements, each of the same size,
   with length constant */
#define FD_TEMPL_MBR_ELEM_FIXED(NAME,TYPE,BYTES)                      \
    cur_byte += (cur_bit != 0);                                       \
    cur_bit = 0;                                                      \
    if( BYTES > sz ) return FD_QUIC_PARSE_FAIL;                       \
    tmp_len = BYTES / sizeof(fd_quic_##TYPE);                         \
    for( size_t j = 0; j < tmp_len; ++j ) {                           \
      cur_byte += FD_TEMPL_PARSE(TYPE,out->NAME[j],buf+cur_byte);     \
    }

#if 0
#define FD_TEMPL_MBR_OPT(STRUCT,NAME,MASK,TEMPL)
#else
#define FD_TEMPL_MBR_OPT(TYPE_NAME,NAME,MASK,...)   \
    do {                                            \
      _Bool cond = out->TYPE_NAME & (MASK);         \
      out->NAME##_opt = cond;                       \
      if( cond ) {                                  \
        __VA_ARGS__                                 \
      }                                             \
    } while(0);
#endif


// at end, return the number of bytes consumed
#define FD_TEMPL_DEF_STRUCT_END(NAME) \
    cur_byte += (cur_bit != 0);       \
    return cur_byte;                  \
  }

#include "fd_quic_dft.h"


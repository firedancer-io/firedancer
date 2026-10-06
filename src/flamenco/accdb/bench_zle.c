#include "fd_zle.h"
#include "../../util/fd_util.h"

/* bench_zle: single-thread cache-hot encode/decode throughput on
   account shaped inputs, weighted to match mainnet.

   (This file is mostly AI-generated.)

   Workload was fit on full snapshot data at slot 442,351,854 (Aug 2026,
   1.076 B accounts, 343 GB of raw account data).  This file generates
   random account data that matches mainnet account distribution and
   fd_zle compression behavior within <0.1% margin of error.

   Solana mainnet's account distribution is dominated by a few types of
   programs, whose account data patterns are handwritten below.  (Since
   fd_zle is a zero length compressor, the account data patterns merely
   need to reconstruct where the zeros are, and can kill the rest with
   random bytes.)

   run[] alternates literal and zero run lengths starting with a literal
   run (a leading 0 means the account starts with zeros) and sums to
   data_len.  These are then randomized to prevent branch predictor
   overfitting. */

#define MAX_SZ (8UL<<20)

#define BENCH_WORK_SZ          ( 1UL<<30)
#define ALL_ZERO_BENCH_WORK_SZ (12UL<<30)

static uchar in  [ MAX_SZ+64UL ] __attribute__((aligned(64)));
static uchar comp[ FD_ZLE_COMPRESS_BOUND( MAX_SZ ) ] __attribute__((aligned(64)));
static uchar out [ MAX_SZ ] __attribute__((aligned(64)));

static ulong volatile sink;

/* Metaplex edition: a discriminator and a u64 supply. */
static uint const run_metaplex_edition[] = { 1, 8, 1, 10 };
/* pump.fun bonding curve: a discriminator, five u64 reserves and a
      complete flag.  Short literals split by the high zero bytes of little
      endian integers, right at the point where zero coding stops paying. */
static uint const run_pumpfun_curve[] = {
      15,      1,      5,      3,      7,      1,      1,      8,      6,      2 };
/* Metaplex token record: one pubkey sized blob, half of it unset. */
static uint const run_token_record[] = { 9, 23 };
/* A one byte account.  The floor case: 1 byte in, 2 bytes out. */
static uint const run_wormhole_1b[] = { 1 };
/* SPL Token account: mint and owner, the amount, then the delegate,
      state, is_native, delegated_amount and close_authority COptions,
      nearly all of them unset.  The most common account on Solana. */
static uint const run_spl_token_acct[] = { 70, 38, 1, 56 };
/* Token-2022 token account: the 165 byte SPL layout plus an account
      type discriminator and an empty TLV extension header. */
static uint const run_t22_acct[] = { 67, 41, 1, 56, 2, 3 };
/* SPL Token mint, the 61% that carry a freeze authority: barely
      compressible. */
static uint const run_spl_token_mint[] = { 1, 3, 33, 8, 2, 3, 32 };
/* SPL Token mint, the other 39%: no mint or freeze authority, so both
      COption bodies are zero. */
static uint const run_spl_token_mint_nofz[] = { 0, 4, 32, 1, 6, 1, 2, 36 };
/* PumpSwap AMM record: a short header, then all zeros. */
static uint const run_pumpswap_amm[] = { 40, 97 };
/* Stake account: meta, authorized, lockup and delegation.  Bimodal at
      66% and 81% of raw; this is the more common mode. */
static uint const run_stake_acct[] = {
       1,      3,      3,      5,     64,     48,     38,      2,      2,      6,      8,      6,      6,      8 };
/* Metaplex Token Metadata, the two dominant record versions.  Long
      trailing zero runs: name, symbol and uri are fixed width and mostly
      empty, and the v1.3 record over allocates. */
static uint const run_metaplex_md[] = {
      66,      3,     15,     17,      1,      3,      3,      7,      1,      3,     63,    137,      4,      3,
      33,      1,     32,      1,      5,    209 };
static uint const run_metaplex_md_v3[] = {
      66,      3,     14,     18,      1,      3,      3,      7,      1,      3,    116,     87,      6,      2,
       1,    348 };
/* Metaplex edition marker: a 248 byte bitmap that is almost always
      empty. */
static uint const run_metaplex_marker[] = { 1, 8, 1, 272 };
/* Address Lookup Table: densely packed pubkeys, 94% of raw.  The shape
      zero coding cannot help with. */
static uint const run_alt[] = {
       1,      3,     12,      5,     33,      2,     64,     32,     94,      1,     24,      1,     35,      4,
     129,      1,    127 };
/* Raydium AMM v4 AmmInfo: ~75 runs of densely packed u64 fields.  The
      worst common shape for a run coder, both for ratio and for the
      unpredictable branch per frame. */
static uint const run_raydium_amm[] = {
       1,      7,      1,      7,      1,      7,      1,      7,      1,      7,      1,      7,      1,     16,
       3,      4,      2,      6,      3,      5,      3,      5,      3,      5,      1,      8,      3,      5,
       3,      4,      1,      7,      2,      6,      1,      7,      2,      6,      1,      7,      1,      7,
       1,      7,      2,     22,      4,      4,      5,      3,      4,     28,      7,      9,      5,     11,
       4,      4,      5,     11,      7,      9,      6,      2,    123,      4,    161,     64,     34,      1,
       2,     11,      2,     14 };
/* OpenBook v1 queue: a live header over an empty ring. */
static uint const run_openbook_q[] = {
       6,      7,     64,     32,     16,   3088,      3,      5,      7 };
/* Meteora DAMM v2 pool: dense fixed point fields. */
static uint const run_meteora_damm[] = {
      11,     37,      1,      1,      1,    117,     59,      4,     65,     32,     32,     32,      4,      4,
       1,     23,      3,      1,      1,     11,     12,      4,      8,      8,      4,      4,      1,      4,
       1,      2,      7,     25,      4,     44,      4,     12,      1,     15,      4,      4,      1,     23,
       1,     15,     32,     16,      1,    415 };
/* Raydium AMM v4 pool state: a header over an unused tail. */
static uint const run_raydium_pool[] = { 32, 993, 4, 13, 6, 1144, 16 };
/* Serum v3 (defunct): a 5+5 byte magic sandwich around a slab that was
      never used.  99.9% zero, and 95 GB of chain state looks like this. */
static uint const run_serum_slab[] = { 6, 14511, 7 };
/* Meteora DLMM BinArray: ~70 bins of a few live bytes each followed by
      a fixed zero tail, i.e. a long stream of short frames.  Stresses the
      per frame cost rather than the copy loops. */
static uint const run_dlmm_bins[] = {
       9,      7,      1,      7,     32,     16,     11,    133,     11,    133,     11,    133,     11,    133,
      11,    133,     11,    133,     11,    133,     11,    133,     11,    133,     11,     69,      8,     56,
      11,     69,      8,     56,     11,     69,      8,     56,     11,     69,      8,     56,     11,     69,
       8,     56,     11,     69,      8,     56,     11,     69,      8,     56,     11,     69,      8,     56,
      11,     69,      8,     56,     11,     69,      8,     56,     11,     69,      8,     56,     11,     69,
       8,     56,     11,     69,      8,     56,     11,     69,      8,     56,     11,     69,      8,     56,
      11,     69,      8,     56,     11,     69,      8,     56,     11,     69,      8,     56,     11,     69,
       8,     56,     11,     69,      8,     56,     11,     69,      8,     56,     11,     69,      8,     56,
      11,     69,      8,     56,     11,     69,      8,     56,     11,     69,      8,     56,     11,     69,
       8,     56,     11,     69,      8,     56,     11,     69,      8,     56,     11,     69,      8,     56,
      11,     69,      8,     56,     11,     69,      8,     56,     11,     69,      8,     56,     11,     69,
       8,     56,     11,     69,      8,     56,     11,     53,      5,     11,      8,     56,     11,    133,
      11,    133,     11,    133,     11,    133,     11,    133,     11,    133,     11,    133,     11,    133,
      11,    133,     11,    133,     11,    133,     11,    133,     11,    133,     11,    133,     11,    133,
      11,    133,     11,    133,     11,    133,     11,    133,     11,    133,     11,    133,     11,    133,
      11,    133,     11,    133,     11,    133,     11,    117 };
/* Raydium CLMM TickArrayState: a handful of initialized ticks in a
      10 KiB array. */
static uint const run_clmm_ticks[] = { 44, 672, 4, 9405, 2, 113 };
static uint const run_serum_q_64k[] = { 6, 65487, 7 };
static uint const run_serum_slab_64k[] = { 6, 65535, 7 };
static uint const run_serum_q_256k[] = { 6, 262143, 7 };
struct shape {
  char const * name;
  ulong        acct;      /* accounts on chain with this layout */
  uint const * run;
  ulong        run_cnt;
};

typedef struct shape shape_t;

#define SHAPE( name, acct, run ) { (name), (acct), (run), sizeof(run)/sizeof(uint) }

static shape_t const shape[] = {
  SHAPE( "metaplex edition"       ,     22921472UL, run_metaplex_edition     ),
  SHAPE( "pump.fun curve"         ,      9347776UL, run_pumpfun_curve        ),
  SHAPE( "metaplex token record"  ,      3567168UL, run_token_record         ),
  SHAPE( "wormhole 1 B"           ,      1570816UL, run_wormhole_1b          ),
  SHAPE( "spl-token account"      ,    615273088UL, run_spl_token_acct       ),
  SHAPE( "token-2022 account"     ,     84784704UL, run_t22_acct             ),
  SHAPE( "spl-token mint"         ,     45047074UL, run_spl_token_mint       ),
  SHAPE( "spl-token mint nofz"    ,     29217565UL, run_spl_token_mint_nofz  ),
  SHAPE( "pumpswap amm"           ,      7725696UL, run_pumpswap_amm         ),
  SHAPE( "stake account"          ,      1442496UL, run_stake_acct           ),
  SHAPE( "metaplex metadata"      ,     42464896UL, run_metaplex_md          ),
  SHAPE( "metaplex metadata v1.3" ,      8667712UL, run_metaplex_md_v3       ),
  SHAPE( "metaplex edition marker",      2572480UL, run_metaplex_marker      ),
  SHAPE( "address lookup table"   ,       149056UL, run_alt                  ),
  SHAPE( "raydium amm v4 info"    ,       709184UL, run_raydium_amm          ),
  SHAPE( "openbook v1 queue"      ,      1618048UL, run_openbook_q           ),
  SHAPE( "meteora damm v2 pool"   ,      1436096UL, run_meteora_damm         ),
  SHAPE( "raydium amm v4 pool"    ,       705600UL, run_raydium_pool         ),
  SHAPE( "serum v3 slab"          ,      1050688UL, run_serum_slab           ),
  SHAPE( "meteora dlmm bins"      ,       450752UL, run_dlmm_bins            ),
  SHAPE( "raydium clmm ticks"     ,       424128UL, run_clmm_ticks           ),
  SHAPE( "serum v3 queue 64K"     ,        62848UL, run_serum_q_64k          ),
  SHAPE( "serum v3 slab 64K"      ,       288640UL, run_serum_slab_64k       ),
  SHAPE( "serum v3 queue 256K"    ,       141504UL, run_serum_q_256k         )
};

#define SHAPE_CNT (sizeof(shape)/sizeof(shape_t))

/* Band tails.  Each table is (literal run, zero run, cumulative weight
   in permille) sampled from the pooled interior texture of every
   unnamed account in that band. */

static uint const pair_tail0[][3] = {
  {      4,      4,   86 }, {      9,      3,  167 }, {      3,      5,  239 }, {     40,      1,  298 },
  {      4,      3,  348 }, {     12,      4,  399 }, {      5,      3,  445 }, {      8,      1,  490 },
  {     43,      5,  531 }, {      1,      3,  568 }, {      8,      8,  604 }, {     45,      4,  639 },
  {     41,      3,  673 }, {      3,      4,  705 }, {     45,      3,  737 }, {     10,      7,  769 },
  {     44,      4,  798 }, {     40,      8,  818 }, {      9,      1,  837 }, {     12,      5,  856 },
  {     12,      8,  874 }, {      1,      1,  888 }, {     45,      5,  902 }, {     13,      4,  916 },
  {     11,      5,  928 }, {      1,      8,  939 }, {      6,      2,  950 }, {      2,      1,  961 },
  {     44,      8,  971 }, {      1,      7,  982 }, {      9,      7,  991 }, {     36,      1, 1000 }
};
static uint const pair_tail1[][3] = {
  {      1,      3,   86 }, {      1,      1,  162 }, {      4,      4,  237 }, {      2,      3,  303 },
  {      6,      1,  369 }, {      6,      2,  430 }, {      1,     29,  477 }, {      1,      8,  522 },
  {      8,      1,  567 }, {      5,      4,  606 }, {      2,      6,  644 }, {      5,      3,  681 },
  {      3,      5,  708 }, {      7,      1,  735 }, {     15,      1,  760 }, {      2,      7,  779 },
  {     67,      3,  798 }, {     77,      4,  816 }, {      4,      5,  834 }, {     64,     29,  852 },
  {      1,      7,  867 }, {      4,      3,  882 }, {     32,      1,  896 }, {      3,      4,  910 },
  {      1,      4,  922 }, {     40,     16,  935 }, {     11,      3,  947 }, {      9,      1,  958 },
  {      3,     29,  969 }, {      9,      3,  980 }, {     12,      4,  990 }, {     32,      8, 1000 }
};
static uint const pair_tail2[][3] = {
  {      1,      1,  175 }, {      4,      4,  296 }, {      1,      3,  363 }, {     33,     33,  425 },
  {      2,     36,  481 }, {      2,      1,  534 }, {      1,      7,  574 }, {      5,      3,  609 },
  {      6,     36,  643 }, {      4,      3,  670 }, {     32,      1,  692 }, {      2,      3,  713 },
  {      4,     36,  732 }, {     65,      1,  750 }, {      2,      6,  768 }, {      3,      1,  785 },
  {     67,      3,  802 }, {      3,      5,  819 }, {      6,      3,  834 }, {     32,     34,  849 },
  {     80,      3,  864 }, {      6,      2,  879 }, {      7,      3,  894 }, {     33,      1,  907 },
  {      7,     36,  921 }, {     10,      6,  934 }, {      9,      3,  947 }, {      8,     36,  958 },
  {      2,      2,  969 }, {      1,      8,  980 }, {      6,      1,  990 }, {      7,      1, 1000 }
};
static uint const pair_tail3[][3] = {
  {      4,      4,  225 }, {      5,      3,  336 }, {     20,      4,  408 }, {      6,      2,  474 },
  {      2,      2,  529 }, {      9,      7,  569 }, {      8,      8,  605 }, {      1,      1,  638 },
  {      4,     12,  669 }, {      7,      9,  695 }, {      5,     11,  720 }, {      1,      3,  745 },
  {      3,     13,  768 }, {     10,      6,  788 }, {      1,      7,  807 }, {      6,     10,  825 },
  {      1,     15,  842 }, {      2,      1,  857 }, {      2,      6,  872 }, {      8,     15,  886 },
  {      3,      5,  899 }, {     16,     15,  910 }, {     64,     15,  921 }, {      6,      7,  932 },
  {      2,     14,  943 }, {     12,      4,  953 }, {     11,      5,  961 }, {     32,     15,  970 },
  {      5,      4,  978 }, {      3,     15,  985 }, {      4,      1,  993 }, {      4,      3, 1000 }
};
static uint const pair_tail4[][3] = {
  {      8,     24,  152 }, {      8,     36,  297 }, {      9,      7,  381 }, {      8,      8,  461 },
  {     11,      5,  518 }, {     12,      4,  551 }, {      7,      9,  581 }, {      9,     35,  611 },
  {      1,      3,  641 }, {      4,      4,  670 }, {      2,      2,  695 }, {      1,      1,  719 },
  {     10,      6,  742 }, {      6,     36,  764 }, {      2,      6,  786 }, {      2,     36,  806 },
  {      1,      7,  824 }, {     12,     32,  843 }, {      1,     36,  860 }, {      3,      5,  877 },
  {      7,     36,  891 }, {      3,      8,  906 }, {      7,     25,  918 }, {      9,     23,  929 },
  {      2,      1,  940 }, {      3,     13,  950 }, {      4,     36,  960 }, {      4,      1,  969 },
  {    220,      4,  977 }, {      4,     12,  985 }, {      1,      5,  993 }, {     32,      1, 1000 }
};
static uint const pair_tail5[][3] = {
  {      2,      2,  178 }, {      1,      3,  318 }, {      2,      6,  436 }, {      4,      4,  523 },
  {      1,      1,  602 }, {      3,      5,  656 }, {      8,     24,  705 }, {      1,      7,  733 },
  {      9,      7,  760 }, {     12,     24,  785 }, {      6,      2,  805 }, {      3,      1,  821 },
  {     11,     24,  836 }, {     63,     24,  851 }, {      8,      8,  865 }, {      1,      5,  879 },
  {      6,      6,  891 }, {      5,      3,  902 }, {      6,      3,  912 }, {      2,     10,  921 },
  {      2,      4,  930 }, {     12,      4,  939 }, {      5,      4,  947 }, {      2,      1,  955 },
  {      9,     23,  962 }, {     32,     24,  968 }, {      2,      3,  974 }, {     11,     21,  980 },
  {      8,      1,  985 }, {     10,      6,  990 }, {      1,      2,  995 }, {     11,      5, 1000 }
};
static uint const pair_tail6[][3] = {
  {      2,      2,  247 }, {      4,      4,  395 }, {      2,      6,  537 }, {      1,      3,  656 },
  {      3,      5,  760 }, {      1,      6,  804 }, {      1,      1,  833 }, {      6,      6,  858 },
  {      3,      1,  880 }, {      1,      5,  899 }, {      3,      6,  916 }, {      6,      2,  932 },
  {      8,      4,  944 }, {      2,      4,  954 }, {      7,      5,  959 }, {      5,      3,  964 },
  {      2,      1,  969 }, {      1,      4,  973 }, {     63,      6,  978 }, {     32,      6,  981 },
  {      5,      6,  984 }, {      5,      1,  987 }, {      4,      6,  989 }, {      2,      3,  991 },
  {      9,      6,  993 }, {     10,      6,  994 }, {     34,      6,  995 }, {      1,      2,  997 },
  {     11,      5,  998 }, {      7,      1,  999 }, {      2,      5, 1000 }, {     42,      6, 1001 }
};
static uint const pair_tail7[][3] = {
  {      2,      2,  179 }, {      4,      4,  335 }, {      1,      3,  481 }, {      2,      6,  606 },
  {      3,      5,  713 }, {      1,      7,  746 }, {      6,      6,  773 }, {      3,      1,  798 },
  {     63,      7,  822 }, {      1,      1,  846 }, {      6,      2,  862 }, {      3,      7,  878 },
  {      8,      4,  891 }, {      1,      5,  905 }, {     42,      6,  917 }, {      4,      7,  928 },
  {      2,      4,  938 }, {     10,      6,  948 }, {      5,      3,  953 }, {      7,      5,  959 },
  {      1,      4,  964 }, {      2,      1,  969 }, {     18,      7,  973 }, {      5,      7,  977 },
  {     16,      7,  981 }, {     14,      7,  984 }, {     41,      7,  987 }, {     21,      7,  990 },
  {     12,      7,  993 }, {      2,      7,  996 }, {     17,      7,  998 }, {     19,      7, 1000 }
};

struct synth {
  char const * name;
  ulong        acct;      /* accounts on chain this case stands for */
  ulong        sz;        /* mean data_len of the band tail */
  ulong        code_sz;   /* sampled prefix; the rest is one zero run */
  uint const   (* pair)[3];
  ulong        pair_cnt;
};

typedef struct synth synth_t;

#define SYNTH( name, acct, sz, code, tbl ) \
  { (name), (acct), (sz), (code), (tbl), sizeof(tbl)/sizeof(tbl[0]) }

static synth_t const synth[] = {
  SYNTH( "tail 1-64"     ,     39997696UL,       29UL,       23UL, pair_tail0 ),
  SYNTH( "tail 65-256"   ,    111374912UL,      140UL,       81UL, pair_tail1 ),
  SYNTH( "tail 257-1K"   ,     35740800UL,      456UL,      310UL, pair_tail2 ),
  SYNTH( "tail 1K-4K"    ,      4929344UL,     2175UL,      489UL, pair_tail3 ),
  SYNTH( "tail 4K-16K"   ,      2348352UL,     7771UL,     3015UL, pair_tail4 ),
  SYNTH( "tail 16K-64K"  ,        41856UL,    29668UL,    14285UL, pair_tail5 ),
  SYNTH( "tail 64K-1M"   ,        90944UL,   237237UL,    90209UL, pair_tail6 ),
  SYNTH( "tail >1M"      ,         4160UL,  1958702UL,   784949UL, pair_tail7 )
};

#define SYNTH_CNT (sizeof(synth)/sizeof(synth_t))

/* The snapshot itself, per band, for the fit report. */

struct ref {
  char const * name;
  ulong        acct;
  ulong        raw;
  ulong        comp;
};

static struct ref const chain[] = {
  { "1-64"    ,      77404928UL,      2189840832UL,      1513895168UL },
  { "65-256"  ,     894865536UL,    138967900928UL,     67748377024UL },
  { "257-1K"  ,      90304128UL,     49319376576UL,     20453432448UL },
  { "1K-4K"   ,       8689088UL,     19099444736UL,      2356349184UL },
  { "4K-16K"  ,       4273920UL,     42421981440UL,      3532961792UL },
  { "16K-64K" ,        104704UL,      5358324928UL,       319812416UL },
  { "64K-1M"  ,        521088UL,     77591140672UL,      4857884224UL },
  { ">1M"     ,          4160UL,      8148198720UL,      2169811200UL }
};

#define BAND_CNT (sizeof(chain)/sizeof(struct ref))

static ulong
band_of( ulong sz ) {
  ulong b = 0UL;
  static ulong const edge[] = { 64UL, 256UL, 1024UL, 4096UL, 16384UL, 65536UL, 1UL<<20 };
  for( ulong i=0UL; i<sizeof(edge)/sizeof(ulong); i++ ) b += (ulong)( sz>edge[i] );
  return b;
}

/* fill_runs writes a run length sequence into in, literal runs filled
   with non-zero random bytes.  Returns the total size.  The pad up to
   the next 64 byte boundary is poisoned, so a pad byte leaking into the
   output would break the round trip check in bench(). */

static ulong
fill_runs( fd_rng_t *   rng,
           uint const * run,
           ulong        run_cnt ) {
  ulong j = 0UL;
  for( ulong i=0UL; i<run_cnt; i++ ) {
    ulong len = run[ i ];
    if( i & 1UL ) { fd_memset( in+j, 0, len ); j += len; }
    else          { for( ulong k=0UL; k<len; k++ ) in[ j++ ] = (uchar)( fd_rng_uint( rng ) | 1U ); }
  }
  fd_memset( in+j, 0xff, fd_ulong_align_up( j, 64UL )+64UL-j );
  return j;
}

/* fill_synth resamples a band tail's run texture, then closes the
   account with one zero run.  Pair selection walks a Weyl sequence
   rather than the rng: the draws have to be reproducible outside this
   file, because code_sz was calibrated against them so that the case
   lands on its band tail's real compression ratio. */

static ulong
fill_synth( fd_rng_t *      rng,
            synth_t const * s ) {
  ulong j = 0UL;
  for( ulong d=1UL; j<s->code_sz; d++ ) {
    ulong wgt = ( ( d*2654435761UL )>>8 ) % 1000UL;
    ulong i   = 0UL; while( i<s->pair_cnt-1UL && s->pair[i][2]<=wgt ) i++;
    ulong lit = s->pair[i][0];
    ulong zer = s->pair[i][1];
    for( ulong k=0UL; k<lit && j<s->code_sz; k++ ) in[ j++ ] = (uchar)( fd_rng_uint( rng ) | 1U );
    for( ulong k=0UL; k<zer && j<s->code_sz; k++ ) in[ j++ ] = 0;
  }
  fd_memset( in+j,      0,    s->sz-j );
  fd_memset( in+s->sz,  0xff, 64UL    );
  return s->sz;
}

/* Column rules and headers are dimmed so the numbers read first;
   fd_log strips the escapes from the log file. */

#define DIM (fd_log_style_dim())
#define RST (fd_log_style_normal())

static void
hdr_cases( void ) {
  FD_LOG_NOTICE(( "%s%-24s %10s %14s | %8s | %8s %8s | %8s %8s%s",
                  DIM, "case", "size", "accounts", "ratio",
                  "enc GB/s", "enc ns/B", "dec GB/s", "dec ns/B", RST ));
}

/* bench times one input and returns its compressed size.  For the small
   shapes the per account cost matters more than the throughput, since
   the fixed cost of a call dominates there. */

static ulong
bench( char const * name,
       ulong        sz,
       ulong        acct,
       ulong        work_sz,
       double *     opt_enc_ns,
       double *     opt_dec_ns ) {
  ulong comp_sz = fd_zle_compress( comp, in, sz );
  FD_TEST( fd_zle_decompress( out, sz, comp, comp_sz )==(long)sz );
  FD_TEST( 0==memcmp( out, in, sz ) );

  ulong iter = 1UL + work_sz/sz;
  /* The 1-byte Wormhole case otherwise makes over a billion calls. */
  if( FD_UNLIKELY( sz==1UL ) ) iter = 1UL<<24;

  for( ulong i=0UL; i<iter/8UL+1UL; i++ ) sink += fd_zle_compress( comp, in, sz );

  long t0 = fd_log_wallclock();
  for( ulong i=0UL; i<iter; i++ ) sink += fd_zle_compress( comp, in, sz );
  long t1 = fd_log_wallclock();
  for( ulong i=0UL; i<iter; i++ ) sink += (ulong)fd_zle_decompress( out, sz, comp, comp_sz );
  long t2 = fd_log_wallclock();

  double bytes  = (double)sz*(double)iter;
  double enc_ns = (double)(t1-t0)/(double)iter;
  double dec_ns = (double)(t2-t1)/(double)iter;

  FD_LOG_NOTICE(( "%-24s %10lu %14lu %s|%s %7.2f%% %s|%s %8.2f %8.4f %s|%s %8.2f %8.4f",
                  name, sz, acct, DIM, RST,
                  100.*(double)comp_sz/(double)sz, DIM, RST,
                  bytes/(double)(t1-t0), enc_ns/(double)sz, DIM, RST,
                  bytes/(double)(t2-t1), dec_ns/(double)sz ));

  if( opt_enc_ns ) *opt_enc_ns = enc_ns;
  if( opt_dec_ns ) *opt_dec_ns = dec_ns;
  return comp_sz;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  uint seed = fd_env_strip_cmdline_uint( &argc, &argv, "--seed", NULL, 42U );
  int  do_synth = !fd_env_strip_cmdline_contains( &argc, &argv, "--no-synth" );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  FD_TEST( rng );

  double b_acct[ BAND_CNT ], b_raw[ BAND_CNT ], b_comp[ BAND_CNT ];
  double b_enc [ BAND_CNT ], b_dec[ BAND_CNT ];
  for( ulong b=0UL; b<BAND_CNT; b++ ) b_acct[b] = b_raw[b] = b_comp[b] = b_enc[b] = b_dec[b] = 0.;

  hdr_cases();

  for( ulong i=0UL; i<SHAPE_CNT+SYNTH_CNT; i++ ) {
    char const * name;
    ulong        acct, sz;
    if( i<SHAPE_CNT ) {
      shape_t const * s = shape+i;
      name = s->name; acct = s->acct; sz = fill_runs( rng, s->run, s->run_cnt );
    } else {
      synth_t const * s = synth+(i-SHAPE_CNT);
      name = s->name; acct = s->acct; sz = fill_synth( rng, s );
    }

    double enc_ns, dec_ns;
    ulong  comp_sz = bench( name, sz, acct, BENCH_WORK_SZ, &enc_ns, &dec_ns );

    ulong  b = band_of( sz );
    double n = (double)acct;
    b_acct[b] += n;
    b_raw [b] += n*(double)sz;
    b_comp[b] += n*(double)comp_sz;
    b_enc [b] += n*enc_ns;
    b_dec [b] += n*dec_ns;
  }

  /* Synthetic bounds.  Neither shape occurs on chain and neither is in
     the mix; they bracket what the coder can do. */

  if( do_synth ) {

    FD_LOG_NOTICE(( "%s-- synthetic bounds (not in the mix) --%s", DIM, RST ));

    for( ulong j=0UL; j<MAX_SZ; j++ ) in[j] = (uchar)fd_rng_uint( rng );
    bench( "uniform random 8 MiB", MAX_SZ, 0UL, BENCH_WORK_SZ, NULL, NULL );

    fd_memset( in, 0, MAX_SZ+64UL );
    bench( "all-zero 64 B",     64UL,     0UL, ALL_ZERO_BENCH_WORK_SZ, NULL, NULL );
    bench( "all-zero 256 B",   256UL,     0UL, ALL_ZERO_BENCH_WORK_SZ, NULL, NULL );
    bench( "all-zero 1 KiB",     1UL<<10, 0UL, ALL_ZERO_BENCH_WORK_SZ, NULL, NULL );
    bench( "all-zero 4 KiB",     4UL<<10, 0UL, ALL_ZERO_BENCH_WORK_SZ, NULL, NULL );
    bench( "all-zero 16 KiB",   16UL<<10, 0UL, ALL_ZERO_BENCH_WORK_SZ, NULL, NULL );
    bench( "all-zero 64 KiB",   64UL<<10, 0UL, ALL_ZERO_BENCH_WORK_SZ, NULL, NULL );
    bench( "all-zero 1 MiB",     1UL<<20, 0UL, ALL_ZERO_BENCH_WORK_SZ, NULL, NULL );
    bench( "all-zero 8 MiB", MAX_SZ,      0UL, ALL_ZERO_BENCH_WORK_SZ, NULL, NULL );

  }

  /* How well the mix reproduces the snapshot, band by band. */

  double ta = 0., tr = 0., tc = 0., te = 0., td = 0.;
  double ca = 0., cr = 0., cc = 0.;
  FD_LOG_NOTICE(( "%s-- band fit vs snapshot --%s", DIM, RST ));
  FD_LOG_NOTICE(( "%s%-8s %14s %14s %9s %9s %9s %9s%s", DIM, "band", "accounts", "raw bytes",
                  "acct err", "byte err", "mix ratio", "chain", RST ));
  for( ulong b=0UL; b<BAND_CNT; b++ ) {
    FD_LOG_NOTICE(( "%-8s %14.0f %14.0f %8.2f%% %8.2f%% %8.2f%% %8.2f%%",
                    chain[b].name, b_acct[b], b_raw[b],
                    100.*(b_acct[b]-(double)chain[b].acct)/(double)chain[b].acct,
                    100.*(b_raw [b]-(double)chain[b].raw )/(double)chain[b].raw,
                    100.*b_comp[b]/b_raw[b],
                    100.*(double)chain[b].comp/(double)chain[b].raw ));
    ta += b_acct[b]; tr += b_raw[b]; tc += b_comp[b]; te += b_enc[b]; td += b_dec[b];
    ca += (double)chain[b].acct; cr += (double)chain[b].raw; cc += (double)chain[b].comp;
  }
  FD_LOG_NOTICE(( "%s%-8s%s %14.0f %14.0f %8.2f%% %8.2f%% %8.2f%% %8.2f%%",
                  fd_log_style_bold(), "TOTAL", RST, ta, tr, 100.*(ta-ca)/ca, 100.*(tr-cr)/cr,
                  100.*tc/tr, 100.*cc/cr ));
  FD_LOG_NOTICE(( "%smix%s: %.2f%% of raw, enc %.4f ns/B (%.2f GB/s), dec %.4f ns/B (%.2f GB/s)",
                  fd_log_style_bold(), RST,
                  100.*tc/tr, te/tr, tr/te, td/tr, tr/td ));

  fd_rng_delete( fd_rng_leave( rng ) );
  fd_halt();
  return 0;
}

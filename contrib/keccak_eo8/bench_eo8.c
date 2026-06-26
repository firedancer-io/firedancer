/* bench_eo8.c — EO-8 (even/odd bit-interleaved, 8-way) Keccak-f[1600]
   permutation, register-renamed (no stack b-array, like our native keccak8),
   benched against the validated native-8 (linked from the firedancer build).

   Layout: 8 parallel states.  Each 64-bit lane w splits into
     E = even bits of w (32 bits),  O = odd bits of w (32 bits).
   One zmm per Keccak lane holds [E_s0..E_s7 | O_s0..O_s7] as 16 u32:
     u32 index 0..7  = E of states 0..7   (low  256 bits)
     u32 index 8..15 = O of states 0..7   (high 256 bits)

   Rotation by a compile-time constant D, producing CANONICAL (E,O) output:
     D == 0      : identity
     D even (2k) : rol32 both halves by k                 -> vprold        (1 op)
     D odd (2k+1): swap halves, then rol32 low by k+1,
                   high by k                               -> vshufi+vprolvd (2 ops)
   (The "compile-time swap" idea makes the swap free at the rotate, but theta-C
   and chi then need the lanes in a consistent orientation, which is why we
   materialize canonical here.)

   All XOR / chi / iota are bitwise and identical in EO form (vpternlogq).

   Public domain. */

#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

typedef __m512i v512u;

/* ---- native-8 raw entry, linked from the firedancer object ---------- */
extern void fd_keccak256_avx512_keccak8_f1600_raw( void * state_soa, const unsigned long * rc );

static const uint64_t RC[24] = {
  0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
  0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
  0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
  0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
  0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
  0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL };

/* ===== compact scalar Keccak-f[1600] reference (for correctness) ====== */
static const int RHO[25] = { 0,1,62,28,27, 36,44,6,55,20, 3,10,43,25,39,
                             41,45,15,21,8, 18,2,61,56,14 };
static const int PIo[25] = { 0,10,20,5,15, 16,1,11,21,6, 7,17,2,12,22,
                             23,8,18,3,13, 14,24,9,19,4 };
static inline uint64_t rol64(uint64_t x,int r){ return r? (x<<r)|(x>>(64-r)) : x; }
static void keccak_ref(uint64_t a[25]){
  for(int rnd=0;rnd<24;rnd++){
    uint64_t C[5],D[5],b[25];
    for(int x=0;x<5;x++) C[x]=a[x]^a[x+5]^a[x+10]^a[x+15]^a[x+20];
    for(int x=0;x<5;x++) D[x]=C[(x+4)%5]^rol64(C[(x+1)%5],1);
    for(int x=0;x<5;x++) for(int y=0;y<5;y++) a[x+5*y]^=D[x];
    for(int i=0;i<25;i++) b[PIo[i]]=rol64(a[i],RHO[i]);
    for(int y=0;y<5;y++) for(int x=0;x<5;x++)
      a[5*y+x]=b[5*y+x]^((~b[5*y+(x+1)%5])&b[5*y+(x+2)%5]);
    a[0]^=RC[rnd];
  }
}

/* ===== EO-8 permutation ================================================ */
#define XOR(a,b)        _mm512_xor_si512((a),(b))
#define XOR3(a,b,c)     _mm512_ternarylogic_epi64((a),(b),(c),0x96)
#define XOR5(a,b,c,d,e) XOR3(XOR3((a),(b),(c)),(d),(e))
#define CHI(a,b,c)      _mm512_ternarylogic_epi64((a),(b),(c),0xD2)
#define SWAPH(v)        _mm512_shuffle_i64x2((v),(v),0x4E)  /* swap 256-bit halves */

/* canonical EO rotate-left by compile-time D */
#define EO_ROL(in, D)  (                                                          \
    (D)==0 ? (in)                                                                 \
  : ((D)&1)==0 ? _mm512_rol_epi32((in),(D)/2)                                      \
  : _mm512_rolv_epi32( SWAPH(in),                                                  \
      _mm512_set_epi32( (D)/2,(D)/2,(D)/2,(D)/2,(D)/2,(D)/2,(D)/2,(D)/2,           \
                        (D)/2+1,(D)/2+1,(D)/2+1,(D)/2+1,(D)/2+1,(D)/2+1,(D)/2+1,(D)/2+1 ) ) )

/* Register-renamed EO permutation (no stack b-array): same structure as our
   native keccak8, with ROL replaced by EO_ROL.  pi is compile-time renaming. */
#define DV \
  v512u _Ba,_Be,_Bi,_Bo,_Bu, _Da,_De,_Di,_Do,_Du, \
        _ba,_be,_bi,_bo,_bu, _ga,_ge,_gi,_go,_gu, _ka,_ke,_ki,_ko,_ku, \
        _ma,_me,_mi,_mo,_mu, _sa,_se,_si,_so,_su
#define TRPC(L1,L2,L3,L4,L5, B1,B2,B3,B4,B5, R1,R2,R3,R4,R5) \
  B1=EO_ROL(XOR(L1,_Da),R1); B2=EO_ROL(XOR(L2,_De),R2); B3=EO_ROL(XOR(L3,_Di),R3); \
  B4=EO_ROL(XOR(L4,_Do),R4); B5=EO_ROL(XOR(L5,_Du),R5); \
  L1=CHI(_Ba,_Be,_Bi); L2=CHI(_Be,_Bi,_Bo); L3=CHI(_Bi,_Bo,_Bu); L4=CHI(_Bo,_Bu,_Ba); L5=CHI(_Bu,_Ba,_Be)
#define TRPI0(L1,L2,L3,L4,L5, rc) \
  _Ba=XOR5(_ba,_ga,_ka,_ma,_sa); _Be=XOR5(_be,_ge,_ke,_me,_se); _Bi=XOR5(_bi,_gi,_ki,_mi,_si); \
  _Bo=XOR5(_bo,_go,_ko,_mo,_so); _Bu=XOR5(_bu,_gu,_ku,_mu,_su); \
  _Da=EO_ROL(_Be,1); _De=EO_ROL(_Bi,1); _Di=EO_ROL(_Bo,1); _Do=EO_ROL(_Bu,1); _Du=EO_ROL(_Ba,1); \
  _Da=XOR(_Da,_Bu); _De=XOR(_De,_Ba); _Di=XOR(_Di,_Be); _Do=XOR(_Do,_Bi); _Du=XOR(_Du,_Bo); \
  TRPC(L1,L2,L3,L4,L5, _Ba,_Be,_Bi,_Bo,_Bu, 0,44,43,21,14); L1=XOR(L1,rc)
#define TR1(L1,L2,L3,L4,L5) TRPC(L1,L2,L3,L4,L5, _Bi,_Bo,_Bu,_Ba,_Be, 3,45,61,28,20)
#define TR2(L1,L2,L3,L4,L5) TRPC(L1,L2,L3,L4,L5, _Bu,_Ba,_Be,_Bi,_Bo, 18,1,6,25,8)
#define TR3(L1,L2,L3,L4,L5) TRPC(L1,L2,L3,L4,L5, _Be,_Bi,_Bo,_Bu,_Ba, 36,10,15,56,27)
#define TR4(L1,L2,L3,L4,L5) TRPC(L1,L2,L3,L4,L5, _Bo,_Bu,_Ba,_Be,_Bi, 41,2,62,55,39)
#define R4(i) \
  TRPI0(_ba,_ge,_ki,_mo,_su, rc_eo[(i)+0]); TR1(_ka,_me,_si,_bo,_gu); TR2(_sa,_be,_gi,_ko,_mu); TR3(_ga,_ke,_mi,_so,_bu); TR4(_ma,_se,_bi,_go,_ku); \
  TRPI0(_ba,_me,_gi,_so,_ku, rc_eo[(i)+1]); TR1(_sa,_ke,_bi,_mo,_gu); TR2(_ma,_ge,_si,_ko,_bu); TR3(_ka,_be,_mi,_go,_su); TR4(_ga,_se,_ki,_bo,_mu); \
  TRPI0(_ba,_ke,_si,_go,_mu, rc_eo[(i)+2]); TR1(_ma,_be,_ki,_so,_gu); TR2(_ga,_me,_bi,_ko,_su); TR3(_sa,_ge,_mi,_bo,_ku); TR4(_ka,_se,_gi,_mo,_bu); \
  TRPI0(_ba,_be,_bi,_bo,_bu, rc_eo[(i)+3]); TR1(_ga,_ge,_gi,_go,_gu); TR2(_ka,_ke,_ki,_ko,_ku); TR3(_ma,_me,_mi,_mo,_mu); TR4(_sa,_se,_si,_so,_su)
static void eo8_perm( v512u a[25], const v512u rc_eo[24] ){
  DV;
  _ba=a[0];_be=a[1];_bi=a[2];_bo=a[3];_bu=a[4]; _ga=a[5];_ge=a[6];_gi=a[7];_go=a[8];_gu=a[9];
  _ka=a[10];_ke=a[11];_ki=a[12];_ko=a[13];_ku=a[14]; _ma=a[15];_me=a[16];_mi=a[17];_mo=a[18];_mu=a[19];
  _sa=a[20];_se=a[21];_si=a[22];_so=a[23];_su=a[24];
  R4(0); R4(4); R4(8); R4(12); R4(16); R4(20);
  a[0]=_ba;a[1]=_be;a[2]=_bi;a[3]=_bo;a[4]=_bu; a[5]=_ga;a[6]=_ge;a[7]=_gi;a[8]=_go;a[9]=_gu;
  a[10]=_ka;a[11]=_ke;a[12]=_ki;a[13]=_ko;a[14]=_ku; a[15]=_ma;a[16]=_me;a[17]=_mi;a[18]=_mo;a[19]=_mu;
  a[20]=_sa;a[21]=_se;a[22]=_si;a[23]=_so;a[24]=_su;
}

/* ===== EO interleave helpers (pext/pdep, correctness/setup only) ======= */
static inline uint32_t even_bits(uint64_t w){ return (uint32_t)_pext_u64(w,0x5555555555555555ULL); }
static inline uint32_t odd_bits (uint64_t w){ return (uint32_t)_pext_u64(w,0xAAAAAAAAAAAAAAAAULL); }
static inline uint64_t reinterleave(uint32_t e,uint32_t o){
  return _pdep_u64(e,0x5555555555555555ULL)|_pdep_u64(o,0xAAAAAAAAAAAAAAAAULL); }

/* native SoA (ulong[200], [z*8+s]) -> EO zmm[25] */
static void to_eo( v512u a[25], const uint64_t soa[200] ){
  for(int z=0;z<25;z++){ uint32_t t[16];
    for(int s=0;s<8;s++){ uint64_t w=soa[z*8+s]; t[s]=even_bits(w); t[8+s]=odd_bits(w); }
    a[z]=_mm512_loadu_si512(t); }
}
static void from_eo( uint64_t soa[200], const v512u a[25] ){
  for(int z=0;z<25;z++){ uint32_t t[16]; _mm512_storeu_si512(t,a[z]);
    for(int s=0;s<8;s++) soa[z*8+s]=reinterleave(t[s],t[8+s]); }
}

static inline double now_ns(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
  return (double)t.tv_sec*1e9+(double)t.tv_nsec; }

int main(void){
  /* build EO round constants (broadcast across 8 states) */
  v512u rc_eo[24];
  for(int r=0;r<24;r++){ uint32_t t[16]; uint32_t e=even_bits(RC[r]),o=odd_bits(RC[r]);
    for(int s=0;s<8;s++){ t[s]=e; t[8+s]=o; } rc_eo[r]=_mm512_loadu_si512(t); }

  /* ---- correctness: random states, EO-8 vs scalar reference ---- */
  uint64_t soa[200]; uint64_t ref[8][25];
  unsigned long seed=0x1234567;
  for(int z=0;z<25;z++) for(int s=0;s<8;s++){ seed=seed*6364136223846793005UL+1; soa[z*8+s]=seed^(seed>>29); }
  for(int s=0;s<8;s++) for(int z=0;z<25;z++) ref[s][z]=soa[z*8+s];
  v512u a[25] __attribute__((aligned(64))); to_eo(a,soa); eo8_perm(a,rc_eo);
  uint64_t out[200]; from_eo(out,a);
  for(int s=0;s<8;s++) keccak_ref(ref[s]);
  int ok=1; for(int s=0;s<8 && ok;s++) for(int z=0;z<25;z++) if(out[z*8+s]!=ref[s][z]){ ok=0;
    printf("MISMATCH state %d lane %d: got %016lx want %016lx\n",s,z,out[z*8+s],ref[s][z]); break; }
  printf("EO-8 correctness vs scalar Keccak-f[1600]: %s\n", ok?"PASS":"FAIL");
  if(!ok) return 1;

  /* ---- bench EO-8 ---- */
  unsigned long iter=2000000UL;
  double best=1e30;
  for(int t=0;t<3;t++){ double t0=now_ns();
    for(unsigned long k=0;k<iter;k++) eo8_perm(a,rc_eo);
    double dt=(now_ns()-t0)/(double)iter; if(dt<best)best=dt; }
  printf("EO-8   (24r): %7.2f ns/call  %6.2f ns/state\n", best, best/8.0);

  /* ---- bench native-8 (linked, validated) ---- */
  double bestn=1e30;
  for(int t=0;t<3;t++){ double t0=now_ns();
    for(unsigned long k=0;k<iter;k++) fd_keccak256_avx512_keccak8_f1600_raw(soa,RC);
    double dt=(now_ns()-t0)/(double)iter; if(dt<bestn)bestn=dt; }
  printf("native-8 (24r): %7.2f ns/call  %6.2f ns/state\n", bestn, bestn/8.0);
  printf("ratio EO/native = %.3f\n", best/bestn);
  return 0;
}

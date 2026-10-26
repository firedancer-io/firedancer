#ifndef HEADER_fd_src_ballet_bls_fd_bls_h
#define HEADER_fd_src_ballet_bls_fd_bls_h

#include "../../util/fd_util.h"
#include "../../third_party/blst/bindings/blst.h"

#define FD_BLS_SEC_SZ            (32UL)
#define FD_BLS_PUB_SZ            (96UL)
#define FD_BLS_PUB_COMPRESSED_SZ (48UL)
#define FD_BLS_SIG_SZ            (192UL)
#define FD_BLS_SIG_COMPRESSED_SZ (96UL)
#define FD_BLS_SET_MAX           (2000UL) /* TODO make set_dynamic so this isn't dependent on the VAT cap */
#define FD_BLS_DST               "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
#define FD_BLS_DST_SZ            (sizeof(FD_BLS_DST)-1UL)

#if FD_HAS_AVX512

#include "../../util/simd/fd_avx512.h"

#define FD_BLS_ALIGNED __attribute__((aligned(64)))

typedef struct FD_BLS_ALIGNED {
   wwv_t m1;
   wwv_t m2;
} fd_bls_fp_t;

typedef struct { fd_bls_fp_t c[2]; } fd_bls_fp2_t;

typedef blst_scalar fd_bls_sec_t;
/* Complete homogeneous projective points. */
typedef struct FD_BLS_ALIGNED { fd_bls_fp_t  x, y, z; } fd_bls_pub_t;
typedef struct FD_BLS_ALIGNED { fd_bls_fp2_t x, y, z; } fd_bls_sig_t;
typedef struct FD_BLS_ALIGNED { fd_bls_fp2_t x, y;    } fd_bls_hash_t;


#else

typedef blst_scalar    fd_bls_sec_t;
typedef blst_p1        fd_bls_pub_t;
typedef blst_p2        fd_bls_sig_t;
typedef blst_p2_affine fd_bls_hash_t;

#endif

#define SET_NAME fd_bls_set
#define SET_MAX  FD_BLS_SET_MAX
#include "../../util/tmpl/fd_set.c" /* TODO make set_dynamic so this isn't dependent on the VAT cap */

struct fd_bls_agg {
  fd_bls_pub_t pub;
  fd_bls_sig_t sig;
  fd_bls_set_t set[ fd_bls_set_word_cnt ]; /* bit position is the signer's epoch rank */
};
typedef struct fd_bls_agg fd_bls_agg_t;

FD_PROTOTYPES_BEGIN

/* Contracts.  Each function below carries a contract proved in Lean
   over the compiled AVX-512 code (proofs repo, Firedancer/Bls12381/,
   lifted with -fno-inline; every theorem is a statement about the
   lifted function's call in the MLIR semantics).  A theorem name X
   means MLIR.Firedancer.Bls12381.X; MLIR.X is written out.

   Memory vocabulary (MLIR/Semantics/Effectful/Memory/Fits.lean,
   Firedancer/Bls12381/Api/Rep.lean):
     readable n bytes   - Fits: a live allocation holding all n bytes,
                          every bit initialized;
     writable n bytes   - Room: a live, writable allocation with room for
                          n bytes (contents may be uninitialized);
     readable object    - PubFit / SigFit / HashFit: each fd_bls_fp_t of
                          the object readable (and the object in range);
     writable object    - PubRoom / SigRoom / HashRoom, likewise;
     disjoint           - the byte ranges do not overlap (Range.Disjoint);
     separate           - in different allocations (Pointer ids differ).
   Every call theorem also assumes the object does not wrap the end of
   the address space (offset + size <= 2^64: true of any C object) and
   a well-formed machine state.  The theorems also state the model's
   allocation counter after the call (exactly, or as some K); not
   shown here.

   CONSTANT TABLES: every call theorem assumes the module's constant
   tables are present.  Memory holds every global the call can reach
   (its own and its callees', transitively), each with its initializer
   image: premise s.mem.Globals (f).globals, MemoryState.Globals in
   MLIR/Semantics/GlobalInitializer.lean.  This premise is satisfiable
   for all 30 functions.  bls-build/audit/globals_audit.py checks, by
   evaluation, that in each list any two entries with the same symbol
   carry the same image (Global.Consistent).  A well-formed state
   holding any such list exists (ne_globals_sat,
   bls-build/wip/N3/Witness.lean).  An unsatisfiable Globals premise
   would make a theorem vacuous, and e2e_audit does not detect that.
   "Nothing else changes" means the
   theorem gives the final memory exactly as the stated writes on top
   of the initial memory.

   ALIGNMENT: fd_bls_fp_t (hence every fd_bls_pub/sig/hash/agg_t) is
   FD_BLS_ALIGNED (64) and the code uses aligned AVX-512 accesses.  The
   Lean model has no addresses (access alignment is ignored by the
   translation, MLIR/Syntax/Translate.lean), so 64-byte alignment of
   every such pointer is an ASSUMED precondition (the C type's), not a
   proved one.  uchar buffers carry no alignment requirement in the
   theorems.

   Representation predicates (Api/Rep.lean, Api/RepI.lean,
   Api/HashDeps.lean):
     FpVal v x    - the 16 RNS lanes of the fd_bls_fp_t v encode x in
                    Fp = Z/p (redundancy <= 40p, every lane < 2x its
                    modulus; Field/Conformance.lean RnsFp.Encodes);
     Fp2Val       - componentwise over Fp2 = Fp[u]/(u^2+1);
     Below2 v     - every lane of v < 2x its RNS modulus (true of every
                    FpVal; the precondition of fd_bls_fp_equal);
     FpEnc / Fp2Enc / PubEnc / SigEnc - every coordinate is an FpVal /
                    Fp2Val of some field element;
     PubVal o P   - o = (X,Y,Z) holds FpVals of (x,y,z), a homogeneous
                    projective representative of P on E: y^2 = x^3 + 4
                    (finite P = (a,b): z != 0, x = a z, y = b z;
                    infinity: x = 0, y != 0, z = 0; G1/G1.lean G1.Rep);
     SigVal o Q   - likewise over Fp2 on the twist E': y^2 = x^3 +
                    4(1+u) (G2Sub.HomRep: infinity is z = 0, y != 0);
     HashVal o Q  - affine: finite Q = (x,y) with Fp2Val coordinates, or
                    Q = infinity with all four fd_bls_fp_t all-zero;
     PubValI / SigValI / HashValI - PubVal / SigVal / HashVal, or the
                    point is infinity and z (hash: x and y) encode 0.
                    The C's all-zero identity object satisfies these
                    (PubValI.zero, SigValI.zero) but is no PubVal/SigVal.
   G1 = r-torsion of E(Fp), G2 = r-torsion of E'(Fp2) (inG1/inG2,
   Math/Curve.lean); g1 the standard generator (Math/BLS.lean).

   blst externs are not verified; each is a named contract Ext.*
   (Api/Blst.lean, justified in TRUSTED.md) that the theorems take as
   hypotheses.  "End to end" means every internal Firedancer callee is
   discharged by its own proved theorem: standard axioms only, no
   sorry, no callee contract (bls-build/audit/E2E.txt,
   bls-build/audit/e2e_audit.py). */

/* Secret keys */
/* fd_bls_sec_to_pub: sec is 32 readable bytes (the scalar SK, little
   endian, all 256 bits), pub is 384 writable bytes; the theorem has
   no aliasing premise.  With A the 96-byte blst affine point
   blst_p1_to_affine(blst_sk_to_pk_in_g1(SK)): if A is all zero
   (infinity), pub gets 384 zero bytes; otherwise pub gets x, y = the
   RNS forms of A's Montgomery limbs (ma_fm: fd_bls_fp_digits50 then
   fd_bls_fp_from_mont_core) and z = the RNS one
   (pub_from_affine.mem).  Nothing else changes.  Meaning (IETF BLS
   SkToPk, over the blst contracts Ext.SkToPkG1Val/Ext.P1ToAffineVal):
   afterwards pub is a writable object representing [SK]g1 (PubValI;
   when [SK]g1 is infinity, e.g. SK = 0 mod r, PubValI admits the
   all-zero identity).  The theorem has no premise on SK's value.
   Externs: Ext.P1AffineIsInf, Ext.P1ToAffine, Ext.SkToPkG1.
   Proofs: fd_bls.fd_bls_sec_to_pub.call_eq, .call_value
   (Api/FromAffine.lean).  Status: end to end. */
void fd_bls_sec_to_pub( fd_bls_sec_t const * sec, fd_bls_pub_t * pub );
/* fd_bls_sec_derive: requires ikm_sz>=32 (otherwise FD_TEST aborts;
   no theorem covers that path).  sec is 32 writable bytes, ikm is
   ikm_sz readable bytes, the two ranges disjoint.  Writes to sec the
   32 bytes keygen(IKM) that blst_keygen(sec,ikm,ikm_sz,NULL,0) stores
   (IKM the ikm_sz bytes at ikm).  Nothing else changes, nothing is
   allocated.  keygen's meaning, IETF BLS KeyGen(IKM) (HKDF-SHA256,
   draft-irtf-cfrg-bls-signature section 2.3), is the trusted extern
   contract Ext.Keygen (keygen is uninterpreted in the proof).
   Proof: fd_bls.fd_bls_sec_derive.call_eq (Api/SecDerive.lean).
   Status: end to end. */
void fd_bls_sec_derive( fd_bls_sec_t * sec, uchar const * ikm, ulong ikm_sz );
/* fd_bls_sec_sign: sec is 32 readable bytes (SK, little endian, all
   256 bits), sig is 768 writable bytes, and msg_sz==0 or msg is msg_sz
   readable bytes.  No aliasing condition.  Returns normally with sig
   holding an object representing [SK]H(msg) (SigValI; the all-zero
   identity if that is infinity).  H(msg) = RFC 9380 hash_to_curve(msg)
   for suite BLS12381G2_XMD:SHA-256_SSWU_RO_ with DST FD_BLS_DST
   (HashToG2.hashToG2 xmd msg dstPopBytes).  This is IETF BLS CoreSign,
   proof-of-possession scheme.  The statement pins only sig's value: it
   does NOT state that the rest of memory is unchanged.  Externs:
   Ext.Xmd/XmdVal (blst_expand_message_xmd; SHA-256 uninterpreted),
   Ext.FpFromU64/Val, Ext.P2AffineIsInf, Ext.P2FromAffine/Val,
   Ext.SignPkInG1/Val, Ext.P2ToAffine/Val.  Proof:
   fd_bls.fd_bls_sec_sign.call_value (Api/HashMsg.lean; the hash
   step as in fd_bls_hash_msg).  Status: end to end. */
void fd_bls_sec_sign( fd_bls_sec_t const * sec, uchar const * msg, ulong msg_sz, fd_bls_sig_t * sig );

/* Public Keys (G1).  fd_bls_pub_de accepts compressed or uncompressed
   encodings and rejects infinity and points outside G1. */
/* fd_bls_pub_de: pub is 384 writable bytes, buf is buf_sz readable
   bytes, pub and buf separate.  Let r be pubDe48(buf[0,48)) if
   buf_sz==48, pubDe96(buf[0,96)) if buf_sz==96, else "reject".  These
   are the ZCash encoding (draft-irtf-cfrg-pairing-friendly-curves
   App. C) with blst's acceptance rules, then IETF KeyValidate
   (Math/Serialize.lean):
     48: compressed (C flag set, I flag clear); x canonical after
         masking the 3 flag bits; x^3+4 a square; y the root with sign
         S (y > (p-1)/2); blst's (0,+-2) rejection;
     96: all three flag bits clear, x and y canonical, on the curve,
         (0,+-2) rejected;
   then P != infinity and P in G1.  If r accepts P: returns 0 and pub
   is overwritten with an object representing P (PubVal).  Otherwise:
   returns -1 and memory is unchanged.  Nothing else changes.
   Proof: fd_bls.fd_bls_pub_de.call_value (Api/PubDeVal.lean; PubDeOut
   in Api/PubDe.lean).  Status: end to end. */
int  fd_bls_pub_de          ( fd_bls_pub_t * pub, uchar const * buf, ulong buf_sz );
/* fd_bls_pub_de_unchecked accepts only an uncompressed encoding and checks
   that it is a curve point, but skips the infinity and G1 subgroup checks.
   It is only for keys that have already passed those checks. */
/* fd_bls_pub_de_unchecked: pub is 384 writable bytes, buf is 96
   readable bytes, pub and buf separate.  Decodes exactly blst's
   blst_p1_deserialize acceptance set (blstP1Deserialize,
   Math/Serialize.lean):
     - uncompressed (flags clear), x and y canonical, on the curve;
     - a compressed encoding in the first 48 bytes (C flag set; the
       compressed infinity included, the last 48 bytes ignored);
     - the uncompressed infinity encoding;
   with the points (0,+-2) rejected.  There is NO subgroup check and
   NO infinity rejection.  If accepted, decoding P: returns 0 and pub
   is overwritten with an object o with PubVal o P; or, only when P is
   infinity, pub := 384 zero bytes (the all-zero identity).  Otherwise:
   returns -1 and memory is unchanged.  Nothing else changes.  Only for
   keys that have already passed the infinity and G1 checks.
   Proof: fd_bls.fd_bls_pub_de_unchecked.call_value (Api/PubDeVal.lean).
   Status: end to end. */
int  fd_bls_pub_de_unchecked( fd_bls_pub_t * pub, uchar const buf[ static FD_BLS_PUB_SZ ] );
/* fd_bls_pub_compress: pub is a readable fd_bls_pub_t representing P
   (PubValI: the all-zero identity allowed), buf is 48 writable bytes.
   No aliasing condition.  Writes to buf the 48 bytes fb_g1cBits P,
   which are blst_p1_compress (ZCash format; byte k = g1CompressBytes
   P k, fb_g1cBits_byte):
     infinity: c0 00 .. 00;
     P = (x,y): x canonical, big endian, with
                byte 0 |= 0x80 | (y > (p-1)/2 ? 0x20 : 0).
   Nothing else changes.  Proofs:
   fd_bls.fd_bls_pub_compress.call_value_e2e (Api/InvE2E.lean),
   fb_g1cBits_byte (Api/Serializers.lean).  Status: end to end. */
void fd_bls_pub_compress( fd_bls_pub_t const * pub, uchar buf[ static FD_BLS_PUB_COMPRESSED_SZ ] );
/* fd_bls_pub_add: a, b are readable fd_bls_pub_t (all 384 bytes
   initialized) whose z lanes are Below2.  out is 384 writable bytes,
   either equal to a or disjoint from it, and likewise for b.  a and b
   may alias each other.  With A = *a, B = *b and "tests zero" meaning
   fd_bls_fp_equal(z,0) != 0:
     A.z tests zero -> out := B (no write if out==b);
     B.z tests zero -> out := A (no write if out==a);
     else           -> out := g1_add.pub(A,B), the complete projective
                       RCB addition of fd_bls_g1_add (after a copy of A
                       into out that it fully overwrites).
   (fd_bls_pub_add.mem.)  Nothing else changes.  Afterwards out holds
   fd_bls_pub_add.spec g1_add.pub A B (fd_bls_pub_add.mem_readPub).
   Meaning: if A represents P and B represents Q (PubVal), out
   represents P+Q (PubVal).  The PubValI form, all-zero identity
   allowed, is fd_bls_pub_add.valueI with ig_g1AddVal.  Proofs:
   fd_bls.fd_bls_pub_add.call_eq_g1 (G1/AddC.lean),
   fd_bls_pub_add.value_g1 (G1/AddVal.lean), mem_readPub/valueI
   (Api/PubAdd.lean, Api/RepI.lean).  Status: end to end. */
void fd_bls_pub_add     ( fd_bls_pub_t * out, fd_bls_pub_t const * a, fd_bls_pub_t const * b );
/* fd_bls_pub_neg: out and a are fd_bls_pub_t, either equal (in place)
   or disjoint.  a is 384 readable bytes, out 384 writable bytes.
   Copies *a to *out, then replaces out->y by fd_bls_fp_neg(a->y);
   nothing else changes.  In place, only out->y is rewritten.  If *a
   represents the G1 point P, *out represents -P: PubVal, and also
   PubValI (all-zero identity allowed).  Partially overlapping out/a is
   not covered.  Proofs: fd_bls.fd_bls_pub_neg.call_eq (disjoint),
   .call_eq_self and .call_neg_self (in place), fd_bls_pub_neg.value
   (Api/Neg.lean), fd_bls_pub_neg.valueI (Api/RepI.lean).
   Status: end to end. */
void fd_bls_pub_neg     ( fd_bls_pub_t * out, fd_bls_pub_t const * a );
/* fd_bls_pub_is_inf: pub->z is a readable fd_bls_fp_t whose lanes
   are Below2.  Only z is read; this holds for every valid
   representation, PubValI.  Returns fd_bls_fp_equal(pub->z, 0), which
   is 0 or 1.  For pub representing P (PubVal, or PubValI with the
   all-zero identity) the result is 1 iff P is the point at infinity,
   else 0.  Nothing is written.  Proofs:
   fd_bls.fd_bls_pub_is_inf.call_eq (Api/FpTests.lean),
   fd_bls_pub_is_inf.value (Api/IsInf.lean),
   fd_bls_pub_is_inf.valueI (Api/RepI.lean).  Status: end to end. */
int  fd_bls_pub_is_inf  ( fd_bls_pub_t const * pub );
/* fd_bls_pub_eq: a, b are readable fd_bls_pub_t (may alias), each a
   valid field encoding (PubEnc: every coordinate an FpVal).  If either
   is infinity (z tests zero), returns is_inf(a)&is_inf(b).  Otherwise
   returns fp_equal(a.y*b.z, b.y*a.z) & fp_equal(a.x*b.z, b.x*a.z)
   (fd_bls_fp_mul / fd_bls_fp_equal; fd_bls_pub_eq.spec).  For a, b
   representing P, Q (PubVal): 1 iff P==Q, else 0.  Nothing is
   written.  Proofs: fd_bls.fd_bls_pub_eq.call_eq, fd_bls_pub_eq.value
   (Api/PubEq.lean).  Status: end to end. */
int  fd_bls_pub_eq      ( fd_bls_pub_t const * a, fd_bls_pub_t const * b );
/* Overwrites out with the sum of the set-selected public keys.  The
   cached variant may use full (the sum of pubs[0..pub_cnt)) to subtract
   the complement when set is dense.  full may be NULL. */
/* fd_bls_pub_sum: out is 384 writable bytes (a writable object).  set
   is 256 readable bytes, and every rank in it is < FD_BLS_SET_MAX.
   pubs is the whole FD_BLS_SET_MAX-entry array: 2000*384 readable
   bytes.  For every rank r < 2000, out == pubs+r or out is disjoint
   from pubs[r].  pubs[r].z lanes are Below2 for every rank r in set.
   Let L be pubs[r] for r in set, in increasing rank order
   (fd_bls_set.iterList_eq).  Writes out := g1Sum.res L, the result
   fd_bls_g1_sum_batch computes from L: the all-zero object if every
   entry tests infinite (or L is empty), else its mixed / complete
   addition chain.  Nothing else changes.  Meaning: if the selected
   pubs represent the points Ps in that order (PubVal), out represents
   the sum of Ps (PubValI: the all-zero identity for an empty or
   all-infinite set).  With every pubs[r], r < 2000, representing
   P(r), out represents sum_{r in set} P(r) (value_g1_sum).  A variant
   needing the readability/disjointness/Below2 premises only for the
   set's ranks: fd_bls.fd_bls_pub_sum.call_eq_closed_sel /
   .call_value_sel (Api/PubSumSel.lean).  Proofs:
   fd_bls.fd_bls_pub_sum.call_eq_g1, fd_bls_pub_sum.value_g1,
   fd_bls_pub_sum.value_g1_sum (G1/PubSumG1.lean).  Status: end to
   end. */
void fd_bls_pub_sum       ( fd_bls_pub_t * out, fd_bls_pub_t const * pubs,                fd_bls_set_t const * set );
/* fd_bls_pub_sum_cached: as fd_bls_pub_sum (out writable, set
   readable with ranks < 2000, the whole 2000-entry pubs array
   readable, out == pubs+r or disjoint from pubs[r] for every r <
   2000), plus:
     - pub_cnt <= FD_BLS_SET_MAX;
     - pubs[r].z lanes Below2 for EVERY r < 2000;
     - full == NULL, or full is a readable fd_bls_pub_t, disjoint from
       out, with Below2 z lanes;
     - the z lanes of g1Sum.res(pubs[r] for r < pub_cnt not in set)
       are Below2 (a premise on that intermediate sum).
   Dense path iff full != NULL and pub_cnt < 2*|set|: out := the
   missing ranks' batch sum, out->y negated, then
   fd_bls_pub_add(out, full, out).  Otherwise exactly fd_bls_pub_sum's
   write (psc.mem).  Nothing else changes.  Meaning: let P(r) =
   Ps.getD r 0 for a list of points Ps.  Suppose every pubs[r],
   r < 2000, represents P(r) (PubVal), the set's ranks are < 2000,
   pub_cnt <= 2000, and, if full != NULL: set is a subset of
   [0,pub_cnt), *full represents sum_{r<pub_cnt} P(r) (PubVal), and
   full is readable and disjoint from out.  Then out represents
   sum_{r in set} P(r) (PubValI).  Proofs:
   fd_bls.fd_bls_pub_sum_cached.call_eq_g1g1,
   fd_bls_pub_sum_cached.value_g1g1 (G1/PubSumG1.lean; psc.mem in
   Api/PubSumCached.lean).  Status: end to end. */
void fd_bls_pub_sum_cached( fd_bls_pub_t * out, fd_bls_pub_t const * pubs, ulong pub_cnt, fd_bls_set_t const * set, fd_bls_pub_t const * full );

/* Signatures (G2).  fd_bls_sig_de and _de_compressed subgroup-check their
   input.  _de_unchecked only checks that an uncompressed encoding is a curve
   point.*/
/* fd_bls_sig_ser: sig is a readable fd_bls_sig_t representing Q
   (SigValI: the all-zero identity allowed), buf is 192 writable bytes.
   No aliasing condition.  Writes to buf the 192 bytes fb_g2sBits Q,
   which are blst_p2_serialize (byte k = g2SerializeBytes Q k):
     infinity: 40 00 .. 00;
     Q = (x,y): x.c1 || x.c0 || y.c1 || y.c0, each canonical, 48-byte
                big endian.
   Nothing else changes.  Proofs: fd_bls.fd_bls_sig_ser.call_value_e2e
   (Api/InvE2E.lean), fb_g2sBits_byte (Api/Serializers.lean).
   Status: end to end. */
void fd_bls_sig_ser          ( fd_bls_sig_t const * sig, uchar buf[ static FD_BLS_SIG_SZ ] );
/* fd_bls_sig_compress: sig is a readable fd_bls_sig_t representing Q
   (SigValI), buf is 96 writable bytes.  No aliasing condition.  Writes
   to buf the 96 bytes fb_g2cBits Q, which are blst_p2_compress (byte
   k = g2CompressBytes Q k):
     infinity: c0 00 .. 00;
     Q = (x,y): x.c1 || x.c0 big endian, with
                byte 0 |= 0x80 | (big(y) ? 0x20 : 0),
                big(y) = y.c1 != 0 ? y.c1 > (p-1)/2 : y.c0 > (p-1)/2
                (blst sgn0_pty_mont_384x).
   Nothing else changes.  Proofs:
   fd_bls.fd_bls_sig_compress.call_value_e2e (Api/InvE2E.lean),
   fb_g2cBits_byte (Api/Serializers.lean).  Status: end to end. */
void fd_bls_sig_compress     ( fd_bls_sig_t const * sig, uchar buf[ static FD_BLS_SIG_COMPRESSED_SZ ] );
/* fd_bls_sig_de: sig is 768 writable bytes, buf is 192 readable
   bytes, sig and buf separate.  Let r = sigCheck(g2Deserialize(buf)),
   Math/Serialize.lean.  The decoding is blst_p2_deserialize:
     - uncompressed (flags clear), coordinates canonical, on E';
     - a compressed encoding in the first 96 bytes (C flag set; the
       compressed infinity included, the last 96 bytes ignored);
     - the uncompressed infinity encoding.
   Then the G2 subgroup check (infinity is in G2).  If r accepts Q:
   returns 0.  For finite Q, sig := (x, y, 1), where x, y are Fp2Val
   encodings of Q's affine coordinates and z is the RNS one.  For
   Q = infinity, sig := 768 zero bytes.  Otherwise: returns -1 and
   memory is unchanged.  Nothing else changes.  Proof:
   fd_bls.fd_bls_sig_de.call_value (Api/SigDeAll.lean; SigDeOut in
   Api/SigDecode.lean, Api/SigDe.lean).  Status: end to end. */
int  fd_bls_sig_de           ( fd_bls_sig_t * sig, uchar const buf[ static FD_BLS_SIG_SZ ] );
/* fd_bls_sig_de_compressed: sig is 768 writable bytes, buf is 96
   readable bytes, sig and buf separate.  Let r =
   sigCheck(g2Uncompress(buf)).  The decoding is blst_p2_uncompress
   (Math/Serialize.lean):
     - C flag set;
     - infinity: I flag set and every other bit zero;
     - otherwise x.c1 (3 flag bits masked) and x.c0 canonical,
       x^3 + 4(1+u) a square, y the root with sign S (Fp2 sign as in
       fd_bls_sig_compress).
   Then the G2 subgroup check.  If r accepts Q: returns 0, and sig :=
   (x, y, 1) with Fp2Val coordinates for finite Q, or 768 zero bytes
   for infinity.  Otherwise: returns -1 and memory is unchanged.
   Nothing else changes.  Proof:
   fd_bls.fd_bls_sig_de_compressed.call_value
   (Api/SigDeCompressed.lean).  Status: end to end. */
int  fd_bls_sig_de_compressed( fd_bls_sig_t * sig, uchar const buf[ static FD_BLS_SIG_COMPRESSED_SZ ] );
/* fd_bls_sig_de_unchecked: as fd_bls_sig_de with r =
   g2Deserialize(buf): the same blst_p2_deserialize acceptance set
   (uncompressed on-curve, compressed in the first 96 bytes, or the
   uncompressed infinity) with NO subgroup check.  sig is 768 writable
   bytes, buf 192 readable bytes, sig and buf separate.  If accepted:
   returns 0 and sig := (x, y, 1) with Fp2Val coordinates, or 768 zero
   bytes for infinity.  Otherwise: returns -1 and memory is unchanged.
   Nothing else changes.  Proof:
   fd_bls.fd_bls_sig_de_unchecked.call_value (Api/SigDeAll.lean).
   Status: end to end. */
int  fd_bls_sig_de_unchecked ( fd_bls_sig_t * sig, uchar const buf[ static FD_BLS_SIG_SZ ] );
/* fd_bls_sig_add: a, b are readable fd_bls_sig_t (all 768 bytes
   initialized) whose z.c0, z.c1 lanes are Below2.  out is 768 writable
   bytes, either equal to a or disjoint from it, and likewise for b.  a
   and b may alias each other.  With A = *a, B = *b and "is infinity"
   meaning both z components test zero:
     A is infinity -> out := B (no write if out==b);
     B is infinity -> out := A (no write if out==a);
     else          -> out := MLIR.ma_addProj(A,B), fd_bls_g2_add_projective's
                      complete projective RCB addition on E'
                      (hg_addProj.spec); it reads both inputs before
                      writing.
   (fd_bls_sig_add.mem.)  Nothing else changes.  Afterwards out holds
   fd_bls_sig_add.spec MLIR.ma_addProj A B
   (MLIR.fd_bls_sig_add.mem_readSig, Api/SigAddManySpec.lean).
   Meaning: if A represents P and B represents Q (SigVal), out
   represents P+Q (SigVal).  Proofs:
   MLIR.fd_bls.fd_bls_sig_add.call_eq_g2, MLIR.fd_bls_sig_add.value_g2
   (Api/SigG2.lean; mem/spec in Api/PubAdd.lean;
   fd_bls_g2.fd_bls_g2_add_projective.call_eq in G2/AddProj.lean).
   Status: end to end. */
void fd_bls_sig_add          ( fd_bls_sig_t * out, fd_bls_sig_t const * a, fd_bls_sig_t const * b );
/* fd_bls_sig_neg: out and a are fd_bls_sig_t, either equal (in place)
   or disjoint.  a is 768 readable bytes, out 768 writable bytes.
   Copies *a to *out (no copy in place), then replaces both Fp
   components of out->y by fd_bls_fp_neg of a->y's; x and z are
   unchanged and nothing else changes.  If *a represents the G2 point
   Q, the result represents -Q: SigVal, and also SigValI (all-zero
   identity allowed).  Partially overlapping out/a is not covered.
   Proofs: fd_bls.fd_bls_sig_neg.call_eq_self (in place),
   fd_bls.fd_bls_sig_neg.call_eq (disjoint, Verify/SigNeg.lean),
   fd_bls_sig_neg.value (Api/Neg.lean), fd_bls_sig_neg.valueI
   (Api/RepI.lean).  Status: end to end. */
void fd_bls_sig_neg          ( fd_bls_sig_t * out, fd_bls_sig_t const * a );
/* fd_bls_sig_validate: sig is a readable fd_bls_sig_t representing Q
   (SigValI: the all-zero identity allowed).  Returns 1 if Q is
   infinity; otherwise 1 iff Q is in G2 ([r]Q = infinity), else 0.  The
   path is sig_to_rns_affine then fd_bls_g2_validate_affine.  Nothing
   is written.  Proof: fd_bls.fd_bls_sig_validate.call_value
   (Api/SigValidate.lean).  Status: end to end. */
int  fd_bls_sig_validate     ( fd_bls_sig_t const * sig );
/* fd_bls_sig_is_inf: sig->z.c0 and sig->z.c1 are readable
   fd_bls_fp_t with Below2 lanes.  Only z is read; this holds for
   every valid representation, SigValI.  Returns
   fp_equal(z.c1,0) & fp_equal(z.c0,0), which is 0 or 1.  For sig
   representing Q (SigVal, or SigValI with the all-zero identity) the
   result is 1 iff Q is infinity, else 0.  Nothing is written.
   Proofs: fd_bls.fd_bls_sig_is_inf.call_eq (Api/FpTests.lean),
   fd_bls_sig_is_inf.value (Api/IsInf.lean),
   fd_bls_sig_is_inf.valueI (Api/RepI.lean).  Status: end to end. */
int  fd_bls_sig_is_inf       ( fd_bls_sig_t const * sig );
/* fd_bls_sig_eq: a, b are readable fd_bls_sig_t (may alias), each a
   valid field encoding (SigEnc: every coordinate an Fp2Val).  If
   either is infinity, returns is_inf(a)&is_inf(b).  Otherwise returns
   fp2_equal(a.y*b.z, b.y*a.z) & fp2_equal(a.x*b.z, b.x*a.z)
   (fd_bls_fp2_mul; fp2_equal is the & of both components'
   fd_bls_fp_equal; fd_bls_sig_eq.spec).  For a, b representing Q1, Q2
   (SigVal): 1 iff Q1==Q2, else 0.  Nothing is written.  Proofs:
   fd_bls.fd_bls_sig_eq.call_eq, fd_bls_sig_eq.value (Api/SigEq.lean).
   Status: end to end. */
int  fd_bls_sig_eq           ( fd_bls_sig_t const * a, fd_bls_sig_t const * b );

/* Hash-to-curve and verification */
/* fd_bls_hash_msg: hash is 512 writable bytes (a writable
   fd_bls_hash_t).  msg_sz==0, or msg is msg_sz readable bytes in an
   allocation separate from hash.  Returns normally having written only
   hash, with an object o representing H(msg) (HashValI: for finite
   H(msg) affine Fp2Val coordinates; for infinity the all-zero object
   or coordinates encoding 0).  H(msg) =
   HashToG2.hashToG2 xmd msg FD_BLS_DST is RFC 9380 hash_to_curve for
   suite BLS12381G2_XMD:SHA-256_SSWU_RO_ with the proof-of-possession
   DST:
     clear_cofactor(map_to_curve(u0) + map_to_curve(u1)),
     (u0,u1) = hash_to_field(msg, 2) over expand_message_xmd,
     map_to_curve = iso_map o simplified SWU (Hash/HashToG2.lean).
   H(msg) is in G2 (hashToG2_inG2).  Nothing else changes.  Externs:
   Ext.Xmd/XmdVal (blst_expand_message_xmd; SHA-256 uninterpreted).
   Proofs: fd_bls.fd_bls_hash_msg.call_value (Api/HashMsg.lean), over
   fd_bls_hash.fd_bls_hash_to_g2.call_eq and hash_to_g2.value
   (Hash/HashToG2Call.lean; map step fd_bls_hash.sswu_map2_rns.call_eq
   Hash/SswuMap.lean, fd_bls_hash.ec_dadd_eprime_rns.call_eq
   Hash/Dadd.lean, fd_bls_hash.isogeny_map_rns.call_eq
   Hash/Isogeny.lean).  Status: end to end. */
void fd_bls_hash_msg( uchar const * msg, ulong msg_sz, fd_bls_hash_t * hash );
/* fd_bls_hash_eq: a, b are readable fd_bls_hash_t with every Fp lane
   Below2 (true of every valid representation, HashValI).  Returns
   fd_bls_fp2_equal(a->y,b->y) & fd_bls_fp2_equal(a->x,b->x), each
   fp2_equal the & of its two components' fd_bls_fp_equal; the result
   is 0 or 1.  Suppose the four coordinates are Fp2Val encodings of
   xa, ya, xb, yb.  This covers every finite HashVal, and the all-zero
   infinity object, whose coordinates encode 0 (ma_fpVal_zero).  Then
   the result is 1 iff xa==xb and ya==yb, else 0.  Nothing is written;
   the state is unchanged.  Proofs: fd_bls.fd_bls_hash_eq.call_eq,
   fd_bls_hash_eq.value_finite (Api/HashEq.lean).  Status: end to
   end. */
int  fd_bls_hash_eq( fd_bls_hash_t const * a, fd_bls_hash_t const * b );
/* fd_bls_agg_verify_hashed: h, pub, sig are readable objects with
   valid field encodings (HashEnc, PubEnc, SigEnc).  Returns
   verifyHashPair.spec1(*h,*pub,*sig):
     0 if h's four Fp coordinates all test zero, pub.z tests zero,
       or both sig.z components test zero;
     else 1 iff fd_bls_fp12_is_one of the RNS pairing block
            fd_bls_pairing_rns([(pub affine, h), (-g1, sig affine)]),
     else 0.
   Nothing is written.  Meaning: suppose h represents H (HashVal) with
   H in G2, pub represents pk (PubVal), and sig represents sg (SigVal)
   with sg in G2.  Then the result (spec1, hence 0 or 1) is 1 iff
   H != infinity, pk != infinity, sg != infinity and
   e(pk,H) * e(-g1,sg) == 1, else 0.  Here e is verifySpec's
   Bilin.pairingSpec: the reduced ate pairing (Miller loop over z,
   final exponent (p^12-1)/r), 1 when either point is infinity or
   the G2 argument is not in G2.  This is IETF BLS CoreVerify on a
   hashed message.  sg in G2 and H in G2 are preconditions of the
   theorem; pk in G1 is not required.  Proofs:
   fd_bls.fd_bls_agg_verify_hashed.call_eq, .call_value
   (Verify/AggVerify.lean; spec1 in Verify/VerifyHelpers.lean; the
   pairing value pd_dep.pairing_rns.value = P's pd_pr.value,
   Verify/PairingVal.lean).  Status: end to end (E2E.txt lists
   .call_value). */
int  fd_bls_agg_verify_hashed( fd_bls_hash_t const * hash, fd_bls_pub_t const * pub, fd_bls_sig_t const * sig );
/* fd_bls_agg_verify: msg_sz==0 or msg is msg_sz readable bytes.  pub
   is a readable fd_bls_pub_t representing pk (PubVal).  sig is a
   readable fd_bls_sig_t representing sg (SigVal) with sg in G2 (a
   precondition, not checked).  Let H = H(msg) as in fd_bls_hash_msg.
   Returns r with r == 1 iff H != infinity, pk != infinity,
   sg != infinity and e(pk,H) * e(-g1,sg) == 1 (verifySpec
   Bilin.pairingSpec).  This is IETF BLS CoreVerify, proof-of-
   possession DST.  The statement does not pin r to 0 in the other
   case.  Nothing is written.  Externs: Ext.Xmd/XmdVal.  Proof:
   fd_bls.fd_bls_agg_verify.call_value (Verify/AggVerify.lean).
   Status: end to end. */
int  fd_bls_agg_verify( uchar const * msg, ulong msg_sz, fd_bls_pub_t const * pub, fd_bls_sig_t const * sig );
/* fd_bls_agg_verify_pair: msg_sz==0 or msg is msg_sz readable bytes.
   msg_fallback==NULL, msg_fallback_sz==0, or msg_fallback is
   msg_fallback_sz readable bytes.  pub is a readable fd_bls_pub_t
   representing pk.  pub_fallback==NULL or it is a readable
   fd_bls_pub_t, representing pkf when non-NULL.  sig is a readable
   fd_bls_sig_t representing sg with sg in G2 (PubVal/SigVal).  Let
   H = H(msg) and Hf = H(msg_fallback) as in fd_bls_hash_msg.  Returns
   r with r == 1 iff msg_fallback != NULL, pub_fallback != NULL, and
   verifyPairSpec holds:
     H, pk, Hf, pkf, sg all != infinity, and
     e(pk,H) * e(pkf,Hf) * e(-g1,sg) == 1   (Bilin.pairingSpec).
   In particular r != 1 for a NULL fallback.  The statement does not
   pin r to 0 when r != 1.  Nothing is written.  Externs:
   Ext.Xmd/XmdVal.  Proof: fd_bls.fd_bls_agg_verify_pair.call_value
   (Verify/AggVerifyPair.lean).  Status: end to end. */
int  fd_bls_agg_verify_pair( uchar const * msg, ulong msg_sz,
                             fd_bls_pub_t const * pub,
                             uchar const * msg_fallback, ulong msg_fallback_sz,
                             fd_bls_pub_t const * pub_fallback, fd_bls_sig_t const * sig );

/* Aggregate bookkeeping and bad-signer isolation */
/* fd_bls_agg_null: agg is 1408 writable bytes (a writable
   fd_bls_agg_t).  Zeroes agg->pub (384 bytes), agg->sig (768 bytes at
   offset 384) and agg->set (256 bytes at offset 1152), then returns
   agg.  Nothing else changes.  Afterwards agg->pub and agg->sig read
   as the all-zero objects and the set is empty
   (fd_bls.fd_bls_agg_null.zero).  The all-zero objects are the C's
   identity convention: PubValI/SigValI of infinity (PubValI.zero,
   SigValI.zero), not PubVal/SigVal.  Proofs:
   fd_bls.fd_bls_agg_null.call_eq, .zero (Api/Agg.lean).
   Status: end to end. */
fd_bls_agg_t * fd_bls_agg_null( fd_bls_agg_t * agg );
/* fd_bls_agg_construct: agg is 1408 writable bytes, separate from set,
   pub and sig.  set is 256 readable bytes, with every rank in it <
   FD_BLS_SET_MAX.  pub is the whole 2000-entry array (2000*384
   readable bytes), sig likewise (2000*768 readable bytes).  For every
   rank r < 2000: pub[r].z and sig[r].z.c0/z.c1 lanes are Below2.  Let
   rs be the set's ranks in increasing order.  Writes, then returns
   agg:
     agg->set := a copy of set;
     agg->pub := g1Sum.res(pub[r] for r in rs)   (fd_bls_g1_sum_batch);
     agg->sig := fd_bls_sig_add_many of the sig[r]: 768 zero bytes if
                 every one tests infinite (or rs is empty), else
                 sigAddMany.sum (two-lane mixed adds fd_bls_g2_add_affine
                 merged by fd_bls_g2_add_projective, or sequential
                 fd_bls_sig_add).
   (MLIR.fd_bls_agg_construct.mem.)  Nothing else changes.  Meaning:
   let P(r) = Ps.getD r 0 and Q(r) = Qs.getD r 0 for lists of points
   Ps, Qs.  Suppose every pub[r], r < 2000, represents P(r) (PubVal)
   and every sig[r] represents Q(r) (SigVal).  Then agg->pub
   represents sum_{r in set} P(r) (PubValI) and agg->sig represents
   sum_{r in set} Q(r) (SigValI; PubValI/SigValI admit the all-zero
   identities).  Proofs:
   MLIR.fd_bls.fd_bls_agg_construct.call_eq_g,
   MLIR.fd_bls_agg_construct.value_g (Api/SigG2.lean; mem in
   Api/AggConstruct.lean).  Status: end to end. */
fd_bls_agg_t * fd_bls_agg_construct( fd_bls_agg_t * agg,       fd_bls_pub_t const * pub,
                                     fd_bls_sig_t const * sig, fd_bls_set_t const * set );
/* fd_bls_agg_verify_subtract: msg_sz==0 or msg is msg_sz readable
   bytes.  agg is 1408 writable bytes: agg->pub (offset 0) and
   agg->sig (offset 384) readable, with valid field encodings of z
   (FpEnc, Fp2Enc), and agg->set (offset 1152) 256 readable bytes with
   every rank < FD_BLS_SET_MAX.  bad is 256 writable bytes.  pub is the
   whole 2000-entry array (2000*384 readable bytes), sig likewise
   (2000*768 readable bytes).  agg and bad are separate from each
   other and from pub and sig.  Meaning premises: let P(r) =
   Ps.getD r 0 and Q(r) = Qs.getD r 0 for lists of points Ps, Qs.
   Every pub[r], r < 2000, represents P(r) (PubVal); every sig[r]
   represents Q(r) (SigVal); every P(r) is in G1 and every Q(r) in G2.
   agg is consistent: agg->pub represents sum_{r in set} P(r) and
   agg->sig represents sum_{r in set} Q(r) (PubValI/SigValI).  H(msg)
   (as in fd_bls_hash_msg) != infinity.
   Result: returns r with memory m' (ma_subtract.Post), where L is
   the set's ranks in increasing order and the model is
   AggTree.subtract with V = E2E.blsV H(msg) on the aggregate
   (sum_L P, sum_L Q, L).  blsV H pk sg iff H, pk, sg are all
   != infinity and ePair(pk,H) * ePair(-g1,sg) == 1 (E2E.aggVerifySpec;
   ePair is the reduced ate pairing, 1 at infinity), i.e. CoreVerify.
     - if V(sum_L P, sum_L Q): r = 0, agg->pub/agg->sig represent the
       same sums, agg->set holds L, bad is empty;
     - else bad holds the ranks of AggTree.run, the recursive
       bisection of fd_bls_agg_bisect_run over L; agg->pub represents
       sum_L P - sum_bad P and agg->sig sum_L Q - sum_bad Q; agg->set
       holds L minus bad; r = -1 if that remaining key is infinity,
       else 0.
   ma_subtract.Post pins only r, the values agg->pub and agg->sig
   represent, and the elements of agg->set and bad; it does NOT state
   that the rest of memory is unchanged.  The statement holds for
   arbitrary fd_log_private_0/_2 and fd_log_wallclock (the logging
   externs behind FD_TEST).  Externs: Ext.Xmd/XmdVal.
   Model facts (Verify/AggTree.lean).  They apply to this model
   instance because its input sums are the members' sums by
   construction.
     Soundness: if the aggregate fails V, every rank in bad is in
       the set and fails V individually (AggTree.run_sound,
       run_subset, run_sublist).
     Exactness (ma_subtract.exact, over AggTree.subtract_exact):
       assume in addition that the set's keys are != infinity (P(k)
       != infinity for k in L), that the aggregate fails V, and
       E2E.NoCancelDefects: no contiguous sub-run of members has
       defects ePair(pk,H)*ePair(-g1,sg) multiplying to 1 unless all
       are 1.  NoCancelDefects holds e.g. when at most one member is
       invalid (E2E.noCancelDefects_of_le_one).  Then the model's bad
       list is exactly L filtered to the members failing CoreVerify,
       and the remaining set is exactly L filtered to the valid ones.
       H(msg) is in G2 (hashToG2_inG2).  Hence, through
       ma_subtract.Post, bad's elements are exactly the set's invalid
       members and agg->set's elements exactly its valid ones.  The
       companion fd_bls.fd_bls_agg_verify_subtract.call_exact
       (Verify/PdSubtractReprove.lean) states this at the call level.
       It adds that agg->pub/agg->sig represent the valid members'
       sums, and that when r == 0 the remaining aggregate verifies.
       Without NoCancelDefects, only soundness is proved.
   Proofs: fd_bls.fd_bls_agg_verify_subtract.call_value,
   ma_subtract.Post, ma_subtract.exact (Verify/AggSubtract.lean;
   ma_setRanks in Verify/BisectDeps.lean); callee
   fd_bls.fd_bls_agg_verify_bisect.call_eq (Verify/AggVerifyBisect.lean)
   over fd_bls.fd_bls_agg_bisect_run.call_value
   (Verify/BisectStepE.lean).  Status: end to end. */
int fd_bls_agg_verify_subtract( fd_bls_agg_t * agg,
                                uchar const * msg, ulong msg_sz,
                                fd_bls_pub_t const * pub, fd_bls_sig_t const * sig,
                                fd_bls_set_t * bad );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_bls_fd_bls_h */

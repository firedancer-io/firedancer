//! Efficient computation of 32 parity shreds for 32 data shreds.
//!
//! Based on the O(n log n) algorithm described in:
//!   zS. -J. Lin, T. Y. Al-Naffouri, Y. S. Han and W. -H. Chung, "Novel
//!   Polynomial Basis With Fast Fourier Transform and Its Application to
//!   Reed–Solomon Erasure Codes," in IEEE Transactions on Information Theory,
//!   vol. 62, no. 11, pp. 6284-6299, Nov. 2016, doi: 10.1109/TIT.2016.2608892.
//!
//! Given 32 data shreds, we want to produce 32 parity shreds such that any
//! 32 of the 64 total shreds can reconstruct the original data. The standard
//! approach is to treat the data as evaluations of a polynomial, then evaluate
//! that polynomial at additional points to get parity.
//!
//! Specifically, we want to find a unique polynomial P(x) of degree < 32 over
//! GF(2^8), such that P(0) = data[0], P(1) = data[1], ..., P(31) = data[31].
//! Then parity[i] = P(32 + i) for i in [0, 32).
//!
//! The naive way (Lagrange interpolation then evaluation) is O(n^2). This
//! file implements an O(n log n) algorithm.
//!
//! The classical FFT works over fields that have roots of unity (complex numbers,
//! certain prime fields). GF(2^8) has no roots of unity of useful order. Instead
//! it has an easy to access subspace structure. The integer {0, 1, 2, ..., 2^j - 1},
//! when interpreted as GF(2^8) elements, form a subspace under XOR (addition).
//!
//! ## Subspace Polynomials
//!
//! From that, we define subspace polynomials. `s_j(x)` is the polynomial
//! that vanishes on the subspace {0, 1, ..., 2^j - 1}:
//!     s_0(x) = x
//!     s_1(x) = x * (x + 1)
//!     s_2(x) = x * (x + 1) * (x + 2) * (x + 3)
//!
//! These satisfy a useful reccurange:
//!     s_j(x) = s_{j-1}(x) * s_{j-1}(x ^ 2{j - 1})
//!
//! This is because {0, ..., 2^j - 1} = {0, ..., 2^{j-1} - 1} union {2^{j-1},
//! ..., 2^j - 1}, and adding 2^{j-1} in GF(2) is the same as XOR.
//!
//! We normalize S_j(x) = s_j(x) / s_j(2^j), so that S_j(2^j) = 1.
//!
//! The polynomial basis is a way to represent the polynomial. Instead of
//! representing it as a_0 + a_1*x + a_2*x^2 + ..., we use the basis {X_0,
//! X_1, ..., X_{N-1}} where:
//!     X_i(x) = product of S_j(x) for each bit j set in i
//!
//! For example, X_0 = 1, X_1 = S_0(x) = x, X_5 = S_0(x) * S_2(x).
//!
//! ## Polynomial Basis
//!
//! A polynomial in this basis can be converted to/from evaluations using
//! a butterfly network, the same way classical FFT works between frequency
//! and time domains.
//!
//! The core operation is the butterfly. It pairs two values v[a] and v[b]
//! with a GF(2^8) constant c.
//!     For ifft butterfly: v[b] ^= v[a]; v[a] ^= c * v[b];
//!     For fft butterfly:  v[a] ^= c * b[b]; v[b] ^= v[a];
//!
//! These are inverses of each other, applying ifft then fft (or vice versa)
//! with the same constant is the identity.
//!
//! When c = 0, the multiplication vanishes and only the XOR remains (we
//! apply this property in the implementation of both, with comptime checks).
//!
//! ## Schedule
//!
//! For a transform of size N = 32, there are log2(N) = 5 rounds. Round j
//! uses stride 2^j, it pairs elements that are 2^j apart.
//!
//! Round 0 (stride 1): pairs (0, 1), (2, 3), (4, 5), ..., (30, 31)
//! Round 1 (stride 2): pairs (0, 2), (4, 6), (8, 10), ..., (28, 30)
//! ...
//! Round 3 (stride 8): pairs (0, 8), (16, 24)
//! Round 4 (stride 16): pairs (0, 16)
//!
//! The IFFT processes rounds bottom-up (0, 1, 2, 3, 4). The FFT processes
//! rounds top-down (4, 3, 2, 1, 0).
//!
//! After each round's butterflies, the two halves of the data become
//! independent subproblems that can be processed in any order, which is
//! very helpful as we can schedule the expensive memory loads in a strided
//! fashion to help mask their latency.
//!
//! Each butterfly at round j uses the constant S_j(omega ^ base), where:
//!   - omega is the position of the bufferfly group (a multiple of 2*stride)
//!   - base is the shift: 0 for the IFFT, 32 for the FFT
//!
//! For the IFFT with beta=0, the constant is S_j(omega). Since S_j(0) = 0
//! for all j (0 is in every subspace), many butterflies have c = 0 and skip
//! the multiplication entirely. The same isn't true for the FFT, as with
//! beta=32, the constant is S_j(omega ^ beta), which will never be zero.
//!
//! ## The Whole Thing
//!
//! The IFFT finds the unique polynomial (in the novel basis) that passes
//! through all 32 data points. The FFT evaluates that same polynomial at
//! 32 new points. Any 32 of the 64 total evaluations determine the degree-31
//! polynomial uniquely, making it possible to later recover the polynomial
//! through another FFT pass, and re-evaluate it at the points [0, 32), getting
//! those original data evaluations.

const std = @import("std");
const builtin = @import("builtin");
const L = if (builtin.cpu.has(.x86, .avx512f)) 64 else 32;
comptime {
    std.debug.assert(builtin.cpu.has(.x86, .gfni)); // Needs GFNI extension to work.
}

/// Assumes that shred_sz >= L.
export fn fd_reedsol_private_encode_32_32(
    shred_sz: usize,
    data: [*]const [*]const u8,
    parity: [*]const [*]u8,
) void {
    var pos: usize = 0;
    var v: [32]@Vector(L, u8) = undefined;
    while (pos < shred_sz) {
        // Load the next L bytes of each of the 32 data shreds.
        inline for (0..32) |i| v[i] = data[i][pos..][0..L].*;
        // Compute the iFFT to find the polynomial that interpolates
        // the data, expressed in coefficient basis.
        inline for (Butterfly.backwards) |b| Butterfly.ifft(&v, b.r0, b.r1, b.c);
        // Evaluates the polynomial at integers in [32, 64) to produce
        // 32 parity shreds.
        inline for (Butterfly.forwards) |b| Butterfly.fft(&v, b.r0, b.r1, b.c);
        // Store the next L bytes of each parity shred.
        inline for (0..32) |i| parity[i][pos..][0..L].* = v[i];
        // Advance shred position. If the shred size is not a multiple of
        // L, clamp pos so the last iteration covers the final L bytes.
        pos += L;
        if (pos >= shred_sz) break;
        pos = @min(pos, shred_sz - L);
    }
}

/// GF(2^8) multiplication reduced by x^8 + x^4 + x^3 + x^2 + x + 1
fn mul(x: u8, y: u8) u8 {
    var a: u8 = x;
    var b: u8 = y;
    var p: u8 = 0;
    for (0..8) |_| {
        p ^= (b & 1) *% a;
        a = (a << 1) ^ ((a >> 7) *% 0x1D);
        b >>= 1;
    }
    return p;
}

fn pow(base: u8, exp: u8) u8 {
    var result: u8 = 1;
    var b: u8 = base;
    var e: u8 = exp;
    while (e != 0) {
        if ((e & 1) != 0) result = mul(result, b);
        b = mul(b, b);
        e >>= 1;
    }
    return result;
}

/// GF(2^8) division, using Fermat's little theorem
///
/// a/b = a * b^{-1} = a * b^{254}
fn div(a: u8, b: u8) u8 {
    return mul(a, pow(b, 254));
}

/// Compute the normalized subspace polynomial table.
const bar = bar: {
    @setEvalBranchQuota(1_000_000);
    var ptab: [8][256]u8 = undefined;
    var vals: [8][256]u8 = undefined;
    for (0..8) |j| {
        for (0..256) |x| {
            if (j == 0) {
                vals[0][x] = x;
            } else {
                vals[j][x] = mul(vals[j - 1][x], vals[j - 1][x ^ (1 << (j - 1))]);
            }
        }
        for (0..256) |x| {
            ptab[j][x] = div(vals[j][x], vals[j][1 << j]);
        }
    }
    break :bar ptab;
};

const Butterfly = struct {
    r0: comptime_int,
    r1: comptime_int,
    c: comptime_int,

    const N = 32;
    const V = @Vector(L, u8);

    /// Schedule for performing FFTs at shift=32 (second param), converting
    //. the coefficient basis into N evaluations at points [32, 64).
    const forwards = genForwards(N, 32, 0, 0);
    /// Schedule for performing inverse-FFTs to convert N evaluations at
    /// points [0, 32) into a coefficient basis.
    const backwards = genBackwards(N, 0, 0, 0);

    /// The IFFT and FFT decompose into log2(N) rounds of butterfly operations.
    /// At round j (stride 2^j), each buttefly pairs elements at positions
    /// (base, base + 2^j) and multiplies by S_j(omega ^ beta).
    ///
    /// ifft (evaluation -> coefficient):
    ///   v[r1] ^= v[r0]
    ///   v[r0] ^= S_j(omega ^ beta) * v[r1]
    ///
    /// fft (coefficient -> evaluation):
    ///   v[r0] ^= S_j(omega ^ beta) * v[r1]
    ///   v[r1] ^= v[r0]
    ///
    /// where omega is the base position within the round (aligned to 2*stride)
    /// and beta is the evaluation shift.
    fn gen(n: u8, beta: u8, i_round: u8, r_offset: u8) []const Butterfly {
        const half_len = n / (1 << (i_round + 1));
        var butterflies: [half_len]Butterfly = undefined;
        for (&butterflies, 0..) |*b, j| {
            const omega = j * (1 << (i_round + 1));
            const c = bar[i_round][omega ^ beta];
            b.* = .{ .r0 = r_offset + omega, .r1 = r_offset + (1 << i_round) + omega, .c = c };
        }
        return &butterflies;
    }

    fn genForwards(n: u8, beta: u8, i_round: u8, r_offset: u8) []const Butterfly {
        if (1 << i_round == n) return &.{};
        const result: []const Butterfly =
            genForwards(n, beta, i_round + 1, r_offset) ++
            genForwards(n, beta, i_round + 1, r_offset + (1 << i_round));
        return result ++ Butterfly.gen(n, beta, i_round, r_offset);
    }
    fn genBackwards(n: u8, beta: u8, i_round: u8, r_offset: u8) []const Butterfly {
        if (1 << i_round == n) return &.{};
        var result: []const Butterfly = Butterfly.gen(n, beta, i_round, r_offset);
        result = result ++ genBackwards(n, beta, i_round + 1, r_offset);
        result = result ++ genBackwards(n, beta, i_round + 1, r_offset + (1 << i_round));
        return result;
    }

    inline fn fft(v: *[32]V, a: comptime_int, b: comptime_int, c: comptime_int) void {
        if (c != 0) v[a] ^= gfmul(v[b], c);
        v[b] ^= v[a];
    }
    inline fn ifft(v: *[32]V, a: comptime_int, b: comptime_int, c: comptime_int) void {
        v[b] ^= v[a];
        if (c != 0) v[a] ^= gfmul(v[b], c);
    }

    const table = t: {
        @setEvalBranchQuota(100_000);
        var output: [256]@Vector(L / 8, u64) = undefined;
        for (0..256) |c| {
            var t: [8]u8 = undefined;
            for (0..8) |j| t[j] = mul(c, 1 << j);
            var w: u64 = 0;
            for (0..64) |i| {
                const bit = 1 << 7 - i / 8;
                if (t[i % 8] & bit != 0) w |= 1 << i;
            }
            output[c] = @splat(w);
        }
        break :t output;
    };
    inline fn gfmul(x: V, c: u8) V {
        return asm ("vgf2p8affineqb $0x00, %[c], %[x], %[r]"
            : [r] "=v" (-> V),
            : [c] "rm" (table[c]),
              [x] "v" (x),
        );
    }
};

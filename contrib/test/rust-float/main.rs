// Rust side of the C/Rust floating point corpus.
//
// Prints one line per result plus an FNV-1a hash of the stream.
// src/flamenco/types/test_rust_float.c generates the same corpus and must
// produce the same lines; the Makefile here diffs the two.
//
//   rustc -O main.rs -o rust-float && ./rust-float

/// splitmix64, so both languages walk the same pseudo random corpus.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
}

/// Bit patterns worth hitting exactly: zeros, subnormals, the normal
/// boundaries, the integer-exactness boundary at 2^53, the u64 cast
/// boundary at 2^64, infinities and both nan kinds.
const SPECIALS: &[u64] = &[
    0x0000000000000000, // +0
    0x8000000000000000, // -0
    0x0000000000000001, // + smallest subnormal
    0x8000000000000001, // - smallest subnormal
    0x000fffffffffffff, // + largest subnormal
    0x800fffffffffffff, // - largest subnormal
    0x0010000000000000, // + smallest normal
    0x8010000000000000, // - smallest normal
    0x3ff0000000000000, // +1
    0xbff0000000000000, // -1
    0x3fe0000000000000, // +0.5
    0x4000000000000000, // +2
    0x4008000000000000, // +3
    0x400921fb54442d18, // +pi
    0x3fb999999999999a, // +0.1
    0x4330000000000000, // 2^52
    0x4340000000000000, // 2^53
    0x4340000000000001, // 2^53 + 1ulp
    0x43e0000000000000, // 2^63
    0x43f0000000000000, // 2^64
    0x43efffffffffffff, // just below 2^64
    0xc3e0000000000000, // -2^63
    0x7fefffffffffffff, // +max normal
    0xffefffffffffffff, // -max normal
    0x7ff0000000000000, // +inf
    0xfff0000000000000, // -inf
    0x7ff8000000000000, // +qnan
    0xfff8000000000000, // -qnan
    0x7ff0000000000001, // +snan
    0xfff0000000000001, // -snan
    0x7ff8000deadbeef0, // +qnan, non trivial payload
    0x3fefffffffffffff, // just below 1
    0x3ff0000000000001, // just above 1
    0x4059000000000000, // 100
    0xc059000000000000, // -100
];

/// Mantissa of a double, and the bits of 1.0.
const MANT_MASK: u64 = 0x000fffffffffffff;
const ONE_BITS: u64 = 0x3ff0000000000000;

const N_RANDOM: usize = 128;

struct Out {
    hash: u64,
    dump: bool,
    buf: String,
}

impl Out {
    /// Every line is printed raw, nan payloads and zero signs included,
    /// so a diff against the C stream shows exactly where the two
    /// disagree.  The hash folds a normalised form instead, in which a
    /// nan result is "nan" and an unsigned-zero result is "zero", since
    /// those results are not stable across compilers.
    fn line2(&mut self, raw: &str, norm: &str) {
        // FNV-1a over the normalised line bytes, newline included.
        for b in norm.as_bytes().iter().chain(b"\n") {
            self.hash ^= *b as u64;
            self.hash = self.hash.wrapping_mul(0x100000001b3);
        }
        if self.dump {
            self.buf.push_str(raw);
            self.buf.push('\n');
        }
    }

    fn line(&mut self, s: &str) {
        self.line2(s, s);
    }

    fn f64(&mut self, op: &str, a: u64, r: f64) {
        let raw = format!("{op} {a:016x} -> {:016x}", r.to_bits());
        let norm = if r.is_nan() { format!("{op} {a:016x} -> nan") } else { raw.clone() };
        self.line2(&raw, &norm);
    }

    fn f64_2(&mut self, op: &str, a: u64, b: u64, r: f64) {
        let raw = format!("{op} {a:016x} {b:016x} -> {:016x}", r.to_bits());
        let norm = if r.is_nan() { format!("{op} {a:016x} {b:016x} -> nan") } else { raw.clone() };
        self.line2(&raw, &norm);
    }

    /// min and max additionally leave the sign of a zero result open.
    fn f64_2_z(&mut self, op: &str, a: u64, b: u64, r: f64) {
        if r == 0.0 {
            let raw = format!("{op} {a:016x} {b:016x} -> {:016x}", r.to_bits());
            let norm = format!("{op} {a:016x} {b:016x} -> zero");
            self.line2(&raw, &norm);
        } else {
            self.f64_2(op, a, b, r);
        }
    }

    fn u64v(&mut self, op: &str, a: u64, r: u64) {
        self.line(&format!("{op} {a:016x} -> {r:016x}"));
    }

    fn boolv(&mut self, op: &str, a: u64, b: u64, r: bool) {
        self.line(&format!("{op} {a:016x} {b:016x} -> {}", r as i32));
    }
}

fn main() {
    let dump = std::env::args().any(|a| a == "--dump");
    let mut o = Out { hash: 0xcbf29ce484222325, dump, buf: String::new() };

    let mut vals: Vec<u64> = SPECIALS.to_vec();
    let mut rng = Rng(0x0123456789abcdef);
    for _ in 0..N_RANDOM {
        vals.push(rng.next());
    }

    for i in 0..vals.len() {
        let ab = vals[i];
        let a = f64::from_bits(ab);

        o.f64("sqrt", ab, a.sqrt());
        o.f64("abs", ab, a.abs());
        o.f64("floor", ab, a.floor());
        o.f64("ceil", ab, a.ceil());
        o.f64("trunc", ab, a.trunc());
        o.f64("round", ab, a.round());
        o.f64("rint", ab, a.round_ties_even());
        o.f64("ln", ab, a.ln());
        o.f64("log2", ab, a.log2());
        o.f64("log10", ab, a.log10());
        o.f64("exp", ab, a.exp());
        o.f64("exp2", ab, a.exp2());
        o.f64("recip", ab, a.recip());
        o.f64("neg", ab, -a);

        // `as` saturates; a plain C cast would be undefined behaviour.
        o.u64v("as_u64", ab, a as u64);
        o.u64v("as_i64", ab, (a as i64) as u64);
        o.u64v("as_u32", ab, (a as u32) as u64);
        o.u64v("as_i32", ab, ((a as i32) as u32) as u64);
        o.u64v("f32_as_u64", ab, (a as f32) as u64);
        o.u64v("f32_as_u32", ab, ((a as f32) as u32) as u64);
        o.u64v("as_f32", ab, (a as f32).to_bits() as u64);
        // u64 -> f64 rounds to nearest, ties to even.
        o.f64("u64_as_f64", ab, ab as f64);
        o.f64("i64_as_f64", ab, (ab as i64) as f64);

        let bb = vals[(i + 1) % vals.len()];
        let cb = vals[(i + 2) % vals.len()];
        let b = f64::from_bits(bb);
        let c = f64::from_bits(cb);

        o.f64_2("add", ab, bb, a + b);
        o.f64_2("sub", ab, bb, a - b);
        o.f64_2("mul", ab, bb, a * b);
        o.f64_2("div", ab, bb, a / b);
        o.f64_2("rem", ab, bb, a % b);
        o.f64_2_z("min", ab, bb, a.min(b));
        o.f64_2_z("max", ab, bb, a.max(b));
        o.f64_2("powf", ab, bb, a.powf(b));
        o.f64_2("copysign", ab, bb, a.copysign(b));
        o.f64_2("hypot", ab, bb, a.hypot(b));

        // mul_add rounds once, a*b+c rounds twice.
        o.f64_2("mul_add", ab, bb, a.mul_add(b, c));
        o.f64_2("muladd", ab, bb, a * b + c);

        // Random patterns give operands of wildly different scale, so
        // a*b+c is dominated by one term and the two roundings never
        // differ.  Rescaling the mantissas into [1,2) makes them differ.
        let as_ = f64::from_bits((ab & MANT_MASK) | ONE_BITS);
        let bs = f64::from_bits((bb & MANT_MASK) | ONE_BITS);
        let cs = -f64::from_bits((cb & MANT_MASK) | ONE_BITS);
        o.f64_2("mul_add_scaled", ab, bb, as_.mul_add(bs, cs));
        o.f64_2("muladd_scaled", ab, bb, as_ * bs + cs);

        // The fd_ helpers these stand in for.
        o.boolv("fd_is_nan", ab, 0, a.is_nan());
        o.boolv("fd_is_inf", ab, 0, a.is_infinite());
        o.boolv("fd_is_zero", ab, 0, a == 0.0);
        o.boolv("fd_is_denorm", ab, 0, a.is_subnormal());
        o.boolv("fd_is_normal", ab, 0, a.is_normal());
        o.u64v("fd_sign", ab, ab >> 63);
        o.u64v("fd_bexp", ab, (ab >> 52) & 0x7ff);
        o.u64v("fd_mant", ab, ab & MANT_MASK);
        o.u64v("fd_pack", ab, ab);
        o.u64v("fd_roundtrip", ab, f64::from_bits(ab).to_bits());
        o.f64("fd_abs", ab, a.abs());
        o.boolv("fd_eq", ab, bb, a.to_bits() == b.to_bits());
        // Against itself, which separates the two notions of equality:
        // bits say a nan equals itself, == says it equals nothing.
        o.boolv("fd_eq_self", ab, ab, a.to_bits() == a.to_bits());
        o.boolv("eq_self", ab, ab, a == a);
        o.f64("fd_if_t", ab, if true { a } else { b });
        o.f64("fd_if_f", ab, if false { a } else { b });

        // f32 helpers, against the same value narrowed to f32.
        let f = a as f32;
        o.boolv("fd_f32_is_nan", ab, 0, f.is_nan());
        o.boolv("fd_f32_is_inf", ab, 0, f.is_infinite());
        o.boolv("fd_f32_is_zero", ab, 0, f == 0.0);
        o.boolv("fd_f32_is_denorm", ab, 0, f.is_subnormal());
        o.boolv("fd_f32_is_normal", ab, 0, f.is_normal());

        o.boolv("eq", ab, bb, a == b);
        o.boolv("lt", ab, bb, a < b);
        o.boolv("le", ab, bb, a <= b);
        o.boolv("ne", ab, bb, a != b);
    }

    if dump {
        print!("{}", o.buf);
    }
    eprintln!("{} values, hash {:016x}", vals.len(), o.hash);
}

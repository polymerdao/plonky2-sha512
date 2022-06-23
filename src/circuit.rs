use crate::split_base::CircuitBuilderSplit;
use num::bigint::BigUint;
use num::FromPrimitive;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_ecdsa::gadgets::biguint::{BigUintTarget, CircuitBuilderBiguint};
use plonky2_field::extension_field::Extendable;
use plonky2_u32::gadgets::arithmetic_u32::U32Target;

#[rustfmt::skip]
pub const H512_512: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

/// Constants necessary for SHA-512 family of digests.
#[rustfmt::skip]
pub const K64: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

pub struct Sha512Targets {
    pub message: Vec<BoolTarget>,
    pub digest: Vec<BoolTarget>,
}

fn biguint_to_bits_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &BigUintTarget,
) -> Vec<BoolTarget> {
    let mut res = Vec::new();
    for i in (0..2).rev() {
        let bit_targets = builder.split_le_base::<2>(a.get_limb(i).0, 32);
        for j in (0..32).rev() {
            res.push(BoolTarget::new_unsafe(bit_targets[j]));
        }
    }
    res
}

//define ROTATE(x, y)  (((x)>>(y)) | ((x)<<(64-(y))))
fn rotate64(y: usize) -> Vec<usize> {
    let mut res = Vec::new();
    for i in 64 - y..64 {
        res.push(i);
    }
    for i in 0..64 - y {
        res.push(i);
    }
    res
}

/*
a ^ b ^ c = a+b+c - 2*a*b - 2*a*c - 2*b*c + 4*a*b*c
          = a*( 1 - 2*b - 2*c + 4*b*c ) + b + c - 2*b*c
          = a*( 1 - 2*b -2*c + 4*m ) + b + c - 2*m
where m = b*c
 */
fn xor3<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: BoolTarget,
    b: BoolTarget,
    c: BoolTarget,
) -> BoolTarget {
    let m = builder.mul(b.target, c.target);
    let two_b = builder.add(b.target, b.target);
    let two_c = builder.add(c.target, c.target);
    let two_m = builder.add(m, m);
    let four_m = builder.add(two_m, two_m);
    let one = builder.one();
    let one_minus_two_b = builder.sub(one, two_b);
    let one_minus_two_b_minus_two_c = builder.sub(one_minus_two_b, two_c);
    let one_minus_two_b_minus_two_c_add_four_m = builder.add(one_minus_two_b_minus_two_c, four_m);
    let mut res = builder.mul(a.target, one_minus_two_b_minus_two_c_add_four_m);
    res = builder.add(res, b.target);
    res = builder.add(res, c.target);

    BoolTarget::new_unsafe(builder.sub(res, two_m))
}

fn bits_to_biguint_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bits_target: Vec<BoolTarget>,
) -> BigUintTarget {
    assert_eq!(bits_target.len(), 64);
    let u32_0 = builder.le_sum(bits_target[0..32].iter().rev());
    let u32_1 = builder.le_sum(bits_target[32..64].iter().rev());
    let mut u32_targets = Vec::new();
    u32_targets.push(U32Target(u32_1));
    u32_targets.push(U32Target(u32_0));
    BigUintTarget { limbs: u32_targets }
}

//define Sigma0(x)    (ROTATE((x),28) ^ ROTATE((x),34) ^ ROTATE((x),39))
fn big_sigma0<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &BigUintTarget,
) -> BigUintTarget {
    let a_bits = biguint_to_bits_target(builder, a);
    let rotate28 = rotate64(28);
    let rotate34 = rotate64(34);
    let rotate39 = rotate64(39);
    let mut res_bits = Vec::new();
    for i in 0..64 {
        res_bits.push(xor3(
            builder,
            a_bits[rotate28[i]],
            a_bits[rotate34[i]],
            a_bits[rotate39[i]],
        ));
    }
    bits_to_biguint_target(builder, res_bits)
}

//define Sigma1(x)    (ROTATE((x),14) ^ ROTATE((x),18) ^ ROTATE((x),41))
fn big_sigma1<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &BigUintTarget,
) -> BigUintTarget {
    let a_bits = biguint_to_bits_target(builder, a);
    let rotate28 = rotate64(14);
    let rotate34 = rotate64(18);
    let rotate39 = rotate64(41);
    let mut res_bits = Vec::new();
    for i in 0..64 {
        res_bits.push(xor3(
            builder,
            a_bits[rotate28[i]],
            a_bits[rotate34[i]],
            a_bits[rotate39[i]],
        ));
    }
    bits_to_biguint_target(builder, res_bits)
}

/*
define Ch(x, y, z)    (((x) & (y)) ^ ((~(x)) & (z)))
ch = a&b ^ (!a)&c
   = a*(b-c) + c
 */

/*
define Maj(x, y, z)   (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
maj = a&b ^ a&c ^ b&c
    = a*b   +  a*c  +  b*c  -  2*a*b*c
    = a*( b + c - 2*b*c ) + b*c
    = a*( b + c - 2*m ) + m
where m = b*c
 */

// padded_msg_len = block_count x 1024 bits
// Size: msg_len_in_bits (L) |  p bits   | 128 bits
// Bits:      msg            | 100...000 |    L
pub fn make_circuits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    msg_len_in_bits: u128,
) -> Sha512Targets {
    let mut message = Vec::new();
    let mut digest = Vec::new();
    let block_count = (msg_len_in_bits + 129 + 1023) / 1024;
    let padded_msg_len = 1024 * block_count;
    let p = padded_msg_len - 128 - msg_len_in_bits;
    assert!(p > 1);

    for _ in 0..msg_len_in_bits {
        message.push(builder.add_virtual_bool_target());
    }
    message.push(builder.constant_bool(true));
    for _ in 0..p - 1 {
        message.push(builder.constant_bool(false));
    }
    for i in 0..128 {
        let b = ((msg_len_in_bits as u128) >> (127 - i)) & 1;
        message.push(builder.constant_bool(b == 1));
    }

    // init states
    let mut state = Vec::new();
    for i in 0..8 {
        state.push(builder.constant_biguint(&BigUint::from_u64(H512_512[i]).unwrap()));
    }

    let mut k512 = Vec::new();
    for i in 0..80 {
        k512.push(builder.constant_biguint(&BigUint::from_u64(K64[i]).unwrap()));
    }

    for blk in 0..block_count {
        let mut x = Vec::new();
        let mut a = state[0].clone();
        let mut b = state[1].clone();
        let mut c = state[2].clone();
        let mut d = state[3].clone();
        let mut e = state[4].clone();
        let mut f = state[5].clone();
        let mut g = state[6].clone();
        let mut h = state[7].clone();

        for i in 0..16 {
            let index = blk as usize * 1024 + i * 64;
            let u32_0 = builder.le_sum(message[index..index + 32].iter().rev());
            let u32_1 = builder.le_sum(message[index + 32..index + 64].iter().rev());

            let mut u32_targets = Vec::new();
            u32_targets.push(U32Target(u32_1));
            u32_targets.push(U32Target(u32_0));
            let big_int = BigUintTarget { limbs: u32_targets };

            x.push(big_int);
            let mut t1 = h.clone();
            let big_sigma1_e = big_sigma1(builder, &e);
            t1 = builder.add_biguint(&t1, &big_sigma1_e);
            t1 = builder.add_biguint(&t1, &k512[i]);
            t1 = builder.add_biguint(&t1, &x[i]);

            let t2 = big_sigma0(builder, &a);

            h = g;
            g = f;
            f = e;
            e = builder.add_biguint(&d, &t1);
            d = c;
            c = b;
            b = a;
            a = builder.add_biguint(&t1, &t2);
        }
        // for i in 16..80 {}

        state[0] = builder.add_biguint(&state[0], &a);
        state[1] = builder.add_biguint(&state[1], &b);
        state[2] = builder.add_biguint(&state[2], &c);
        state[3] = builder.add_biguint(&state[3], &d);
        state[4] = builder.add_biguint(&state[4], &e);
        state[5] = builder.add_biguint(&state[5], &f);
        state[6] = builder.add_biguint(&state[6], &g);
        state[7] = builder.add_biguint(&state[7], &h);
    }

    for i in 0..8 {
        for j in (0..2).rev() {
            let bit_targets = builder.split_le_base::<2>(state[i].get_limb(j).0, 32);
            for k in (0..32).rev() {
                digest.push(BoolTarget::new_unsafe(bit_targets[k]));
            }
        }
    }

    Sha512Targets { message, digest }
}

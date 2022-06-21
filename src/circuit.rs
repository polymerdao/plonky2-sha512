use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_field::extension_field::Extendable;

pub struct Sha512Targets {
    pub message: Vec<BoolTarget>,
    pub digest: Vec<BoolTarget>,
}

// padded_msg_len = block_count x 1024 bits
// Size: msg_len_in_bits (L) |  p bits   | 128 bits
// Bits:      msg            | 100...000 |    L
pub fn make_circuits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, msg_len_in_bits: u128) -> Sha512Targets {
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
        let b = (msg_len_in_bits >> (127 - i)) & 1;
        message.push(builder.constant_bool(b == 1));
    }

    for _ in 0..block_count {}

    for _ in 0..512 {
        digest.push(builder.constant_bool(false));
    }

    Sha512Targets {
        message,
        digest,
    }
}

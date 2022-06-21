use plonky2::field::field_types::Field;
use plonky2::hash::hash_types::{HashOutTarget, MerkleCapTarget, RichField};
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_field::extension_field::Extendable;

pub struct Sha512Targets {
    pub message: Vec<BoolTarget>,
    pub digest: Vec<BoolTarget>,
}

pub fn make_circuits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, meg_len: usize) -> Sha512Targets {
    let mut message = Vec::new();
    let mut digest = Vec::new();

    for _ in 0..meg_len {
        message.push(builder.add_virtual_bool_target());
    }
    for _ in 0..512 {
        digest.push(builder.constant_bool(false));
    }

    Sha512Targets {
        message,
        digest,
    }
}

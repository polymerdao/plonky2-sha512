use plonky2::field::field_types::Field;
use plonky2::hash::hash_types::{HashOutTarget, MerkleCapTarget, RichField};
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_field::extension_field::Extendable;

pub struct Sha512Targets<const L: usize> {
    pub message: [BoolTarget; L],
    pub digest: [BoolTarget; 512],
}

pub fn make_circuits<F: RichField + Extendable<D>, const D: usize, const L: usize>(
    builder: &mut CircuitBuilder<F, D>) -> Sha512Targets<L> {
    let mut message = [builder.add_virtual_bool_target(); L];
    let mut digest = [builder.add_virtual_bool_target(); 512];

    Sha512Targets {
        message,
        digest,
    }
}

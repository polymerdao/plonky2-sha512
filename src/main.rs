use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use sha2::{Sha512, Digest};
use plonky2_sha512::circuit::make_circuits;

pub fn prove_sha512<const L: usize>(msg: &[u8]) {
    let mut hasher = Sha512::new();
    hasher.update(msg);
    let hash = hasher.finalize();
    println!("Hash: {:#04X}", hash);

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());
    let targets = make_circuits::<F, D, L>(&mut builder);
    let mut pw = PartialWitness::new();

    let len = msg.len() * 8;
    for i in 0..len {
        pw.set_bool_target(targets.message[i], true);
    }

    for i in 0..512 {
        let b = true;
        if b {
            builder.assert_one(targets.digest[i].target);
        } else {
            builder.assert_zero(targets.digest[i].target);
        }
    }

    let data = builder.build::<C>();
    let proof = data.prove(pw).unwrap();

    data.verify(proof).expect("Hash error");
}

fn main() {
    let mut msg = vec![0; 128 as usize];
    for i in 0..127 {
        msg[i] = i as u8;
    }
    prove_sha512::<1024>(&msg);
}

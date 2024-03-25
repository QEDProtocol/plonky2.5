pub mod air;
pub mod challenger;
pub mod commit;
pub mod constants;
pub mod serde;
pub mod types;
pub mod utils;
pub mod verifier;

use crate::{
    common::u32::{
        arithmetic_u32::U32Target, binary_u32::CircuitBuilderBU32,
        interleaved_u32::CircuitBuilderB32,
    },
    p3::{
        air::Air,
        challenger::DuplexChallengerTarget,
        constants::EXT_DEGREE,
        serde::{Goldilocks, Proof},
        types::{
            CommitmentTarget, CommitmentsTarget, FriConfig, FriProofTarget, ProofTarget,
            TwoAdicFriPcsProofTarget,
        },
        utils::{
            batch_opening_to_target, binomial_extension_field_to_target, opened_values_to_target,
            query_proof_to_target,
        },
        verifier::CircuitBuilderP3Verifier,
    },
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::Target,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

pub trait CircuitBuilderP3Arithmetic<F: RichField + Extendable<D>, const D: usize> {
    fn p3_constant(&mut self, value: impl Into<u64>) -> Target;
    fn p3_and(&mut self, x: Target, y: Target) -> Target;
    fn p3_xor(&mut self, x: Target, y: Target) -> Target;
    fn p3_rsh(&mut self, x: Target, n: u8) -> Target;
    fn p3_lsh(&mut self, x: Target, n: u8) -> Target;
    fn reverse_p3(&mut self, x: Target) -> Target;
    fn reverse_p3_bits_len(&mut self, x: Target, bit_len: usize) -> Target;
    fn p3_arr<const SIZE: usize>(&mut self) -> [Target; SIZE];
    fn p3_arr_fn<const SIZE: usize>(&mut self, f: impl FnMut(usize) -> Target) -> [Target; SIZE];
    fn p3_field_to_arr<const SIZE: usize>(&mut self, x: Target) -> [Target; SIZE];
    fn p3_verify_proof<H: AlgebraicHasher<F>>(
        &mut self,
        proof: Proof<Goldilocks>,
        air: &impl Air,
        log_quotient_degree: usize,
        log_trace_height: usize,
    );
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderP3Arithmetic<F, D>
    for CircuitBuilder<F, D>
{
    fn p3_constant(&mut self, value: impl Into<u64>) -> Target {
        // TODO: don't use hard coded Goldilocks modulus
        // we need to use the modulus here because serialization will not reduce
        // automatically those overflowed values
        self.constant(F::from_canonical_u64(value.into() % 0xFFFF_FFFF_0000_0001))
    }

    fn p3_arr<const SIZE: usize>(&mut self) -> [Target; SIZE] {
        core::array::from_fn(|_| self.zero())
    }

    fn p3_arr_fn<const SIZE: usize>(&mut self, f: impl FnMut(usize) -> Target) -> [Target; SIZE] {
        core::array::from_fn(f)
    }

    fn p3_verify_proof<H: AlgebraicHasher<F>>(
        &mut self,
        proof: Proof<Goldilocks>,
        air: &impl Air,
        log_quotient_degree: usize,
        log_trace_height: usize,
    ) {
        let opening_proof_target = TwoAdicFriPcsProofTarget::<Target, EXT_DEGREE> {
            fri_proof: FriProofTarget {
                commit_phase_commits: proof
                    .opening_proof
                    .fri_proof
                    .commit_phase_commits
                    .into_iter()
                    .map(|x| CommitmentTarget {
                        value: x.value.map(|x| self.p3_constant(x.value)),
                    })
                    .collect::<Vec<_>>(),
                query_proofs: proof
                    .opening_proof
                    .fri_proof
                    .query_proofs
                    .into_iter()
                    .map(|x| query_proof_to_target(x, self))
                    .collect::<Vec<_>>(),
                final_poly: binomial_extension_field_to_target(
                    proof.opening_proof.fri_proof.final_poly,
                    self,
                ),
                pow_witness: self.p3_constant(proof.opening_proof.fri_proof.pow_witness.value),
            },
            query_openings: proof
                .opening_proof
                .query_openings
                .into_iter()
                .map(|x| {
                    x.into_iter()
                        .map(|y| batch_opening_to_target(y, self))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>(),
        };

        let proof_target = ProofTarget {
            commitments: CommitmentsTarget {
                trace: CommitmentTarget {
                    value: proof
                        .commitments
                        .trace
                        .value
                        .map(|x| self.p3_constant(x.value)),
                },
                quotient_chunks: CommitmentTarget {
                    value: proof
                        .commitments
                        .quotient_chunks
                        .value
                        .map(|x| self.p3_constant(x.value)),
                },
            },
            opened_values: opened_values_to_target(proof.opened_values, self),
            opening_proof: opening_proof_target,
            degree_bits: proof.degree_bits,
        };

        let mut challenger = DuplexChallengerTarget::from_builder(self);
        let config = FriConfig {
            log_blowup: 1,
            num_queries: 100,
            proof_of_work_bits: 16,
        };

        self.__p3_verify_proof__::<H>(
            air,
            proof_target,
            &config,
            &mut challenger,
            log_quotient_degree,
            log_trace_height,
        );
    }

    fn p3_and(&mut self, x: Target, y: Target) -> Target {
        let (x_low, x_high) = self.split_low_high(x, 32, 64);
        let (y_low, y_high) = self.split_low_high(y, 32, 64);
        let [low, high] = self.and_u64(
            &[U32Target(x_low), U32Target(x_high)],
            &[U32Target(y_low), U32Target(y_high)],
        );
        self.mul_const_add(F::from_canonical_u64(1 << 32), high.0, low.0)
    }

    fn p3_xor(&mut self, x: Target, y: Target) -> Target {
        let (x_low, x_high) = self.split_low_high(x, 32, 64);
        let (y_low, y_high) = self.split_low_high(y, 32, 64);
        let [low, high] = self.xor_u64(
            &[U32Target(x_low), U32Target(x_high)],
            &[U32Target(y_low), U32Target(y_high)],
        );
        self.mul_const_add(F::from_canonical_u64(1 << 32), high.0, low.0)
    }

    fn p3_lsh(&mut self, x: Target, n: u8) -> Target {
        let (x_low, x_high) = self.split_low_high(x, 32, 64);
        let [low, high] = self.lsh_u64(&[U32Target(x_low), U32Target(x_high)], n);
        self.mul_const_add(F::from_canonical_u64(1 << 32), high.0, low.0)
    }

    fn p3_rsh(&mut self, x: Target, n: u8) -> Target {
        let (x_low, x_high) = self.split_low_high(x, 32, 64);
        let [low, high] = self.rsh_u64(&[U32Target(x_low), U32Target(x_high)], n);
        self.mul_const_add(F::from_canonical_u64(1 << 32), high.0, low.0)
    }

    fn reverse_p3(&mut self, x: Target) -> Target {
        let (x_low, x_high) = self.split_low_high(x, 32, 64);
        let x_low_bin32 = self.convert_u32_bin32(U32Target(x_low));
        let x_high_bin32 = self.convert_u32_bin32(U32Target(x_high));
        let [x_low_reversed, x_high_reversed] = self.reverse_bin64([x_low_bin32, x_high_bin32]);
        let x_low_u32 = self.convert_bin32_u32(x_low_reversed);
        let x_high_u32 = self.convert_bin32_u32(x_high_reversed);
        self.mul_const_add(F::from_canonical_u64(1 << 32), x_high_u32.0, x_low_u32.0)
    }

    fn reverse_p3_bits_len(&mut self, x: Target, bit_len: usize) -> Target {
        let x_reversed = self.reverse_p3(x);
        self.p3_rsh(x_reversed, u8::try_from(64usize - bit_len).unwrap())
    }

    fn p3_field_to_arr<const SIZE: usize>(&mut self, x: Target) -> [Target; SIZE] {
        let mut res = self.p3_arr::<SIZE>();
        res[0] = x;
        res
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::poseidon::PoseidonHash,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };
    use rand::Rng;

    use crate::{
        common::hash::poseidon2::{
            constants::{
                DEGREE, MAT_INTERNAL_DIAG_M_1, ROUNDS_F, ROUNDS_P, ROUND_CONSTANTS, WIDTH,
            },
            Poseidon2Target,
        },
        p3::{air::FibonacciAir, utils::reverse_bits_len},
    };

    use super::*;

    #[test]
    fn test_verify_plonky3_proof() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = GoldilocksField;
        let config = CircuitConfig::standard_recursion_config();

        let proof_str = include_str!("proof_fibonacci.json");
        let proof = serde_json::from_str::<Proof<Goldilocks>>(proof_str).unwrap();

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let air = FibonacciAir {};

        builder.p3_verify_proof::<PoseidonHash>(proof, &air, 0, 6);

        let data = builder.build::<C>();

        let pw = PartialWitness::new();

        let start_time = std::time::Instant::now();
        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("demo proved in {}ms", duration_ms);
        println!("proof public_inputs: {:?}", proof.public_inputs);

        let is_verified = data.verify(proof);
        is_verified.as_ref().unwrap();
        assert!(is_verified.is_ok());
    }

    #[test]
    fn test_poseidon2_hash() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = GoldilocksField;
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);

        let poseidon2_target = Poseidon2Target::new(
            WIDTH,
            DEGREE,
            ROUNDS_F,
            ROUNDS_P,
            MAT_INTERNAL_DIAG_M_1
                .into_iter()
                .map(|x| builder.p3_constant(x))
                .collect::<Vec<_>>(),
            ROUND_CONSTANTS
                .into_iter()
                .map(|x| {
                    x.into_iter()
                        .map(|y| builder.p3_constant(y))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>(),
        );

        let mut input = [builder.zero(); 8];
        poseidon2_target.permute_mut(&mut input, &mut builder);
        builder.register_public_inputs(&input);

        let data = builder.build::<C>();

        let pw = PartialWitness::new();

        let start_time = std::time::Instant::now();
        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("demo proved in {}ms", duration_ms);
        println!("proof public_inputs: {:?}", proof.public_inputs);

        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_p3_and() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = GoldilocksField;
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.add_virtual_target();
        let y = builder.add_virtual_target();
        let x_plus_y = builder.add_virtual_target();

        let res = builder.p3_and(x, y);

        builder.register_public_input(res);
        builder.connect(res, x_plus_y);

        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        let mut rng = rand::thread_rng();
        let x_val = rng.gen::<u64>();
        let y_val = rng.gen::<u64>();

        pw.set_target(x, F::from_canonical_u64(x_val));
        pw.set_target(y, F::from_canonical_u64(y_val));
        pw.set_target(x_plus_y, F::from_canonical_u64(x_val & y_val));

        let start_time = std::time::Instant::now();
        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("demo proved in {}ms", duration_ms);
        println!("proof public_inputs: {:?}", proof.public_inputs);

        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_p3_xor() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = GoldilocksField;
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.add_virtual_target();
        let y = builder.add_virtual_target();
        let x_xor_y = builder.add_virtual_target();

        let res = builder.p3_xor(x, y);

        builder.register_public_input(res);
        builder.connect(res, x_xor_y);

        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        let mut rng = rand::thread_rng();
        let x_val = rng.gen::<u64>();
        let y_val = rng.gen::<u64>();

        pw.set_target(x, F::from_canonical_u64(x_val));
        pw.set_target(y, F::from_canonical_u64(y_val));
        pw.set_target(x_xor_y, F::from_canonical_u64(x_val ^ y_val));

        let start_time = std::time::Instant::now();
        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("demo proved in {}ms", duration_ms);
        println!("proof public_inputs: {:?}", proof.public_inputs);

        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_p3_lsh() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = GoldilocksField;
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.add_virtual_target();
        let x_shifted = builder.add_virtual_target();

        let res = builder.p3_lsh(x, 2);

        builder.register_public_input(res);
        builder.connect(res, x_shifted);

        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        let mut rng = rand::thread_rng();
        let x_val = rng.gen::<u64>();

        pw.set_target(x, F::from_canonical_u64(x_val));
        pw.set_target(
            x_shifted,
            F::from_canonical_u64((((x_val as u128) << 2) & 0xffffffffffffffff) as u64),
        );

        let start_time = std::time::Instant::now();
        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("demo proved in {}ms", duration_ms);
        println!("proof public_inputs: {:?}", proof.public_inputs);

        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_p3_rsh() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = GoldilocksField;
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.add_virtual_target();
        let x_shifted = builder.add_virtual_target();

        let res = builder.p3_rsh(x, 2);

        builder.register_public_input(res);
        builder.connect(res, x_shifted);

        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        let mut rng = rand::thread_rng();
        let x_val = rng.gen::<u64>();

        pw.set_target(x, F::from_canonical_u64(x_val));
        pw.set_target(
            x_shifted,
            F::from_canonical_u64((((x_val as u128) >> 2) & 0xffffffffffffffff) as u64),
        );

        let start_time = std::time::Instant::now();
        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("demo proved in {}ms", duration_ms);
        println!("proof public_inputs: {:?}", proof.public_inputs);

        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_reverse() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = GoldilocksField;
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.add_virtual_target();
        let x_reversed = builder.add_virtual_target();

        let res = builder.reverse_p3(x);

        builder.register_public_input(res);
        builder.connect(res, x_reversed);

        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        let mut rng = rand::thread_rng();
        let x_val = rng.gen::<u64>();

        pw.set_target(x, F::from_canonical_u64(x_val));
        pw.set_target(x_reversed, F::from_canonical_u64(x_val.reverse_bits()));

        let start_time = std::time::Instant::now();
        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("demo proved in {}ms", duration_ms);
        println!("proof public_inputs: {:?}", proof.public_inputs);

        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_reverse_bits_len() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = GoldilocksField;
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.add_virtual_target();
        let x_reversed = builder.add_virtual_target();

        let res = builder.reverse_p3_bits_len(x, 2);

        builder.register_public_input(res);
        builder.connect(res, x_reversed);

        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        let mut rng = rand::thread_rng();
        let x_val = rng.gen::<usize>();
        dbg!(x_val);

        pw.set_target(x, F::from_canonical_usize(x_val));
        pw.set_target(
            x_reversed,
            F::from_canonical_usize(reverse_bits_len(x_val, 2)),
        );

        let start_time = std::time::Instant::now();
        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("demo proved in {}ms", duration_ms);
        println!("proof public_inputs: {:?}", proof.public_inputs);

        assert!(data.verify(proof).is_ok());
    }
}

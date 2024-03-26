pub mod air;
pub mod challenger;
pub mod commit;
pub mod constants;
pub mod extension;
pub mod gadgets;
pub mod serde;
pub mod utils;
pub mod verifier;

use crate::{
    common::{
        richer_field::RicherField,
        u32::{
            arithmetic_u32::U32Target, binary_u32::CircuitBuilderBU32,
            interleaved_u32::CircuitBuilderB32,
        },
    },
    p3::{
        air::Air,
        challenger::DuplexChallengerTarget,
        serde::{
            fri::FriConfig,
            proof::{P3Config, P3ProofField, Proof},
        },
        utils::log2_ceil_usize,
        verifier::CircuitBuilderP3Verifier,
    },
};
use plonky2::{
    field::extension::Extendable,
    iop::target::Target,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

pub trait CircuitBuilderP3Arithmetic<F: RicherField + Extendable<D>, const D: usize> {
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
        proof: P3ProofField,
        air: &impl Air,
        fri_config: FriConfig,
    ) -> Proof<Target>;
}

impl<F: RicherField + Extendable<D>, const D: usize> CircuitBuilderP3Arithmetic<F, D>
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
        proof: P3ProofField,
        air: &impl Air,
        fri_config: FriConfig,
    ) -> Proof<Target> {
        let mut challenger = DuplexChallengerTarget::from_builder(self);

        let config = P3Config {
            fri_config,
            log_quotient_degree: log2_ceil_usize(proof.opened_values.quotient_chunks.len()),
            log_trace_height: proof.opening_proof.fri_proof.commit_phase_commits.len(),
            trace_width: proof.opened_values.trace_local.len(),
            opening_matrix_log_max_height: proof.opening_proof.query_openings[0][0]
                .opening_proof
                .len(),
            opening_proof_query_openings_opened_values_length: proof.opening_proof.query_openings
                [0][1]
                .opened_values[0]
                .len(),
            degree_bits: proof.degree_bits,
        };

        let proof_target = Proof::<Target>::add_virtual_to(self, &config);

        self.__p3_verify_proof__::<H>(air, proof_target.clone(), &config, &mut challenger);

        proof_target
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

    use crate::p3::{
        air::VerifierConstraintFolder, extension::CircuitBuilderP3ExtArithmetic,
        serde::proof::BinomialExtensionField, utils::reverse_bits_len,
    };

    pub const NUM_FIBONACCI_COLS: usize = 3;

    pub struct FibonacciAir {}

    #[repr(C)]
    pub struct FibnacciCols<T> {
        a: T,
        b: T,
        c: T,
    }

    impl Air for FibonacciAir {
        fn name(&self) -> String {
            "Fibonacci".to_string()
        }

        fn width(&self) -> usize {
            NUM_FIBONACCI_COLS
        }

        fn eval<F: RicherField + Extendable<D>, const D: usize>(
            &self,
            folder: &mut VerifierConstraintFolder<Target>,
            cb: &mut CircuitBuilder<F, D>,
        ) {
            let local = FibnacciCols::<BinomialExtensionField<Target>> {
                a: folder.main.trace_local[0].clone(),
                b: folder.main.trace_local[1].clone(),
                c: folder.main.trace_local[2].clone(),
            };

            let next = FibnacciCols::<BinomialExtensionField<Target>> {
                a: folder.main.trace_next[0].clone(),
                b: folder.main.trace_next[1].clone(),
                c: folder.main.trace_next[2].clone(),
            };

            let local_a_plus_b = cb.p3_ext_add(local.a.clone(), local.b.clone());
            folder.assert_eq(local_a_plus_b, local.c.clone(), cb);

            let one = cb.p3_ext_one();
            folder
                .when_first_row::<F, D>()
                .assert_eq(one.clone(), local.a.clone(), cb);
            folder
                .when_first_row::<F, D>()
                .assert_eq(one.clone(), local.b.clone(), cb);

            folder
                .when_transition::<F, D>()
                .assert_eq(next.a.clone(), local.b, cb);
            folder
                .when_transition::<F, D>()
                .assert_eq(next.b, local.c, cb);
        }
    }

    use super::*;

    #[test]
    fn test_verify_plonky3_proof() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = GoldilocksField;
        let config = CircuitConfig::standard_recursion_config();

        let proof_str = include_str!("../../artifacts/proof_fibonacci.json");
        let proof = serde_json::from_str::<P3ProofField>(proof_str).unwrap();
        // let p: Proof<GoldilocksField>;
        // unsafe { p = std::mem::transmute(proof.clone()) }
        // std::fs::write("ppp.json", serde_json::to_string(&p).unwrap()).unwrap();

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let air = FibonacciAir {};

        let config = FriConfig {
            log_blowup: 1,
            num_queries: 100,
            proof_of_work_bits: 16,
        };

        let proof_target = builder.p3_verify_proof::<PoseidonHash>(proof.clone(), &air, config);

        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();

        let p: Proof<GoldilocksField>;
        unsafe { p = std::mem::transmute(proof) }

        proof_target.set_witness::<F, D, _>(&mut pw, &p);

        let start_time = std::time::Instant::now();
        let proof = data.prove(pw).unwrap();
        std::fs::write("proof.json", serde_json::to_string(&proof).unwrap()).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("demo proved in {}ms", duration_ms);
        println!("proof public_inputs: {:?}", proof.public_inputs);

        let is_verified = data.verify(proof);
        is_verified.as_ref().unwrap();
        assert!(is_verified.is_ok());
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

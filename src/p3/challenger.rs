use plonky2::field::extension::Extendable;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::AlgebraicHasher;

use crate::common::poseidon2::poseidon2::Poseidon2Hash;
use crate::common::richer_field::RicherField;
use crate::common::u32::arithmetic_u32::U32Target;
use crate::common::u32::interleaved_u32::CircuitBuilderB32;
use crate::p3::constants::EXT_DEGREE;
use crate::p3::constants::WIDTH;
use crate::p3::serde::proof::BinomialExtensionField;
use crate::p3::CircuitBuilderP3Arithmetic;

pub struct DuplexChallengerTarget {
    sponge_state: Vec<Target>,
    input_buffer: Vec<Target>,
    output_buffer: Vec<Target>,
}

impl DuplexChallengerTarget {
    pub fn from_builder<F: RicherField + Extendable<D>, const D: usize>(
        cb: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            sponge_state: cb.p3_arr::<WIDTH>().to_vec(),
            input_buffer: Vec::new(),
            output_buffer: Vec::new(),
        }
    }
}

pub trait DuplexChallenger<F: RicherField + Extendable<D>, const D: usize> {
    fn p3_duplexing<H: AlgebraicHasher<F>>(&mut self, x: &mut DuplexChallengerTarget);
    fn p3_observe_single<H: AlgebraicHasher<F>>(
        &mut self,
        x: &mut DuplexChallengerTarget,
        value: Target,
    );
    fn p3_observe<H: AlgebraicHasher<F>>(
        &mut self,
        x: &mut DuplexChallengerTarget,
        values: impl IntoIterator<Item = Target>,
    );
    fn p3_sample<H: AlgebraicHasher<F>>(&mut self, x: &mut DuplexChallengerTarget) -> Target;
    fn p3_sample_arr<H: AlgebraicHasher<F>>(
        &mut self,
        x: &mut DuplexChallengerTarget,
    ) -> [Target; EXT_DEGREE];
    fn p3_sample_ext<H: AlgebraicHasher<F>>(
        &mut self,
        x: &mut DuplexChallengerTarget,
    ) -> BinomialExtensionField<Target>;
    fn p3_sample_bits<H: AlgebraicHasher<F>>(
        &mut self,
        x: &mut DuplexChallengerTarget,
        bits: usize,
    ) -> Target;
    fn p3_check_witness<H: AlgebraicHasher<F>>(
        &mut self,
        x: &mut DuplexChallengerTarget,
        bits: usize,
        witness: Target,
    );
}

impl<F: RicherField + Extendable<D>, const D: usize> DuplexChallenger<F, D>
    for CircuitBuilder<F, D>
{
    fn p3_duplexing<H: AlgebraicHasher<F>>(&mut self, x: &mut DuplexChallengerTarget) {
        assert!(x.input_buffer.len() <= WIDTH);

        for (i, val) in x.input_buffer.drain(..).enumerate() {
            x.sponge_state[i] = val;
        }

        x.sponge_state = Poseidon2Hash::permute_targets::<F, D>(&x.sponge_state, self).to_vec();

        x.output_buffer.clear();
        x.output_buffer.extend(x.sponge_state.clone());
    }

    fn p3_observe_single<H: AlgebraicHasher<F>>(
        &mut self,
        x: &mut DuplexChallengerTarget,
        value: Target,
    ) {
        x.output_buffer.clear();
        x.input_buffer.push(value);

        if x.input_buffer.len() == WIDTH {
            self.p3_duplexing::<H>(x);
        }
    }

    fn p3_observe<H: AlgebraicHasher<F>>(
        &mut self,
        x: &mut DuplexChallengerTarget,
        values: impl IntoIterator<Item = Target>,
    ) {
        for value in values {
            self.p3_observe_single::<H>(x, value);
        }
    }

    fn p3_sample<H: AlgebraicHasher<F>>(&mut self, x: &mut DuplexChallengerTarget) -> Target {
        // If we have buffered inputs, we must perform a duplexing so that the challenge
        // will reflect them. Or if we've run out of outputs, we must perform a
        // duplexing to get more.
        if !x.input_buffer.is_empty() || x.output_buffer.is_empty() {
            self.p3_duplexing::<H>(x);
        }

        x.output_buffer
            .pop()
            .expect("Output buffer should be non-empty")
    }

    fn p3_sample_arr<H: AlgebraicHasher<F>>(
        &mut self,
        x: &mut DuplexChallengerTarget,
    ) -> [Target; EXT_DEGREE] {
        core::array::from_fn(|_| self.p3_sample::<H>(x))
    }

    fn p3_sample_bits<H: AlgebraicHasher<F>>(
        &mut self,
        x: &mut DuplexChallengerTarget,
        bits: usize,
    ) -> Target {
        let rand_f = self.p3_sample::<H>(x);
        let (rand_f_low, rand_f_high) = self.split_low_high(rand_f, 32, 64);
        let one = self.one();
        let power_of_bits = self.p3_constant((0x1usize << bits) as u64);
        let power_of_bits_minus_one = self.sub(power_of_bits, one);
        let (power_of_bits_minus_one_low, power_of_bits_minus_one_high) =
            self.split_low_high(power_of_bits_minus_one, 32, 64);

        let [low, high] = self.and_u64(
            &[U32Target(rand_f_low), U32Target(rand_f_high)],
            &[
                U32Target(power_of_bits_minus_one_low),
                U32Target(power_of_bits_minus_one_high),
            ],
        );

        self.mul_const_add(F::from_canonical_u64(1 << 32), high.0, low.0)
    }

    fn p3_sample_ext<H: AlgebraicHasher<F>>(
        &mut self,
        x: &mut DuplexChallengerTarget,
    ) -> BinomialExtensionField<Target> {
        BinomialExtensionField {
            value: self.p3_sample_arr::<H>(x),
        }
    }

    fn p3_check_witness<H: AlgebraicHasher<F>>(
        &mut self,
        x: &mut DuplexChallengerTarget,
        bits: usize,
        witness: Target,
    ) {
        self.p3_observe_single::<H>(x, witness);
        let res = self.p3_sample_bits::<H>(x, bits);
        let zero = self.zero();
        self.connect(res, zero);
    }
}

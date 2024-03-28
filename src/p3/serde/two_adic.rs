use plonky2::field::extension::Extendable;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::common::richer_field::RicherField;
use crate::p3::extension::CircuitBuilderP3ExtArithmetic;
use crate::p3::serde::proof::BinomialExtensionField;
use crate::p3::serde::LagrangeSelectors;
use crate::p3::utils::log2_ceil_usize;
use crate::p3::utils::log2_strict_usize;

#[derive(Clone, Copy, Debug)]
pub struct TwoAdicMultiplicativeCoset {
    pub log_n: usize,
    pub shift: Target,
}

impl TwoAdicMultiplicativeCoset {
    const TWO_ADICITY: usize = 32;

    pub fn size(&self) -> usize {
        1 << self.log_n
    }

    pub fn first_point(&self) -> Target {
        self.shift
    }

    pub fn gen<F: RicherField + Extendable<D>, const D: usize>(
        &self,
        cb: &mut CircuitBuilder<F, D>,
    ) -> Target {
        assert!(self.log_n <= Self::TWO_ADICITY);

        let base = cb.constant(F::from_canonical_u64(1_753_635_133_440_165_772));
        cb.exp_power_of_2(base, Self::TWO_ADICITY - self.log_n)
    }

    pub fn next_point<F: RicherField + Extendable<D>, const D: usize>(
        &self,
        x: BinomialExtensionField<Target>,
        cb: &mut CircuitBuilder<F, D>,
    ) -> BinomialExtensionField<Target> {
        let gen = self.gen(cb);
        cb.p3_ext_mul_single(&x, gen)
    }

    pub fn natural_domain_for_degree<F: RicherField + Extendable<D>, const D: usize>(
        log_n_self: usize,
        degree: usize,
        cb: &mut CircuitBuilder<F, D>,
    ) -> TwoAdicMultiplicativeCoset {
        let log_n = log2_strict_usize(degree);
        assert!(log_n <= log_n_self);
        TwoAdicMultiplicativeCoset {
            log_n,
            shift: cb.one(),
        }
    }

    pub fn create_disjoint_domain<F: RicherField + Extendable<D>, const D: usize>(
        &self,
        min_size: usize,
        cb: &mut CircuitBuilder<F, D>,
    ) -> TwoAdicMultiplicativeCoset {
        let generator = cb.constant(F::from_canonical_u64(7));
        TwoAdicMultiplicativeCoset {
            log_n: log2_ceil_usize(min_size),
            shift: cb.mul(self.shift, generator),
        }
    }

    pub fn split_domains<F: RicherField + Extendable<D>, const D: usize>(
        &mut self,
        num_chunks: usize,
        cb: &mut CircuitBuilder<F, D>,
    ) -> Vec<TwoAdicMultiplicativeCoset> {
        let log_chunks = log2_strict_usize(num_chunks);
        let two_adicity_generator = self.gen(cb);

        (0..num_chunks)
            .map(|i| TwoAdicMultiplicativeCoset {
                log_n: self.log_n - log_chunks,
                shift: {
                    let two_adic_generator_powers_i = cb.exp_u64(two_adicity_generator, i as u64);
                    cb.mul(self.shift, two_adic_generator_powers_i)
                },
            })
            .collect()
    }

    pub fn selectors_at_point<F: RicherField + Extendable<D>, const D: usize>(
        &self,
        point: BinomialExtensionField<Target>,
        cb: &mut CircuitBuilder<F, D>,
    ) -> LagrangeSelectors<BinomialExtensionField<Target>> {
        let shift_inv = cb.inverse(self.shift);
        let unshifted_point = cb.p3_ext_mul_single(&point, shift_inv);
        let unshifted_point_exp_log_n =
            cb.p3_ext_exp_power_of_2(unshifted_point.clone(), self.log_n);
        let one = cb.p3_ext_one();

        let z_h = cb.p3_ext_sub(unshifted_point_exp_log_n, one.clone());

        let unshifted_point_minus_one = cb.p3_ext_sub(unshifted_point.clone(), one);
        let z_h_div_unshifted_point_minus_one =
            cb.p3_ext_div(z_h.clone(), unshifted_point_minus_one);

        let generator = self.gen(cb);
        let generator_inv = cb.inverse(generator);
        let unshifted_point_minus_generator_inv =
            cb.p3_ext_sub_single(unshifted_point, generator_inv.clone());
        let z_h_div_unshifted_point_minus_generator_inv =
            cb.p3_ext_div(z_h.clone(), unshifted_point_minus_generator_inv.clone());

        LagrangeSelectors {
            is_first_row: z_h_div_unshifted_point_minus_one,
            is_last_row: z_h_div_unshifted_point_minus_generator_inv,
            is_transition: unshifted_point_minus_generator_inv,
            inv_zeroifier: cb.p3_ext_inverse(z_h),
        }
    }

    pub fn zp_at_point<F: RicherField + Extendable<D>, const D: usize>(
        &self,
        point: BinomialExtensionField<Target>,
        cb: &mut CircuitBuilder<F, D>,
    ) -> BinomialExtensionField<Target> {
        let shift_inv = cb.inverse(self.shift);
        let point_mul_shift_inv = cb.p3_ext_mul_single(&point, shift_inv);
        let point_mul_shift_inv_powers_log_n =
            cb.p3_ext_exp_power_of_2(point_mul_shift_inv, self.log_n);
        let one = cb.p3_ext_one();
        cb.p3_ext_sub(point_mul_shift_inv_powers_log_n, one)
    }

    pub fn zp_at_single_point<F: RicherField + Extendable<D>, const D: usize>(
        &self,
        point: Target,
        cb: &mut CircuitBuilder<F, D>,
    ) -> Target {
        let shift_inv = cb.inverse(self.shift);
        let point_mul_shift_inv = cb.mul(shift_inv, point);
        let point_mul_shift_inv_powers_log_n = cb.exp_power_of_2(point_mul_shift_inv, self.log_n);
        let one = cb.one();
        cb.sub(point_mul_shift_inv_powers_log_n, one)
    }
}

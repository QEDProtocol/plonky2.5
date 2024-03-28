use plonky2::field::extension::Extendable;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::common::richer_field::RicherField;
use crate::p3::extension::CircuitBuilderP3ExtArithmetic;
use crate::p3::serde::proof::BinomialExtensionField;
use crate::p3::serde::proof::OpenedValues;

pub trait Air {
    fn name(&self) -> String;
    fn width(&self) -> usize;
    fn eval<F: RicherField + Extendable<D>, const D: usize>(
        &self,
        folder: &mut VerifierConstraintFolder<Target>,
        cb: &mut CircuitBuilder<F, D>,
    );
}

pub struct VerifierConstraintFolder<F> {
    pub main: OpenedValues<F>,
    pub is_first_row: BinomialExtensionField<F>,
    pub is_last_row: BinomialExtensionField<F>,
    pub is_transition: BinomialExtensionField<F>,
    pub alpha: BinomialExtensionField<F>,
    pub accumulator: BinomialExtensionField<F>,
}

pub struct FilteredAirBuilder<'a, F> {
    pub inner: &'a mut VerifierConstraintFolder<F>,
    pub condition: BinomialExtensionField<F>,
}

impl VerifierConstraintFolder<Target> {
    pub fn when<F: RicherField + Extendable<D>, const D: usize>(
        &mut self,
        condition: BinomialExtensionField<Target>,
    ) -> FilteredAirBuilder<Target> {
        FilteredAirBuilder {
            inner: self,
            condition: condition,
        }
    }

    pub fn when_first_row<F: RicherField + Extendable<D>, const D: usize>(
        &mut self,
    ) -> FilteredAirBuilder<Target> {
        self.when::<F, D>(self.is_first_row.clone())
    }

    pub fn when_last_row<F: RicherField + Extendable<D>, const D: usize>(
        &mut self,
    ) -> FilteredAirBuilder<Target> {
        self.when::<F, D>(self.is_last_row.clone())
    }

    pub fn when_transition<F: RicherField + Extendable<D>, const D: usize>(
        &mut self,
    ) -> FilteredAirBuilder<Target> {
        self.when::<F, D>(self.is_transition.clone())
    }

    pub fn assert_zero<F: RicherField + Extendable<D>, const D: usize>(
        &mut self,
        x: BinomialExtensionField<Target>,
        cb: &mut CircuitBuilder<F, D>,
    ) {
        self.accumulator = cb.p3_ext_mul_add(self.accumulator.clone(), self.alpha.clone(), x);
    }

    pub fn assert_eq<F: RicherField + Extendable<D>, const D: usize>(
        &mut self,
        x: BinomialExtensionField<Target>,
        y: BinomialExtensionField<Target>,
        cb: &mut CircuitBuilder<F, D>,
    ) {
        let x_sub_y = cb.p3_ext_sub(x, y);
        self.assert_zero(x_sub_y, cb)
    }

    pub fn assert_bool<F: RicherField + Extendable<D>, const D: usize>(
        &mut self,
        x: BinomialExtensionField<Target>,
        cb: &mut CircuitBuilder<F, D>,
    ) {
        let one = cb.p3_ext_one();
        let x_minus_one = cb.p3_ext_sub(x.clone(), one);
        let x_mul_x_minus_one = cb.p3_ext_mul(&x, &x_minus_one);

        self.assert_zero(x_mul_x_minus_one, cb);
    }
}

impl<'a> FilteredAirBuilder<'a, Target> {
    pub fn assert_zero<F: RicherField + Extendable<D>, const D: usize>(
        &mut self,
        x: BinomialExtensionField<Target>,
        cb: &mut CircuitBuilder<F, D>,
    ) {
        let x = cb.p3_ext_mul(&self.condition, &x);
        self.inner.assert_zero(x, cb)
    }

    pub fn assert_eq<F: RicherField + Extendable<D>, const D: usize>(
        &mut self,
        x: BinomialExtensionField<Target>,
        y: BinomialExtensionField<Target>,
        cb: &mut CircuitBuilder<F, D>,
    ) {
        let x_sub_y = cb.p3_ext_sub(x, y);
        let x = cb.p3_ext_mul(&self.condition, &x_sub_y);
        self.inner.assert_zero(x, cb)
    }

    pub fn assert_bool<F: RicherField + Extendable<D>, const D: usize>(
        &mut self,
        x: BinomialExtensionField<Target>,
        cb: &mut CircuitBuilder<F, D>,
    ) {
        let x = cb.p3_ext_mul(&self.condition, &x);
        self.inner.assert_bool(x, cb)
    }
}

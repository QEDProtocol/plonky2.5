use plonky2::field::types::{Field, PrimeField64};
use plonky2::iop::generator::GeneratedValues;
use plonky2::iop::witness::{Witness, WitnessWrite};

use super::arithmetic_u32::U32Target;

pub trait WitnessU32<F: PrimeField64>: Witness<F> {
    fn set_u32_target(&mut self, target: U32Target, value: u32);
    fn get_u32_target(&self, target: U32Target) -> (u32, u32);
    fn set_u32_targets(&mut self, targets: &[U32Target], values: &[u32]);
}

impl<T: Witness<F>, F: PrimeField64> WitnessU32<F> for T {
    fn set_u32_target(&mut self, target: U32Target, value: u32) {
        self.set_target(target.0, F::from_canonical_u32(value));
    }

    fn get_u32_target(&self, target: U32Target) -> (u32, u32) {
        let x_u64 = self.get_target(target.0).to_canonical_u64();
        let low = x_u64 as u32;
        let high = (x_u64 >> 32) as u32;
        (low, high)
    }

    fn set_u32_targets(&mut self, targets: &[U32Target], values: &[u32]) {
        assert_eq!(
            targets.len(),
            values.len(),
            "set_u32_targets: targets and values must be the same length"
        );
        for (target, value) in targets.iter().zip(values.iter()) {
            self.set_u32_target(*target, *value)
        }
    }
}

pub trait GeneratedValuesU32<F: Field> {
    fn set_u32_target(&mut self, target: U32Target, value: u32);
}

impl<F: Field> GeneratedValuesU32<F> for GeneratedValues<F> {
    fn set_u32_target(&mut self, target: U32Target, value: u32) {
        self.set_target(target.0, F::from_canonical_u32(value))
    }
}

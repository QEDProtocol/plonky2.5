extern crate alloc;
use alloc::vec::Vec;

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use super::super::gadgets::arithmetic_u32::U32Target;

/// Bin32Target is an inefficient representation of 32x BoolTargets
/// Whenever possible, use interleaved_u32::B32Target instead
#[derive(Clone, Debug)]
pub struct Bin32Target {
    pub bits: Vec<BoolTarget>,
}

pub trait CircuitBuilderBU32<F: RichField + Extendable<D>, const D: usize> {
    // methods on Bin32Target
    fn xor_bin32(&mut self, a: &Bin32Target, b: &Bin32Target) -> Bin32Target;
    fn and_bin32(&mut self, a: &Bin32Target, b: &Bin32Target) -> Bin32Target;

    // conversion methods
    fn convert_u32_bin32(&mut self, a: U32Target) -> Bin32Target;
    fn convert_u64_bin64(&mut self, a: &[U32Target; 2]) -> [Bin32Target; 2];

    fn convert_bin32_u32(&mut self, a: Bin32Target) -> U32Target;
    fn convert_bin64_u64(&mut self, a: &[Bin32Target; 2]) -> [U32Target; 2];

    fn reverse_bin32(&mut self, a: Bin32Target) -> Bin32Target;
    fn reverse_bin64(&mut self, a: [Bin32Target; 2]) -> [Bin32Target; 2];

    fn connect_bin32(&mut self, a: Bin32Target, b: Bin32Target);
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderBU32<F, D>
    for CircuitBuilder<F, D>
{
    fn convert_u32_bin32(&mut self, a: U32Target) -> Bin32Target {
        Bin32Target {
            bits: self.split_le(a.0, 32),
        }
    }

    fn convert_u64_bin64(&mut self, a: &[U32Target; 2]) -> [Bin32Target; 2] {
        [self.convert_u32_bin32(a[0]), self.convert_u32_bin32(a[1])]
    }

    fn convert_bin32_u32(&mut self, a: Bin32Target) -> U32Target {
        U32Target(self.le_sum(a.bits.iter()))
    }

    fn convert_bin64_u64(&mut self, a: &[Bin32Target; 2]) -> [U32Target; 2] {
        [
            self.convert_bin32_u32(a[0].clone()),
            self.convert_bin32_u32(a[1].clone()),
        ]
    }

    fn reverse_bin32(&mut self, a: Bin32Target) -> Bin32Target {
        Bin32Target {
            bits: a.bits.iter().rev().cloned().collect(),
        }
    }

    fn reverse_bin64(&mut self, a: [Bin32Target; 2]) -> [Bin32Target; 2] {
        [
            Bin32Target {
                bits: a[1].bits.iter().rev().cloned().collect(),
            },
            Bin32Target {
                bits: a[0].bits.iter().rev().cloned().collect(),
            },
        ]
    }

    fn xor_bin32(&mut self, a: &Bin32Target, b: &Bin32Target) -> Bin32Target {
        Bin32Target {
            bits: a
                .bits
                .iter()
                .zip(b.bits.iter())
                .map(|(a, b)| {
                    // a ^ b := (a - b)^2
                    let s = self.sub(a.target, b.target);
                    BoolTarget::new_unsafe(self.mul(s, s))
                })
                .collect(),
        }
    }

    fn and_bin32(&mut self, a: &Bin32Target, b: &Bin32Target) -> Bin32Target {
        Bin32Target {
            bits: a
                .bits
                .iter()
                .zip(b.bits.iter())
                .map(|(a, b)| {
                    // a & b := a * b
                    BoolTarget::new_unsafe(self.mul(a.target, b.target))
                })
                .collect(),
        }
    }

    fn connect_bin32(&mut self, a: Bin32Target, b: Bin32Target) {
        for (a, b) in a.bits.iter().zip(b.bits.iter()) {
            self.connect(a.target, b.target);
        }
    }
}

#[cfg(test)]
mod tests {
    use plonky2::field::types::Field;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::iop::witness::WitnessWrite;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::GenericConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    use super::*;

    #[test]
    fn test_reverse_bin32() {
        let tests = [0x01234567u32, 0x23456701u32, 0x45670123u32];

        // build circuit once
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let input = builder.add_virtual_target();
        let input_bin32 = builder.convert_u32_bin32(U32Target(input));
        let expected = builder.add_virtual_target();
        let output = builder.reverse_bin32(input_bin32);
        let output = builder.convert_bin32_u32(output);
        builder.connect(output.0, expected);
        builder.register_public_input(output.0);
        let data = builder.build::<C>();

        for n in tests {
            let res = n.reverse_bits();

            // test circuit
            let mut pw = PartialWitness::new();
            pw.set_target(input, F::from_canonical_u32(n));
            pw.set_target(expected, F::from_canonical_u32(res));

            let proof = data.prove(pw).unwrap();

            println!("public inputs: {:?}", proof.public_inputs);
            assert!(data.verify(proof).is_ok());
        }
    }
}

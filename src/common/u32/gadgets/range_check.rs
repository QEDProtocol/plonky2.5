use alloc::vec;
use alloc::vec::Vec;

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use super::super::gadgets::arithmetic_u32::U32Target;
use super::super::gates::range_check_u32::U32RangeCheckGate;

pub fn range_check_u32_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    vals: Vec<U32Target>,
) {
    let num_input_limbs = vals.len();
    let gate = U32RangeCheckGate::<F, D>::new(num_input_limbs);
    let row = builder.add_gate(gate, vec![]);

    for (i, &val) in vals.iter().enumerate().take(num_input_limbs) {
        builder.connect(Target::wire(row, gate.wire_ith_input_limb(i)), val.0);
    }
}

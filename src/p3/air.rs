use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::p3::types::{
    BinomialExtensionTarget, CircuitBuilderP3ExtArithmetic, VerifierConstraintFolderTarget,
};

pub trait Air {
    fn name(&self) -> String;
    fn width(&self) -> usize;
    fn eval<F: RichField + Extendable<D>, const D: usize, const E: usize>(
        &self,
        folder: &mut VerifierConstraintFolderTarget<Target, E>,
        cb: &mut CircuitBuilder<F, D>,
    );
}

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

    fn eval<F: RichField + Extendable<D>, const D: usize, const E: usize>(
        &self,
        folder: &mut VerifierConstraintFolderTarget<Target, E>,
        cb: &mut CircuitBuilder<F, D>,
    ) {
        let local = FibnacciCols::<BinomialExtensionTarget<Target, E>> {
            a: folder.main.trace_local[0].clone(),
            b: folder.main.trace_local[1].clone(),
            c: folder.main.trace_local[2].clone(),
        };

        let next = FibnacciCols::<BinomialExtensionTarget<Target, E>> {
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

use plonky2::{
    field::extension::Extendable, iop::target::Target, plonk::circuit_builder::CircuitBuilder,
};

use crate::{common::richer_field::RicherField, p3::types::VerifierConstraintFolderTarget};

pub trait Air {
    fn name(&self) -> String;
    fn width(&self) -> usize;
    fn eval<F: RicherField + Extendable<D>, const D: usize, const E: usize>(
        &self,
        folder: &mut VerifierConstraintFolderTarget<Target, E>,
        cb: &mut CircuitBuilder<F, D>,
    );
}

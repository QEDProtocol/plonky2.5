use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::Witness},
    plonk::circuit_builder::CircuitBuilder,
};

pub trait CircuitBuilderP3Helper<F: RichField + Extendable<D>, const D: usize> {
    fn add_2d_vec_array_inputs(&mut self, rows: usize, cols: usize) -> Vec<Vec<Target>>;
    fn add_2d_vec_array_inputs_with_dims_vec(&mut self, dims: Vec<usize>) -> Vec<Vec<Target>>;
    fn add_2d_vec_array_inputs_with_dims<const N_ROWS: usize>(
        &mut self,
        dims: [usize; N_ROWS],
    ) -> Vec<Vec<Target>>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderP3Helper<F, D>
    for CircuitBuilder<F, D>
{
    fn add_2d_vec_array_inputs(&mut self, rows: usize, cols: usize) -> Vec<Vec<Target>> {
        (0..rows)
            .map(|_| (0..cols).map(|_| self.add_virtual_target()).collect())
            .collect()
    }

    fn add_2d_vec_array_inputs_with_dims_vec(&mut self, dims: Vec<usize>) -> Vec<Vec<Target>> {
        dims.iter()
            .map(|cols| (0..*cols).map(|_| self.add_virtual_target()).collect())
            .collect()
    }

    fn add_2d_vec_array_inputs_with_dims<const N_ROWS: usize>(
        &mut self,
        dims: [usize; N_ROWS],
    ) -> Vec<Vec<Target>> {
        dims.iter()
            .map(|cols| (0..*cols).map(|_| self.add_virtual_target()).collect())
            .collect()
    }
}

pub trait WitnessP3Helper<F: RichField> {
    fn set_2d_vec_array(&mut self, targets: &[Vec<Target>], values: &[Vec<F>]);
}
impl<F: RichField, W: Witness<F>> WitnessP3Helper<F> for W {
    fn set_2d_vec_array(&mut self, targets: &[Vec<Target>], values: &[Vec<F>]) {
        assert!(targets.len() == values.len());
        targets.iter().zip(values.iter()).for_each(|(t, v)| {
            assert!(t.len() == v.len());
            self.set_target_arr(t, v);
        });
    }
}

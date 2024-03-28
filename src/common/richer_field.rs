use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::RichField;

use crate::common::poseidon2::poseidon2::Poseidon2;

pub trait RicherField: RichField + Poseidon2 {}
impl RicherField for GoldilocksField {}

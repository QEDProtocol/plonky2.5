use std::cmp::Reverse;

use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::AlgebraicHasher;

use crate::common::poseidon2::poseidon2::Poseidon2Hash;
use crate::common::richer_field::RicherField;
use crate::p3::constants::CHUNK;
use crate::p3::constants::DIGEST_ELEMS;
use crate::p3::constants::N;
use crate::p3::constants::RATE;
use crate::p3::constants::WIDTH;
use crate::p3::serde::Dimensions;
use crate::p3::CircuitBuilderP3Arithmetic;

pub struct MerkleTreeMmcs;

impl MerkleTreeMmcs {
    pub fn hash_iter_slices<
        'a,
        H: AlgebraicHasher<F>,
        I,
        F: RicherField + Extendable<D>,
        const D: usize,
    >(
        input: I,
        cb: &mut CircuitBuilder<F, D>,
    ) -> [Target; DIGEST_ELEMS]
    where
        I: Iterator<Item = &'a [Target]>,
    {
        let mut state = cb.p3_arr::<WIDTH>();
        for input_chunk in &input.into_iter().flatten().chunks(RATE) {
            state
                .iter_mut()
                .zip(input_chunk)
                .for_each(|(s, i)| *s = i.clone());

            state = Poseidon2Hash::permute_targets::<F, D>(&state, cb);
        }
        state[..DIGEST_ELEMS].try_into().unwrap()
    }

    pub fn compress<H: AlgebraicHasher<F>, F: RicherField + Extendable<D>, const D: usize>(
        input: [[Target; CHUNK]; N],
        cb: &mut CircuitBuilder<F, D>,
    ) -> [Target; CHUNK] {
        let mut state = cb.p3_arr::<WIDTH>();
        for i in 0..N {
            state[i * CHUNK..(i + 1) * CHUNK].copy_from_slice(&input[i]);
        }

        state = Poseidon2Hash::permute_targets::<F, D>(&state, cb);

        state[..CHUNK].try_into().unwrap()
    }

    pub fn verify_batch<H: AlgebraicHasher<F>, F: RicherField + Extendable<D>, const D: usize>(
        commit: &Vec<Target>,
        dimensions: &[Dimensions],
        mut index: Target,
        opened_values: &Vec<Vec<Target>>,
        proof: &Vec<Vec<Target>>,
        cb: &mut CircuitBuilder<F, D>,
    ) -> Result<(), ()> {
        let mut heights_tallest_first = dimensions
            .iter()
            .enumerate()
            .sorted_by_key(|(_, dims)| Reverse(dims.height))
            .peekable();

        let mut curr_height_padded = heights_tallest_first
            .peek()
            .unwrap()
            .1
            .height
            .next_power_of_two();

        let mut root = Self::hash_iter_slices::<H, _, F, D>(
            heights_tallest_first
                .peeking_take_while(|(_, dims)| {
                    dims.height.next_power_of_two() == curr_height_padded
                })
                .map(|(i, _)| opened_values[i].as_slice()),
            cb,
        );

        for sibling in proof.iter() {
            let one = cb.one();
            let index_and_one = cb.p3_and(index, one);
            let is_odd = BoolTarget::new_unsafe(index_and_one);
            let mut left = cb.p3_arr::<DIGEST_ELEMS>();
            let mut right = cb.p3_arr::<DIGEST_ELEMS>();

            for i in 0..DIGEST_ELEMS {
                left[i] = cb._if(is_odd, sibling[i], root[i]);
                right[i] = cb._if(is_odd, root[i], sibling[i]);
            }

            root = Self::compress::<H, F, D>([left, right], cb);
            index = cb.p3_rsh(index, 1);

            curr_height_padded >>= 1;

            let next_height = heights_tallest_first
                .peek()
                .map(|(_, dims)| dims.height)
                .filter(|h| h.next_power_of_two() == curr_height_padded);
            if let Some(next_height) = next_height {
                let next_height_openings_digest = Self::hash_iter_slices::<H, _, F, D>(
                    heights_tallest_first
                        .peeking_take_while(|(_, dims)| dims.height == next_height)
                        .map(|(i, _)| opened_values[i].as_slice()),
                    cb,
                );

                root = Self::compress::<H, F, D>([root, next_height_openings_digest], cb);
            }
        }

        for (x, y) in commit.iter().zip(root.iter()) {
            cb.connect(x.clone(), y.clone());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    use super::*;

    #[test]
    fn test_hash_iter_slice() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = GoldilocksField;
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);

        let arr = [builder.zero(); 4];

        let res = MerkleTreeMmcs::hash_iter_slices::<PoseidonHash, _, F, D>(
            [arr.as_ref(); 2].iter().map(|x| *x),
            &mut builder,
        );

        builder.register_public_inputs(&res);

        let data = builder.build::<C>();

        let pw = PartialWitness::new();

        let start_time = std::time::Instant::now();
        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("demo proved in {}ms", duration_ms);
        println!("proof public_inputs: {:?}", proof.public_inputs);

        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_compress() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = GoldilocksField;
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);

        let res =
            MerkleTreeMmcs::compress::<PoseidonHash, F, D>([[builder.zero(); 4]; 2], &mut builder);

        builder.register_public_inputs(&res);

        let data = builder.build::<C>();

        let pw = PartialWitness::new();

        let start_time = std::time::Instant::now();
        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("demo proved in {}ms", duration_ms);
        println!("proof public_inputs: {:?}", proof.public_inputs);

        assert!(data.verify(proof).is_ok());
    }
}

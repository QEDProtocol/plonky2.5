use crate::p3::{
    constants::EXT_DEGREE,
    serde::{BatchOpening, BinomialExtensionField, Goldilocks, OpenedValues, QueryProof},
    types::{
        BatchOpeningTarget, BinomialExtensionTarget, CommitPhaseProofStepTarget,
        OpenedValuesTarget, QueryProofTarget,
    },
    CircuitBuilderP3Arithmetic,
};
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};

#[must_use]
#[inline]
pub fn log2_strict_usize(n: usize) -> usize {
    let res = n.trailing_zeros();
    assert_eq!(n.wrapping_shr(res), 1, "Not a power of two: {n}");
    res as usize
}

#[must_use]
pub fn log2_ceil_usize(n: usize) -> usize {
    (usize::BITS - n.saturating_sub(1).leading_zeros()) as usize
}

#[inline]
pub const fn reverse_bits(x: usize, n: usize) -> usize {
    reverse_bits_len(x, n.trailing_zeros() as usize)
}

#[inline]
pub const fn reverse_bits_len(x: usize, bit_len: usize) -> usize {
    // NB: The only reason we need overflowing_shr() here as opposed
    // to plain '>>' is to accommodate the case n == num_bits == 0,
    // which would become `0 >> 64`. Rust thinks that any shift of 64
    // bits causes overflow, even when the argument is zero.
    x.reverse_bits()
        .overflowing_shr(usize::BITS - bit_len as u32)
        .0
}

pub fn reverse_slice_index_bits<F>(vals: &mut [F]) {
    let n = vals.len();
    if n == 0 {
        return;
    }
    let log_n = log2_strict_usize(n);

    for i in 0..n {
        let j = reverse_bits_len(i, log_n);
        if i < j {
            vals.swap(i, j);
        }
    }
}

pub fn binomial_extension_field_to_target<F: RichField + Extendable<D>, const D: usize>(
    value: BinomialExtensionField<Goldilocks>,
    cb: &mut CircuitBuilder<F, D>,
) -> BinomialExtensionTarget<Target, EXT_DEGREE> {
    BinomialExtensionTarget {
        value: value.value.map(|x| cb.p3_constant(x.value)),
    }
}

pub fn batch_opening_to_target<F: RichField + Extendable<D>, const D: usize>(
    value: BatchOpening<Goldilocks>,
    cb: &mut CircuitBuilder<F, D>,
) -> BatchOpeningTarget<Target> {
    BatchOpeningTarget {
        opened_values: value
            .opened_values
            .into_iter()
            .map(|x| {
                x.into_iter()
                    .map(|x| cb.p3_constant(x.value))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
        opening_proof: value
            .opening_proof
            .into_iter()
            .map(|x| {
                x.into_iter()
                    .map(|x| cb.p3_constant(x.value))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
    }
}

pub fn query_proof_to_target<F: RichField + Extendable<D>, const D: usize>(
    value: QueryProof<Goldilocks>,
    cb: &mut CircuitBuilder<F, D>,
) -> QueryProofTarget<Target, EXT_DEGREE> {
    QueryProofTarget {
        commit_phase_openings: value
            .commit_phase_openings
            .into_iter()
            .map(|x| CommitPhaseProofStepTarget {
                sibling_value: binomial_extension_field_to_target(x.sibling_value, cb),
                opening_proof: x
                    .opening_proof
                    .into_iter()
                    .map(|x| {
                        x.into_iter()
                            .map(|x| cb.p3_constant(x.value))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>(),
            })
            .collect::<Vec<_>>(),
    }
}

pub fn opened_values_to_target<F: RichField + Extendable<D>, const D: usize>(
    values: OpenedValues<Goldilocks>,
    cb: &mut CircuitBuilder<F, D>,
) -> OpenedValuesTarget<Target, EXT_DEGREE> {
    OpenedValuesTarget {
        trace_local: values
            .trace_local
            .into_iter()
            .map(|x| binomial_extension_field_to_target::<F, D>(x, cb))
            .collect::<Vec<_>>(),
        trace_next: values
            .trace_next
            .into_iter()
            .map(|x| binomial_extension_field_to_target::<F, D>(x, cb))
            .collect::<Vec<_>>(),
        quotient_chunks: values
            .quotient_chunks
            .into_iter()
            .map(|x| {
                x.into_iter()
                    .map(|y| binomial_extension_field_to_target::<F, D>(y, cb))
                    .collect()
            })
            .collect::<Vec<_>>(),
    }
}

use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::Witness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use serde::Deserialize;
use serde::Serialize;

use crate::common::richer_field::RicherField;
use crate::p3::constants::DIGEST_ELEMS;
use crate::p3::constants::EXT_DEGREE;
use crate::p3::gadgets::CircuitBuilderP3Helper;
use crate::p3::gadgets::WitnessP3Helper;
use crate::p3::serde::fri::FriConfig;

#[derive(Copy, Clone, Default, Serialize, Deserialize)]
pub struct Value<F> {
    pub value: F,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenedValues<F> {
    pub trace_local: Vec<BinomialExtensionField<F>>,
    pub trace_next: Vec<BinomialExtensionField<F>>,
    pub quotient_chunks: Vec<Vec<BinomialExtensionField<F>>>,
}

impl OpenedValues<Target> {
    pub fn add_virtual_to<F: RicherField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        trace_width: usize,
    ) -> Self {
        let trace_local = (0..trace_width)
            .map(|_| BinomialExtensionField::add_virtual_to(builder))
            .collect();

        let trace_next = (0..trace_width)
            .map(|_| BinomialExtensionField::add_virtual_to(builder))
            .collect();

        let quotient_chunks = (0..1)
            .map(|_| {
                let a = BinomialExtensionField::add_virtual_to(builder);
                let b = BinomialExtensionField::add_virtual_to(builder);
                let r = vec![a, b];
                r
            })
            .collect();

        Self {
            trace_local,
            trace_next,
            quotient_chunks,
        }
    }

    pub fn set_witness<F: RicherField + Extendable<D>, const D: usize, W: Witness<F>>(
        &self,
        witness: &mut W,
        data: &OpenedValues<F>,
    ) {
        for i in 0..self.trace_local.len() {
            self.trace_local[i].set_witness(witness, &data.trace_local[i]);
            self.trace_next[i].set_witness(witness, &data.trace_next[i]);
        }
        for i in 0..self.quotient_chunks.len() {
            self.quotient_chunks[i][0].set_witness(witness, &data.quotient_chunks[i][0]);
            self.quotient_chunks[i][1].set_witness(witness, &data.quotient_chunks[i][1]);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitments<F> {
    pub trace: Commitment<F>,
    pub quotient_chunks: Commitment<F>,
}

impl Commitments<Target> {
    pub fn add_virtual_to<F: RicherField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            trace: Commitment::add_virtual_to(builder),
            quotient_chunks: Commitment::add_virtual_to(builder),
        }
    }

    pub fn set_witness<F: RicherField + Extendable<D>, const D: usize, W: Witness<F>>(
        &self,
        witness: &mut W,
        data: &Commitments<F>,
    ) {
        self.trace.set_witness(witness, &data.trace);
        self.quotient_chunks
            .set_witness(witness, &data.quotient_chunks);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinomialExtensionField<F> {
    pub value: [F; EXT_DEGREE],
}

impl BinomialExtensionField<Target> {
    pub fn add_virtual_to<F: RicherField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            value: core::array::from_fn(|_| builder.add_virtual_target()),
        }
    }
    pub fn set_witness<F: RicherField + Extendable<D>, const D: usize, W: Witness<F>>(
        &self,
        witness: &mut W,
        data: &BinomialExtensionField<F>,
    ) {
        (0..EXT_DEGREE).for_each(|i| witness.set_target(self.value[i], data.value[i]));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitment<F> {
    pub value: [F; DIGEST_ELEMS],
}

impl Commitment<Target> {
    pub fn add_virtual_to<F: RicherField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            value: core::array::from_fn(|_| builder.add_virtual_target()),
        }
    }
    pub fn set_witness<F: RicherField + Extendable<D>, const D: usize, W: Witness<F>>(
        &self,
        witness: &mut W,
        data: &Commitment<F>,
    ) {
        (0..DIGEST_ELEMS).for_each(|i| witness.set_target(self.value[i], data.value[i]));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriProof<F> {
    pub commit_phase_commits: Vec<Commitment<F>>,
    pub query_proofs: Vec<QueryProof<F>>,
    // This could become Vec<FC::Challenge> if this library was generalized to support non-constant
    // final polynomials.
    pub final_poly: BinomialExtensionField<F>,
    pub pow_witness: F,
}

impl FriProof<Target> {
    pub fn add_virtual_to<F: RicherField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        config: &P3Config,
    ) -> Self {
        let commit_phase_commits = (0..config.log_trace_height)
            .map(|_| Commitment::add_virtual_to(builder))
            .collect();
        let query_proofs = (0..config.fri_config.num_queries)
            .map(|_| QueryProof::add_virtual_to(builder, config.log_trace_height))
            .collect();
        let final_poly = BinomialExtensionField::add_virtual_to(builder);
        let pow_witness = builder.add_virtual_target();

        Self {
            commit_phase_commits,
            query_proofs,
            final_poly,
            pow_witness,
        }
    }

    pub fn set_witness<F: RicherField + Extendable<D>, const D: usize, W: Witness<F>>(
        &self,
        witness: &mut W,
        data: &FriProof<F>,
    ) {
        for i in 0..self.commit_phase_commits.len() {
            self.commit_phase_commits[i].set_witness(witness, &data.commit_phase_commits[i]);
        }
        for i in 0..self.query_proofs.len() {
            self.query_proofs[i].set_witness(witness, &data.query_proofs[i]);
        }
        self.final_poly.set_witness(witness, &data.final_poly);
        witness.set_target(self.pow_witness, data.pow_witness);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryProof<F> {
    /// For each commit phase commitment, this contains openings of a commit
    /// phase codeword at the queried location, along with an opening proof.
    pub commit_phase_openings: Vec<CommitPhaseProofStep<F>>,
}

impl QueryProof<Target> {
    pub fn add_virtual_to<F: RicherField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        log_trace_height: usize,
    ) -> Self {
        let commit_phase_openings = (0..log_trace_height)
            .map(|i| CommitPhaseProofStep::add_virtual_to(builder, log_trace_height - i))
            .collect();

        Self {
            commit_phase_openings,
        }
    }

    pub fn set_witness<F: RicherField + Extendable<D>, const D: usize, W: Witness<F>>(
        &self,
        witness: &mut W,
        data: &QueryProof<F>,
    ) {
        for i in 0..self.commit_phase_openings.len() {
            self.commit_phase_openings[i].set_witness(witness, &data.commit_phase_openings[i]);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitPhaseProofStep<F> {
    /// The opening of the commit phase codeword at the sibling location.
    // This may change to Vec<FC::Challenge> if the library is generalized to support other FRI
    // folding arities besides 2, meaning that there can be multiple siblings.
    pub sibling_value: BinomialExtensionField<F>,

    pub opening_proof: Vec<Vec<F>>,
}

impl CommitPhaseProofStep<Target> {
    pub fn add_virtual_to<F: RicherField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        log_trace_height_minus_i: usize,
    ) -> Self {
        let sibling_value = BinomialExtensionField::add_virtual_to(builder);
        let opening_proof = (0..log_trace_height_minus_i)
            .map(|_| builder.add_virtual_targets(DIGEST_ELEMS))
            .collect();
        Self {
            opening_proof,
            sibling_value,
        }
    }

    pub fn set_witness<F: RicherField + Extendable<D>, const D: usize, W: Witness<F>>(
        &self,
        witness: &mut W,
        data: &CommitPhaseProofStep<F>,
    ) {
        self.sibling_value.set_witness(witness, &data.sibling_value);
        for i in 0..self.opening_proof.len() {
            for j in 0..self.opening_proof[i].len() {
                witness.set_target(self.opening_proof[i][j], data.opening_proof[i][j]);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchOpening<F> {
    pub opened_values: Vec<Vec<F>>,
    pub opening_proof: Vec<Vec<F>>,
}

impl BatchOpening<Target> {
    pub fn add_virtual_to<F: RicherField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        opened_values_row_count: usize,
        opened_values_col_count: usize,
        opening_matrix_log_max_height: usize,
    ) -> Self {
        let opened_values =
            builder.add_2d_vec_array_inputs(opened_values_row_count, opened_values_col_count);
        let opening_proof = (0..opening_matrix_log_max_height)
            .map(|_| builder.add_virtual_hash().elements.to_vec())
            .collect();

        Self {
            opened_values,
            opening_proof,
        }
    }

    pub fn set_witness<F: RicherField, W: Witness<F>>(
        &self,
        witness: &mut W,
        data: &BatchOpening<F>,
    ) {
        witness.set_2d_vec_array(&self.opened_values, &data.opened_values);
        witness.set_2d_vec_array(&self.opening_proof, &data.opening_proof);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoAdicFriPcsProof<F> {
    pub fri_proof: FriProof<F>,
    /// For each query, for each committed batch, query openings for that batch
    pub query_openings: Vec<Vec<BatchOpening<F>>>,
}

impl TwoAdicFriPcsProof<Target> {
    pub fn add_virtual_to<F: RicherField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        config: &P3Config,
    ) -> Self {
        let fri_proof = FriProof::add_virtual_to(builder, config);
        let query_openings = (0..config.fri_config.num_queries)
            .map(|_| {
                vec![
                    BatchOpening::add_virtual_to(
                        builder,
                        1,
                        config.trace_width,
                        config.opening_matrix_log_max_height,
                    ),
                    BatchOpening::add_virtual_to(
                        builder,
                        1,
                        config.opening_proof_query_openings_opened_values_length,
                        config.opening_matrix_log_max_height,
                    ),
                ]
            })
            .collect();

        Self {
            fri_proof,
            query_openings,
        }
    }
    pub fn set_witness<F: RicherField + Extendable<D>, const D: usize, W: Witness<F>>(
        &self,
        witness: &mut W,
        data: &TwoAdicFriPcsProof<F>,
    ) {
        self.fri_proof.set_witness(witness, &data.fri_proof);
        for i in 0..self.query_openings.len() {
            for j in 0..self.query_openings[i].len() {
                self.query_openings[i][j].set_witness(witness, &data.query_openings[i][j]);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<F> {
    pub commitments: Commitments<F>,
    pub opened_values: OpenedValues<F>,
    pub opening_proof: TwoAdicFriPcsProof<F>,
    pub degree_bits: usize,
}

impl Proof<Target> {
    pub fn add_virtual_to<F: RicherField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        config: &P3Config,
    ) -> Self {
        let commitments = Commitments::add_virtual_to(builder);
        let opened_values = OpenedValues::add_virtual_to(builder, config.trace_width);
        let opening_proof = TwoAdicFriPcsProof::add_virtual_to(builder, config);
        let degree_bits = config.degree_bits;

        Self {
            commitments,
            opened_values,
            opening_proof,
            degree_bits,
        }
    }
    pub fn set_witness<F: RicherField + Extendable<D>, const D: usize, W: Witness<F>>(
        &self,
        witness: &mut W,
        data: &Proof<F>,
    ) {
        self.commitments.set_witness(witness, &data.commitments);
        self.opened_values.set_witness(witness, &data.opened_values);
        self.opening_proof.set_witness(witness, &data.opening_proof);
    }
}

pub type P3Field = Value<GoldilocksField>;
pub type P3ProofField = Proof<P3Field>;
pub type P3OpenedValuesField = OpenedValues<P3Field>;
pub type P3TwoAdicFriPcsProofField = TwoAdicFriPcsProof<P3Field>;
pub type P3CommitmentsField = Commitments<P3Field>;
pub type P3FriProofField = FriProof<P3Field>;
pub type P3BinomialExtensionField = BinomialExtensionField<P3Field>;
pub type P3CommitmentField = Commitment<P3Field>;

pub type P3Proof = Proof<Target>;
pub type P3OpenedValues = OpenedValues<Target>;
pub type P3TwoAdicFriPcsProof = TwoAdicFriPcsProof<Target>;
pub type P3Commitments = Commitments<Target>;
pub type P3FriProof = FriProof<Target>;
pub type P3BinomialExtension = BinomialExtensionField<Target>;
pub type P3Commitment = Commitment<Target>;

#[derive(Debug)]
pub struct P3Config {
    pub fri_config: FriConfig,
    pub log_quotient_degree: usize,
    pub log_trace_height: usize,
    pub trace_width: usize,
    pub opening_matrix_log_max_height: usize,
    pub opening_proof_query_openings_opened_values_length: usize,
    pub degree_bits: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_test() {
        let s = include_str!("../../../artifacts/proof_fibonacci.json");
        serde_json::from_str::<P3ProofField>(s).unwrap();
    }
}

use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Default, Serialize, Deserialize)]
pub struct Goldilocks {
    pub value: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenedValues<F> {
    pub trace_local: Vec<BinomialExtensionField<F>>,
    pub trace_next: Vec<BinomialExtensionField<F>>,
    pub quotient_chunks: Vec<Vec<BinomialExtensionField<F>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitments<F> {
    pub trace: Commitment<F>,
    pub quotient_chunks: Commitment<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinomialExtensionField<F> {
    pub value: [F; 2],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitment<F> {
    pub value: [F; 4],
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryProof<F> {
    /// For each commit phase commitment, this contains openings of a commit phase codeword at the
    /// queried location, along with an opening proof.
    pub commit_phase_openings: Vec<CommitPhaseProofStep<F>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitPhaseProofStep<F> {
    /// The opening of the commit phase codeword at the sibling location.
    // This may change to Vec<FC::Challenge> if the library is generalized to support other FRI
    // folding arities besides 2, meaning that there can be multiple siblings.
    pub sibling_value: BinomialExtensionField<F>,

    pub opening_proof: Vec<Vec<F>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchOpening<F> {
    pub opened_values: Vec<Vec<F>>,
    pub opening_proof: Vec<Vec<F>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoAdicFriPcsProof<F> {
    pub fri_proof: FriProof<F>,
    /// For each query, for each committed batch, query openings for that batch
    pub query_openings: Vec<Vec<BatchOpening<F>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<F> {
    pub commitments: Commitments<F>,
    pub opened_values: OpenedValues<F>,
    pub opening_proof: TwoAdicFriPcsProof<F>,
    pub degree_bits: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_test() {
        let s = include_str!("proof_fibonacci.json");
        serde_json::from_str::<Proof<Goldilocks>>(s).unwrap();
    }
}

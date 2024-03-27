use crate::p3::serde::proof::BinomialExtensionField;

#[derive(Debug)]
pub struct FriConfig {
    pub log_blowup: usize,
    pub num_queries: usize,
    pub proof_of_work_bits: usize,
}

pub struct FriChallenges<F> {
    pub query_indices: Vec<F>,
    pub betas: Vec<BinomialExtensionField<F>>,
}

#[derive(Debug, Clone)]
pub enum FriError {
    InvalidProofShape,
    CommitPhaseMmcsError,
    FinalPolyMismatch,
    InvalidPowWitness,
}

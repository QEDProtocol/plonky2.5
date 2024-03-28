use itertools::izip;
use plonky2::field::extension::Extendable;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::AlgebraicHasher;

use crate::common::richer_field::RicherField;
use crate::p3::air::Air;
use crate::p3::air::VerifierConstraintFolder;
use crate::p3::challenger::DuplexChallenger;
use crate::p3::challenger::DuplexChallengerTarget;
use crate::p3::commit;
use crate::p3::constants::EXT_DEGREE;
use crate::p3::extension::CircuitBuilderP3ExtArithmetic;
use crate::p3::serde::fri::FriChallenges;
use crate::p3::serde::fri::FriConfig;
use crate::p3::serde::fri::FriError;
use crate::p3::serde::proof::BinomialExtensionField;
use crate::p3::serde::proof::Commitment;
use crate::p3::serde::proof::FriProof;
use crate::p3::serde::proof::P3Config;
use crate::p3::serde::proof::P3Proof;
use crate::p3::serde::proof::QueryProof;
use crate::p3::serde::proof::TwoAdicFriPcsProof;
use crate::p3::serde::two_adic::TwoAdicMultiplicativeCoset;
use crate::p3::serde::Dimensions;
use crate::p3::utils::log2_strict_usize;
use crate::p3::CircuitBuilderP3Arithmetic;

pub trait CircuitBuilderP3Verifier<F: RicherField + Extendable<D>, const D: usize>:
    CircuitBuilderP3ExtArithmetic<F, D>
{
    fn __p3_verify_proof__<H: AlgebraicHasher<F>>(
        &mut self,
        air: &impl Air,
        proof: P3Proof,
        config: &P3Config,
        challenger: &mut DuplexChallengerTarget,
    );

    fn p3_verify_shape_and_sample_challenges<H: AlgebraicHasher<F>>(
        &mut self,
        config: &FriConfig,
        proof: &FriProof<Target>,
        challenger: &mut DuplexChallengerTarget,
    ) -> Result<FriChallenges<Target>, FriError>;

    fn p3_verify_opening_proof<H: AlgebraicHasher<F>>(
        &mut self,
        config: &FriConfig,
        commits_and_points: Vec<(
            Commitment<Target>,
            Vec<(
                TwoAdicMultiplicativeCoset,
                Vec<(
                    BinomialExtensionField<Target>,
                    Vec<BinomialExtensionField<Target>>,
                )>,
            )>,
        )>,
        proof: TwoAdicFriPcsProof<Target>,
        challenger: &mut DuplexChallengerTarget,
    ) -> Result<(), ()>;

    fn p3_verify_batch<H: AlgebraicHasher<F>>(
        &mut self,
        commit: &Vec<Target>,
        dimensions: &[Dimensions],
        index: Target,
        opened_values: &Vec<Vec<Target>>,
        proof: &Vec<Vec<Target>>,
    ) -> Result<(), ()>;

    fn p3_verify_challenges<H: AlgebraicHasher<F>>(
        &mut self,
        config: &FriConfig,
        proof: &FriProof<Target>,
        challenges: &FriChallenges<Target>,
        reduced_openings: &[[BinomialExtensionField<Target>; 32]],
    ) -> Result<(), ()>;

    fn p3_verify_query<H: AlgebraicHasher<F>>(
        &mut self,
        _config: &FriConfig,
        commit_phase_commits: &Vec<Commitment<Target>>,
        index: Target,
        proof: &QueryProof<Target>,
        betas: &[BinomialExtensionField<Target>],
        reduced_openings: &[BinomialExtensionField<Target>; 32],
        log_max_height: usize,
    ) -> Result<BinomialExtensionField<Target>, ()>;
}

impl<F: RicherField + Extendable<D>, const D: usize> CircuitBuilderP3Verifier<F, D>
    for CircuitBuilder<F, D>
where
    Self: CircuitBuilderP3ExtArithmetic<F, D>,
{
    fn __p3_verify_proof__<H: AlgebraicHasher<F>>(
        &mut self,
        air: &impl Air,
        proof: P3Proof,
        config: &P3Config,
        challenger: &mut DuplexChallengerTarget,
    ) {
        let P3Proof {
            commitments,
            opened_values,
            opening_proof,
            degree_bits,
        } = proof;

        let degree = 1 << degree_bits;
        let quotient_degree = 1 << config.log_quotient_degree;

        let trace_domain = TwoAdicMultiplicativeCoset::natural_domain_for_degree(
            config.log_trace_height,
            degree,
            self,
        );
        let mut quotient_domain = trace_domain
            .create_disjoint_domain(1 << (degree_bits + config.log_quotient_degree), self);
        let quotient_chunks_domains = quotient_domain.split_domains::<F, D>(quotient_degree, self);

        let air_width = air.width();
        let valid_shape = opened_values.trace_local.len() == air_width
            && opened_values.trace_next.len() == air_width
            && opened_values.quotient_chunks.len() == quotient_degree
            && opened_values.quotient_chunks.iter().all(|qc| qc.len() == D);
        if !valid_shape {
            panic!("Invalid Proof Shape");
        }

        self.p3_observe::<H>(challenger, commitments.trace.value.clone());
        let alpha = self.p3_sample_ext::<H>(challenger);
        self.p3_observe::<H>(challenger, commitments.quotient_chunks.value.clone());

        let zeta = self.p3_sample_ext::<H>(challenger);
        let zeta_next = trace_domain.next_point(zeta.clone(), self);

        self.p3_verify_opening_proof::<H>(
            &config.fri_config,
            vec![
                (
                    commitments.trace.clone(),
                    vec![(
                        trace_domain,
                        vec![
                            (zeta.clone(), opened_values.trace_local.clone()),
                            (zeta_next, opened_values.trace_next.clone()),
                        ],
                    )],
                ),
                (
                    commitments.quotient_chunks.clone(),
                    quotient_chunks_domains
                        .iter()
                        .zip(&opened_values.quotient_chunks)
                        .map(|(domain, values)| (*domain, vec![(zeta.clone(), values.clone())]))
                        .collect(),
                ),
            ],
            opening_proof,
            challenger,
        )
        .unwrap();

        let zps: Vec<BinomialExtensionField<Target>> = quotient_chunks_domains
            .iter()
            .enumerate()
            .map(|(i, domain)| {
                quotient_chunks_domains
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, other_domain)| {
                        // ((z*g/shift)^n - 1) / (g / shift)
                        let other_domain_zeta = other_domain.zp_at_point(zeta.clone(), self);
                        let first_point = domain.first_point();
                        let other_domain_first_point =
                            other_domain.zp_at_single_point(first_point, self);
                        let other_domain_first_point_inv = self.inverse(other_domain_first_point);

                        self.p3_ext_mul_single(&other_domain_zeta, other_domain_first_point_inv)
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .reduce(|acc, e| self.p3_ext_mul(&acc, &e))
                    .unwrap_or({
                        let one = self.one();
                        BinomialExtensionField::<Target> {
                            value: self.p3_field_to_arr(one),
                        }
                    })
            })
            .collect();

        let quotient = opened_values
            .quotient_chunks
            .iter()
            .enumerate()
            .map(|(ch_i, ch)| {
                ch.iter()
                    .enumerate()
                    .map(|(e_i, c)| {
                        let monomial = self.p3_ext_monomial(e_i);
                        let monomial_mul_c = self.p3_ext_mul(&monomial, &c);
                        self.p3_ext_mul(&zps[ch_i], &monomial_mul_c)
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .reduce(|acc, e| self.p3_ext_add(acc, e))
                    .unwrap()
            })
            .collect::<Vec<_>>()
            .into_iter()
            .reduce(|acc, e| self.p3_ext_add(acc, e))
            .unwrap();

        let sels = trace_domain.selectors_at_point(zeta, self);

        let mut folder = VerifierConstraintFolder {
            main: opened_values,
            is_first_row: sels.is_first_row,
            is_last_row: sels.is_last_row,
            is_transition: sels.is_transition,
            alpha,
            accumulator: self.p3_ext_zero(),
        };

        air.eval(&mut folder, self);

        let folded_constraints = folder.accumulator;

        let folded_constraints_mul_sels_inv_zeroifier =
            self.p3_ext_mul(&folded_constraints, &sels.inv_zeroifier);

        self.connect_p3_ext(&folded_constraints_mul_sels_inv_zeroifier, &quotient);
    }

    fn p3_verify_opening_proof<H: AlgebraicHasher<F>>(
        &mut self,
        config: &FriConfig,
        commits_and_points: Vec<(
            Commitment<Target>,
            Vec<(
                TwoAdicMultiplicativeCoset,
                Vec<(
                    BinomialExtensionField<Target>,
                    Vec<BinomialExtensionField<Target>>,
                )>,
            )>,
        )>,
        proof: TwoAdicFriPcsProof<Target>,
        challenger: &mut DuplexChallengerTarget,
    ) -> Result<(), ()> {
        let alpha = self.p3_sample_ext::<H>(challenger);

        let fri_challenges = self
            .p3_verify_shape_and_sample_challenges::<H>(config, &proof.fri_proof, challenger)
            .unwrap();

        let log_max_height = proof.fri_proof.commit_phase_commits.len() + config.log_blowup;

        let reduced_openings: Vec<[BinomialExtensionField<Target>; 32]> = proof
            .query_openings
            .iter()
            .zip(&fri_challenges.query_indices)
            .map(|(query_opening, &index)| {
                let mut ro = self.p3_ext_arr::<32>();
                let one = self.p3_ext_one();
                let mut alpha_pow: [BinomialExtensionField<Target>; 32] =
                    self.p3_ext_arr_fn(|_| one.clone());

                for (batch_opening, (batch_commit, mats)) in
                    izip!(query_opening, &commits_and_points)
                {
                    let batch_dims: Vec<Dimensions> = mats
                        .iter()
                        .map(|(domain, _)| Dimensions {
                            // todo: mmcs doesn't really need width
                            width: 0,
                            height: domain.size(),
                        })
                        .collect();

                    self.p3_verify_batch::<H>(
                        &batch_commit.value.to_vec(),
                        &batch_dims,
                        index,
                        &batch_opening.opened_values,
                        &batch_opening.opening_proof,
                    )?;

                    for (mat_opening, (mat_domain, mat_points_and_values)) in
                        izip!(&batch_opening.opened_values, mats)
                    {
                        let log_height = log2_strict_usize(mat_domain.size()) + config.log_blowup;

                        let bits_reduced = log_max_height - log_height;
                        let index_right_shifted = self.p3_rsh(index, bits_reduced as u8);
                        let rev_reduced_index =
                            self.reverse_p3_bits_len(index_right_shifted, log_height);

                        let generator = self.p3_w();
                        let two_adic_generator = self.p3_two_adic_generator(log_height);
                        let two_adic_generator_powers_rev_reduced_index =
                            self.exp(two_adic_generator, rev_reduced_index, 64);

                        let x = self.mul(generator, two_adic_generator_powers_rev_reduced_index);

                        for (z, ps_at_z) in mat_points_and_values {
                            for (p_at_x, p_at_z) in izip!(mat_opening, ps_at_z) {
                                let p_at_z_neg = self.p3_ext_neg(p_at_z.clone());
                                let z_neg = self.p3_ext_neg(z.clone());
                                let p_at_z_plus_p_at_x =
                                    self.p3_ext_add_single(p_at_z_neg, p_at_x.clone());
                                let z_plus_x = self.p3_ext_add_single(z_neg, x.clone());

                                let quotient = self.p3_ext_div(p_at_z_plus_p_at_x, z_plus_x);

                                let alpha_pow_at_log_height_mul_quotient =
                                    self.p3_ext_mul(&alpha_pow[log_height], &quotient);

                                let ro_at_log_height_plus_alpha_pow_at_log_height_mul_quotient =
                                    self.p3_ext_add(
                                        ro[log_height].clone(),
                                        alpha_pow_at_log_height_mul_quotient,
                                    );
                                ro[log_height] =
                                    ro_at_log_height_plus_alpha_pow_at_log_height_mul_quotient;

                                let alpha_pow_at_log_height_mul_alpha =
                                    self.p3_ext_mul(&alpha_pow[log_height], &alpha);
                                alpha_pow[log_height] = alpha_pow_at_log_height_mul_alpha;
                            }
                        }
                    }
                }
                Ok(ro)
            })
            .collect::<Result<Vec<_>, ()>>()
            .unwrap();

        self.p3_verify_challenges::<H>(
            config,
            &proof.fri_proof,
            &fri_challenges,
            &reduced_openings,
        )
        .unwrap();

        Ok(())
    }

    fn p3_verify_shape_and_sample_challenges<H: AlgebraicHasher<F>>(
        &mut self,
        config: &FriConfig,
        proof: &FriProof<Target>,
        challenger: &mut DuplexChallengerTarget,
    ) -> Result<FriChallenges<Target>, FriError> {
        let betas: Vec<BinomialExtensionField<Target>> = proof
            .commit_phase_commits
            .iter()
            .map(|comm| {
                self.p3_observe::<H>(challenger, comm.value.clone());
                self.p3_sample_ext::<H>(challenger)
            })
            .collect();

        if proof.query_proofs.len() != config.num_queries {
            return Err(FriError::InvalidProofShape);
        }

        self.p3_check_witness::<H>(challenger, config.proof_of_work_bits, proof.pow_witness);

        let log_max_height = proof.commit_phase_commits.len() + config.log_blowup;

        let query_indices: Vec<Target> = (0..config.num_queries)
            .map(|_| self.p3_sample_bits::<H>(challenger, log_max_height))
            .collect();

        Ok(FriChallenges {
            query_indices,
            betas,
        })
    }

    fn p3_verify_challenges<H: AlgebraicHasher<F>>(
        &mut self,
        config: &FriConfig,
        proof: &FriProof<Target>,
        challenges: &FriChallenges<Target>,
        reduced_openings: &[[BinomialExtensionField<Target>; 32]],
    ) -> Result<(), ()> {
        let log_max_height = proof.commit_phase_commits.len() + config.log_blowup;
        for (&index, query_proof, ro) in izip!(
            &challenges.query_indices,
            &proof.query_proofs,
            reduced_openings
        ) {
            let folded_eval = self.p3_verify_query::<H>(
                config,
                &proof.commit_phase_commits,
                index,
                query_proof,
                &challenges.betas,
                ro,
                log_max_height,
            )?;

            self.connect_p3_ext(&folded_eval, &proof.final_poly);
        }

        Ok(())
    }

    fn p3_verify_query<H: AlgebraicHasher<F>>(
        &mut self,
        _config: &FriConfig,
        commit_phase_commits: &Vec<Commitment<Target>>,
        mut index: Target,
        proof: &QueryProof<Target>,
        betas: &[BinomialExtensionField<Target>],
        reduced_openings: &[BinomialExtensionField<Target>; 32],
        log_max_height: usize,
    ) -> Result<BinomialExtensionField<Target>, ()> {
        let mut folded_eval = <Self as CircuitBuilderP3ExtArithmetic<F, D>>::p3_ext_zero(self);
        // TODO: use p3_ext_two_adic_generator
        let two_adic_generator = self.p3_two_adic_generator(log_max_height);
        let rev_index_shifted = self.reverse_p3_bits_len(index, log_max_height);
        let x = self.exp(two_adic_generator, rev_index_shifted, 64);
        let mut x = BinomialExtensionField::<Target> {
            value: self.p3_field_to_arr(x),
        };

        let one = self.one();

        let rev_log_max_height: Vec<_> = (0..log_max_height).rev().collect();
        for (log_folded_height, commit, step, beta) in izip!(
            rev_log_max_height,
            commit_phase_commits,
            &proof.commit_phase_openings,
            betas
        ) {
            folded_eval =
                self.p3_ext_add(reduced_openings[log_folded_height + 1].clone(), folded_eval);

            let index_sibling = self.p3_xor(index, one);

            let index_pair = self.p3_rsh(index, 1);

            let index_sibling_and_one = self.p3_and(index_sibling, one);

            let is_odd = BoolTarget::new_unsafe(index_sibling_and_one);

            let mut evals = vec![folded_eval.clone(); 2];

            // evals[index_sibling % 2] = step.sibling_value.clone();

            evals[0] = self.p3_ext_if(is_odd, evals[0].clone(), step.sibling_value.clone());

            evals[1] = self.p3_ext_if(is_odd, step.sibling_value.clone(), evals[1].clone());

            let dims = &[Dimensions {
                width: 2,
                height: (1 << log_folded_height),
            }];

            self.p3_verify_batch::<H>(
                &commit.value.to_vec(),
                dims,
                index_pair,
                &vec![evals
                    .iter()
                    .flat_map(|row| row.value.iter().copied().collect::<Vec<_>>())
                    .collect::<Vec<_>>()],
                &step.opening_proof,
            )
            .unwrap();

            let mut xs = self.p3_ext_arr_fn::<2>(|_| x.clone());
            let two_adic_generator = self.p3_ext_two_adic_generator(1);
            let xs_0_mul_two_adic_generator = self.p3_ext_mul(&xs[0], &two_adic_generator);
            let xs_1_mul_two_adic_generator = self.p3_ext_mul(&xs[1], &two_adic_generator);
            let one = self.one();
            let index_sibling_and_one = self.p3_and(index_sibling, one);
            let is_odd = BoolTarget::new_unsafe(index_sibling_and_one);

            xs[0] = self.p3_ext_if(is_odd, xs[0].clone(), xs_0_mul_two_adic_generator);
            xs[1] = self.p3_ext_if(is_odd, xs_1_mul_two_adic_generator, xs[1].clone());

            // interpolate and evaluate at beta

            let beta_minus_xs_0 = self.p3_ext_sub(beta.clone(), xs[0].clone());

            let eval_1_minus_eval_0 = self.p3_ext_sub(evals[1].clone(), evals[0].clone());

            let xs_1_minus_xs_0 = self.p3_ext_sub(xs[1].clone(), xs[0].clone());

            let eval_1_minus_eval_0_mul_beta_minus_xs_0 =
                self.p3_ext_mul(&eval_1_minus_eval_0, &beta_minus_xs_0);

            let eval_1_minus_eval_0_mul_beta_minus_xs_0_div_xs_1_minus_xs_0 =
                self.p3_ext_div(eval_1_minus_eval_0_mul_beta_minus_xs_0, xs_1_minus_xs_0);

            folded_eval = self.p3_ext_add(
                evals[0].clone(),
                eval_1_minus_eval_0_mul_beta_minus_xs_0_div_xs_1_minus_xs_0,
            );

            index = index_pair;

            x = self.p3_ext_mul(&x, &x);
        }

        Ok(folded_eval)
    }

    fn p3_verify_batch<H: AlgebraicHasher<F>>(
        &mut self,
        commit: &Vec<Target>,
        dimensions: &[Dimensions],
        index: Target,
        opened_values: &Vec<Vec<Target>>,
        proof: &Vec<Vec<Target>>,
    ) -> Result<(), ()> {
        let base_dimensions = dimensions
            .iter()
            .map(|dim| Dimensions {
                width: dim.width * EXT_DEGREE,
                height: dim.height,
            })
            .collect::<Vec<_>>();

        commit::MerkleTreeMmcs::verify_batch::<H, F, D>(
            commit,
            &base_dimensions,
            index,
            &opened_values,
            proof,
            self,
        )
    }
}

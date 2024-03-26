use plonky2::{
    field::extension::Extendable,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    common::richer_field::RicherField,
    p3::{
        utils::{log2_ceil_usize, log2_strict_usize},
        CircuitBuilderP3Arithmetic,
    },
};

#[derive(Copy, Clone)]
pub struct GoldilocksTarget<F> {
    pub value: F,
}

#[derive(Debug, Clone)]
pub struct CommitmentsTarget<F> {
    pub trace: CommitmentTarget<F>,
    pub quotient_chunks: CommitmentTarget<F>,
}

#[derive(Debug, Clone)]
pub struct OpenedValuesTarget<F, const E: usize> {
    pub trace_local: Vec<BinomialExtensionTarget<F, E>>,
    pub trace_next: Vec<BinomialExtensionTarget<F, E>>,
    pub quotient_chunks: Vec<Vec<BinomialExtensionTarget<F, E>>>,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct BinomialExtensionTarget<F, const E: usize> {
    pub value: [F; E],
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct CommitmentTarget<F> {
    pub value: [F; 4],
}

#[derive(Debug, Clone)]
pub struct FriProofTarget<F, const E: usize> {
    pub commit_phase_commits: Vec<CommitmentTarget<F>>,
    pub query_proofs: Vec<QueryProofTarget<F, E>>,
    // This could become Vec<FC::Challenge> if this library was generalized to support non-constant
    // final polynomials.
    pub final_poly: BinomialExtensionTarget<F, E>,
    pub pow_witness: F,
}

#[derive(Debug, Clone)]
pub struct QueryProofTarget<F, const E: usize> {
    /// For each commit phase commitment, this contains openings of a commit phase codeword at the
    /// queried location, along with an opening proof.
    pub commit_phase_openings: Vec<CommitPhaseProofStepTarget<F, E>>,
}

#[derive(Debug, Clone)]
pub struct CommitPhaseProofStepTarget<F, const E: usize> {
    /// The opening of the commit phase codeword at the sibling location.
    // This may change to Vec<FC::Challenge> if the library is generalized to support other FRI
    // folding arities besides 2, meaning that there can be multiple siblings.
    pub sibling_value: BinomialExtensionTarget<F, E>,

    pub opening_proof: Vec<Vec<F>>,
}

#[derive(Debug, Clone)]
pub struct BatchOpeningTarget<F> {
    pub opened_values: Vec<Vec<F>>,
    pub opening_proof: Vec<Vec<F>>,
}

#[derive(Debug, Clone)]
pub struct TwoAdicFriPcsProofTarget<F, const E: usize> {
    pub fri_proof: FriProofTarget<F, E>,
    /// For each query, for each committed batch, query openings for that batch
    pub query_openings: Vec<Vec<BatchOpeningTarget<F>>>,
}

#[derive(Debug, Clone)]
pub struct ProofTarget<F, const E: usize> {
    pub commitments: CommitmentsTarget<F>,
    pub opened_values: OpenedValuesTarget<F, E>,
    pub opening_proof: TwoAdicFriPcsProofTarget<F, E>,
    pub degree_bits: usize,
}

pub trait CircuitBuilderP3ExtArithmetic<
    F: RicherField + Extendable<D>,
    const D: usize,
    const E: usize,
>
{
    fn p3_w(&mut self) -> Target;

    fn p3_two_adic_generator(&mut self, bits: usize) -> Target;

    fn p3_ext_two_adic_generator(&mut self, bits: usize) -> BinomialExtensionTarget<Target, E>;

    fn p3_dth_root(&mut self) -> Target;

    fn connect_p3_ext(
        &mut self,
        x: &BinomialExtensionTarget<Target, E>,
        y: &BinomialExtensionTarget<Target, E>,
    );

    fn p3_ext_if(
        &mut self,
        cond: BoolTarget,
        x: BinomialExtensionTarget<Target, E>,
        y: BinomialExtensionTarget<Target, E>,
    ) -> BinomialExtensionTarget<Target, E>;

    fn p3_ext_frobenius(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
    ) -> BinomialExtensionTarget<Target, E>;

    fn p3_ext_repeated_frobenius(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        count: usize,
    ) -> BinomialExtensionTarget<Target, E>;

    fn p3_ext_frobenius_inv(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
    ) -> BinomialExtensionTarget<Target, E>;

    fn p3_ext_one(&mut self) -> BinomialExtensionTarget<Target, E>;

    fn p3_ext_zero(&mut self) -> BinomialExtensionTarget<Target, E>;

    fn p3_ext_div(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        y: BinomialExtensionTarget<Target, E>,
    ) -> BinomialExtensionTarget<Target, E>;

    fn p3_ext_div_single(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        y: Target,
    ) -> BinomialExtensionTarget<Target, E>;

    fn p3_ext_inverse(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
    ) -> BinomialExtensionTarget<Target, E>;

    fn p3_ext_neg(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
    ) -> BinomialExtensionTarget<Target, E>;

    fn p3_ext_add(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        y: BinomialExtensionTarget<Target, E>,
    ) -> BinomialExtensionTarget<Target, E>;

    fn p3_ext_add_single(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        y: Target,
    ) -> BinomialExtensionTarget<Target, E>;

    fn p3_ext_sub(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        y: BinomialExtensionTarget<Target, E>,
    ) -> BinomialExtensionTarget<Target, E>;

    fn p3_ext_sub_single(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        y: Target,
    ) -> BinomialExtensionTarget<Target, E>;

    fn p3_ext_arr<const SIZE: usize>(&mut self) -> [BinomialExtensionTarget<Target, E>; SIZE];

    fn p3_ext_arr_fn<const SIZE: usize>(
        &mut self,
        f: impl FnMut(usize) -> BinomialExtensionTarget<Target, E>,
    ) -> [BinomialExtensionTarget<Target, E>; SIZE];

    fn p3_ext_mul_single(
        &mut self,
        x: &BinomialExtensionTarget<Target, E>,
        y: Target,
    ) -> BinomialExtensionTarget<Target, E>;

    fn p3_ext_mul(
        &mut self,
        x: &BinomialExtensionTarget<Target, E>,
        y: &BinomialExtensionTarget<Target, E>,
    ) -> BinomialExtensionTarget<Target, E>;

    fn p3_ext_exp_power_of_2(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        power_log: usize,
    ) -> BinomialExtensionTarget<Target, E>;

    fn p3_ext_powers(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        n: usize,
    ) -> Vec<BinomialExtensionTarget<Target, E>>;

    fn p3_ext_monomial(&mut self, exponent: usize) -> BinomialExtensionTarget<Target, E>;

    fn p3_ext_mul_add(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        y: BinomialExtensionTarget<Target, E>,
        z: BinomialExtensionTarget<Target, E>,
    ) -> BinomialExtensionTarget<Target, E>;

    fn p3_ext_add_sub(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        y: BinomialExtensionTarget<Target, E>,
        z: BinomialExtensionTarget<Target, E>,
    ) -> BinomialExtensionTarget<Target, E>;
}

impl<F: RicherField + Extendable<D>, const D: usize, const E: usize>
    CircuitBuilderP3ExtArithmetic<F, D, E> for CircuitBuilder<F, D>
{
    fn p3_w(&mut self) -> Target {
        match E {
            2 => self.p3_constant(7u32),
            _ => panic!("Unsupported extension degree"),
        }
    }

    fn p3_two_adic_generator(&mut self, bits: usize) -> Target {
        let base = self.p3_constant(1_753_635_133_440_165_772u64);
        self.exp_power_of_2(base, 32 - bits)
    }

    fn p3_ext_two_adic_generator(&mut self, bits: usize) -> BinomialExtensionTarget<Target, E> {
        let base = self.p3_constant(1_753_635_133_440_165_772u64);
        let x = self.exp_power_of_2(base, 32 - bits);
        if bits == 33 {
            let mut value = self.p3_field_to_arr::<E>(x);
            value.reverse();
            BinomialExtensionTarget::<Target, E> { value }
        } else {
            BinomialExtensionTarget::<Target, E> {
                value: self.p3_field_to_arr::<E>(x),
            }
        }
    }

    fn p3_dth_root(&mut self) -> Target {
        // plonky3/goldilocks/src/extension.rs
        self.constant(F::from_canonical_u64(18446744069414584320))
    }

    fn p3_ext_frobenius(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
    ) -> BinomialExtensionTarget<Target, E> {
        self.p3_ext_repeated_frobenius(x, 1)
    }

    fn p3_ext_if(
        &mut self,
        cond: BoolTarget,
        x: BinomialExtensionTarget<Target, E>,
        y: BinomialExtensionTarget<Target, E>,
    ) -> BinomialExtensionTarget<Target, E> {
        let mut res = [self.zero(); E];
        for i in 0..E {
            res[i] = self._if(cond, x.value[i], y.value[i]);
        }
        BinomialExtensionTarget::<Target, E> { value: res }
    }

    fn p3_ext_repeated_frobenius(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        count: usize,
    ) -> BinomialExtensionTarget<Target, E> {
        if count == 0 {
            return x.clone();
        } else if count >= E {
            // x |-> x^(n^D) is the identity, so x^(n^count) ==
            // x^(n^(count % D))
            return self.p3_ext_repeated_frobenius(x, count % E);
        }
        let arr: &[Target] = &x.value;

        // z0 = DTH_ROOT^count = W^(k * count) where k = floor((n-1)/D)
        let mut z0 = <Self as CircuitBuilderP3ExtArithmetic<F, D, E>>::p3_dth_root(self);
        for _ in 1..count {
            let dth_root = <Self as CircuitBuilderP3ExtArithmetic<F, D, E>>::p3_dth_root(self);
            z0 = self.mul(z0, dth_root);
        }

        let mut powers: [Target; E] = [z0.clone(); E];
        for i in 1..E {
            powers[i] = self.mul(powers[i - 1], z0.clone());
        }

        let mut res = [self.zero(); E];
        for (i, z) in powers.into_iter().enumerate() {
            res[i] = self.mul(arr[i], z);
        }

        BinomialExtensionTarget::<Target, E> { value: res }
    }

    fn p3_ext_frobenius_inv(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
    ) -> BinomialExtensionTarget<Target, E> {
        // Writing 'a' for self, we need to compute a^(r-1):
        // r = n^D-1/n-1 = n^(D-1)+n^(D-2)+...+n
        let mut f = self.p3_ext_one();
        for _ in 1..E {
            let x_mul_f = self.p3_ext_mul(&x, &f);
            f = self.p3_ext_frobenius(x_mul_f);
        }

        // g = a^r is in the base field, so only compute that
        // coefficient rather than the full product.
        let a = x.value;
        let b = f.value;
        let mut g = self.p3_constant(0u32);
        for i in 1..E {
            let a_i_mul_b_e_minus_i = self.mul(a[i], b[E - i]);
            g = self.add(a_i_mul_b_e_minus_i, g);
        }
        let w = <Self as CircuitBuilderP3ExtArithmetic<F, D, E>>::p3_w(self);
        g = self.mul(g, w);
        let a_0_mul_b_0 = self.mul(a[0], b[0]);
        g = self.add(a_0_mul_b_0, g);

        let g_inverse = self.inverse(g);
        self.p3_ext_mul_single(&f, g_inverse)
    }

    fn p3_ext_one(&mut self) -> BinomialExtensionTarget<Target, E> {
        let one = self.p3_constant(1u32);
        BinomialExtensionTarget::<Target, E> {
            value: self.p3_field_to_arr::<E>(one),
        }
    }

    fn p3_ext_zero(&mut self) -> BinomialExtensionTarget<Target, E> {
        let zero = self.p3_constant(0u32);
        BinomialExtensionTarget::<Target, E> {
            value: self.p3_field_to_arr::<E>(zero),
        }
    }

    fn p3_ext_div(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        y: BinomialExtensionTarget<Target, E>,
    ) -> BinomialExtensionTarget<Target, E> {
        let y_inv = self.p3_ext_inverse(y);
        self.p3_ext_mul(&y_inv, &x)
    }

    fn p3_ext_div_single(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        y: Target,
    ) -> BinomialExtensionTarget<Target, E> {
        let mut res = x.value;
        let y_inv = self.inverse(y);

        for r in res.iter_mut() {
            *r = self.mul(y_inv, *r);
        }
        BinomialExtensionTarget::<Target, E> { value: res }
    }

    fn p3_ext_inverse(
        &mut self,
        a: BinomialExtensionTarget<Target, E>,
    ) -> BinomialExtensionTarget<Target, E> {
        let w = <Self as CircuitBuilderP3ExtArithmetic<F, D, E>>::p3_w(self);
        match E {
            2 => {
                let a_0_square = self.square(a.value[0].clone());
                let a_1_square = self.square(a.value[1].clone());
                let w_mul_sqaure_a_1 = self.mul(w, a_1_square);
                let a_0_square_sub_w_mul_sqaure_a_1 = self.sub(a_0_square, w_mul_sqaure_a_1);

                let scalar = self.inverse(a_0_square_sub_w_mul_sqaure_a_1);
                let a_0_mul_scalar = self.mul(a.value[0].clone(), scalar);
                let a_1_neg = self.neg(a.value[1].clone());
                let a_1_neg_mul_scalar = self.mul(a_1_neg, scalar);

                let mut value = [self.zero(); E];
                value[0] = a_0_mul_scalar;
                value[1] = a_1_neg_mul_scalar;

                BinomialExtensionTarget::<Target, E> { value }
            }
            3 => {
                let a0_square = self.square(a.value[0].clone());
                let a1_square = self.square(a.value[1].clone());
                let a2_w = self.mul(w, a.value[2].clone());
                let a0_a1 = self.mul(a.value[0], a.value[1]);

                // scalar = (a0^3+wa1^3+w^2a2^3-3wa0a1a2)^-1
                let a0_square_mul_a0 = self.mul(a0_square, a.value[0].clone());
                let w_mul_a1_square = self.mul(w, a.value[1].clone());
                let w_mul_a1_square_mul_a1_square = self.mul(w_mul_a1_square, a1_square);
                let a2_w_square = self.square(a2_w.clone());
                let a2_w_square_mul_a2 = self.mul(a2_w_square, a.value[2].clone());
                let a0_square_mul_a0_plus_w_mul_a1_square_mul_a1_square_plus_a2_w_square_mul_a2 =
                    self.add_many([
                        a0_square_mul_a0,
                        w_mul_a1_square_mul_a1_square,
                        a2_w_square_mul_a2,
                    ]);

                let one = self.one();
                let two = self.two();
                let three = self.add(one, two);
                let three_mul_a2_w = self.mul(three, a2_w);
                let three_mul_a2_w_mul_a0_a1 = self.mul(three_mul_a2_w, a0_a1);

                let scalar_inv = self.sub(
                    a0_square_mul_a0_plus_w_mul_a1_square_mul_a1_square_plus_a2_w_square_mul_a2,
                    three_mul_a2_w_mul_a0_a1,
                );
                let scalar = self.inverse(scalar_inv);

                let a1_mul_a2w = self.mul(a.value[1].clone(), a2_w);
                let a0_square_minus_a1_mul_a2w = self.sub(a0_square, a1_mul_a2w);
                let a2w_mul_a2 = self.mul(a2_w, a.value[2].clone());
                let a2w_mul_a2_sub_a0_a1 = self.sub(a2w_mul_a2, a0_a1);
                let a0_mul_a2 = self.mul(a.value[0].clone(), a.value[2].clone());
                let a1_square_minus_a0_mul_a2 = self.sub(a1_square, a0_mul_a2);

                //scalar*[a0^2-wa1a2, wa2^2-a0a1, a1^2-a0a2]
                let mut value = [self.zero(); E];
                value[0] = self.mul(scalar, a0_square_minus_a1_mul_a2w);
                value[1] = self.mul(scalar, a2w_mul_a2_sub_a0_a1);
                value[2] = self.mul(scalar, a1_square_minus_a0_mul_a2);

                BinomialExtensionTarget::<Target, E> { value }
            }
            _ => self.p3_ext_frobenius_inv(a),
        }
    }

    fn p3_ext_neg(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
    ) -> BinomialExtensionTarget<Target, E> {
        let mut res = x.value;
        for r in res.iter_mut() {
            let r_neg = self.neg(*r);
            *r = r_neg;
        }
        BinomialExtensionTarget::<Target, E> { value: res }
    }

    fn p3_ext_add(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        y: BinomialExtensionTarget<Target, E>,
    ) -> BinomialExtensionTarget<Target, E> {
        let mut res = x.value;
        for (r, rhs_val) in res.iter_mut().zip(y.value) {
            *r = self.add(*r, rhs_val);
        }
        BinomialExtensionTarget::<Target, E> { value: res }
    }

    fn p3_ext_add_single(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        y: Target,
    ) -> BinomialExtensionTarget<Target, E> {
        let mut res = x.value;
        res[0] = self.add(res[0], y);
        BinomialExtensionTarget::<Target, E> { value: res }
    }

    fn p3_ext_sub(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        y: BinomialExtensionTarget<Target, E>,
    ) -> BinomialExtensionTarget<Target, E> {
        let mut res = x.value;
        for (r, rhs_val) in res.iter_mut().zip(y.value) {
            *r = self.sub(*r, rhs_val);
        }
        BinomialExtensionTarget::<Target, E> { value: res }
    }

    fn p3_ext_sub_single(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        y: Target,
    ) -> BinomialExtensionTarget<Target, E> {
        let mut res = x.value;
        res[0] = self.sub(res[0], y);
        BinomialExtensionTarget::<Target, E> { value: res }
    }

    fn p3_ext_arr<const SIZE: usize>(&mut self) -> [BinomialExtensionTarget<Target, E>; SIZE] {
        core::array::from_fn(|_| BinomialExtensionTarget::<Target, E> {
            value: self.p3_arr::<E>(),
        })
    }

    fn p3_ext_arr_fn<const SIZE: usize>(
        &mut self,
        f: impl FnMut(usize) -> BinomialExtensionTarget<Target, E>,
    ) -> [BinomialExtensionTarget<Target, E>; SIZE] {
        core::array::from_fn(f)
    }

    fn p3_ext_mul_single(
        &mut self,
        x: &BinomialExtensionTarget<Target, E>,
        y: Target,
    ) -> BinomialExtensionTarget<Target, E> {
        BinomialExtensionTarget::<Target, E> {
            value: x.value.map(|item| self.mul(item, y.clone())),
        }
    }

    fn p3_ext_mul(
        &mut self,
        x: &BinomialExtensionTarget<Target, E>,
        y: &BinomialExtensionTarget<Target, E>,
    ) -> BinomialExtensionTarget<Target, E> {
        let w_af = <Self as CircuitBuilderP3ExtArithmetic<F, D, E>>::p3_w(self);
        let mut res = BinomialExtensionTarget::<Target, E> {
            value: self.p3_arr::<E>(),
        };
        match E {
            2 => {
                let a_0_mul_b_0 = self.mul(x.value[0].clone(), y.value[0].clone());
                let w_af_mul_b_1 = self.mul(w_af, y.value[1].clone());
                let a_1_mul_w_af_mul_b_1 = self.mul(x.value[1].clone(), w_af_mul_b_1);

                let a_0_mul_b_1 = self.mul(x.value[0].clone(), y.value[1].clone());
                let a_1_mul_b_0 = self.mul(x.value[1].clone(), y.value[0].clone());

                let a_0_mul_b_0_plus_w_af_mul_b_1 = self.add(a_0_mul_b_0, a_1_mul_w_af_mul_b_1);
                let a_0_mul_b_1_plus_a_1_mul_b_0 = self.add(a_0_mul_b_1, a_1_mul_b_0);

                res.value[0] = a_0_mul_b_0_plus_w_af_mul_b_1;
                res.value[1] = a_0_mul_b_1_plus_a_1_mul_b_0;
            }
            3 => {
                let a0_b0 = self.mul(x.value[0].clone(), y.value[0].clone());
                let a1_b1 = self.mul(x.value[1].clone(), y.value[1].clone());
                let a2_b2 = self.mul(x.value[2].clone(), y.value[2].clone());

                let a_1_plus_a_2 = self.add(x.value[1].clone(), x.value[2].clone());
                let b_1_plus_b_2 = self.add(y.value[1].clone(), y.value[2].clone());
                let a_1_plus_a_2_mul_b_1_plus_b_2 = self.mul(a_1_plus_a_2, b_1_plus_b_2);

                let a0_b0_neg = self.neg(a0_b0);
                let a1_b1_neg = self.neg(a1_b1);
                let a2_b2_neg = self.neg(a2_b2);

                let mid = self.add_many([a_1_plus_a_2_mul_b_1_plus_b_2, a1_b1_neg, a2_b2_neg]);
                let mid_mul_w_af = self.mul(mid, w_af);

                let c0 = self.add(a0_b0.clone(), mid_mul_w_af);

                let a_0_plus_a_1 = self.add(x.value[0].clone(), x.value[1].clone());
                let b_0_plus_b_1 = self.add(y.value[0].clone(), y.value[1].clone());
                let a_0_plus_a_1_mul_b_0_plus_b_1 = self.mul(a_0_plus_a_1, b_0_plus_b_1);
                let a2_b2_mul_w_af = self.mul(a2_b2, w_af);

                let c1 = self.add_many([
                    a_0_plus_a_1_mul_b_0_plus_b_1,
                    a0_b0_neg,
                    a1_b1_neg,
                    a2_b2_mul_w_af,
                ]);

                let a_0_plus_a_2 = self.add(x.value[0].clone(), x.value[2].clone());
                let b_0_plus_b_2 = self.add(y.value[0].clone(), y.value[2].clone());
                let a_0_plus_a_2_mul_b_0_plus_b_2 = self.mul(a_0_plus_a_2, b_0_plus_b_2);

                let c2 =
                    self.add_many([a_0_plus_a_2_mul_b_0_plus_b_2, a0_b0_neg, a2_b2_neg, a1_b1]);

                res.value[0] = c0;
                res.value[1] = c1;
                res.value[2] = c2;
            }
            _ =>
            {
                #[allow(clippy::needless_range_loop)]
                for i in 0..E {
                    for j in 0..E {
                        if i + j >= E {
                            let x_i_mul_w_af = self.mul(x.value[i].clone(), w_af.clone());
                            let x_i_mul_w_af_mul_y_j = self.mul(x_i_mul_w_af, y.value[j].clone());
                            res.value[i + j - E] =
                                self.add(res.value[i + j - E], x_i_mul_w_af_mul_y_j);
                        } else {
                            let x_i_mul_y_j = self.mul(x.value[i].clone(), x.value[j].clone());
                            res.value[i + j] = self.add(res.value[i + j], x_i_mul_y_j);
                        }
                    }
                }
            }
        }
        res
    }

    fn p3_ext_exp_power_of_2(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        power_log: usize,
    ) -> BinomialExtensionTarget<Target, E> {
        let mut res = x.clone();
        for _ in 0..power_log {
            res = self.p3_ext_mul(&res, &res);
        }
        res
    }

    fn p3_ext_powers(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        n: usize,
    ) -> Vec<BinomialExtensionTarget<Target, E>> {
        let mut res = vec![x.clone()];
        for i in 1..n {
            res.push(self.p3_ext_mul(&x, &res[i - 1]));
        }
        res
    }

    fn p3_ext_monomial(&mut self, exponent: usize) -> BinomialExtensionTarget<Target, E> {
        let mut value = [self.zero(); E];
        value[exponent] = self.one();
        BinomialExtensionTarget::<Target, E> { value }
    }

    fn p3_ext_mul_add(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        y: BinomialExtensionTarget<Target, E>,
        z: BinomialExtensionTarget<Target, E>,
    ) -> BinomialExtensionTarget<Target, E> {
        let x_mul_y = self.p3_ext_mul(&x, &y);
        let x_mul_y_plus_z = self.p3_ext_add(x_mul_y, z);
        x_mul_y_plus_z
    }

    fn p3_ext_add_sub(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        y: BinomialExtensionTarget<Target, E>,
        z: BinomialExtensionTarget<Target, E>,
    ) -> BinomialExtensionTarget<Target, E> {
        let x_plus_y = self.p3_ext_add(x, y);
        let x_plus_y_minus_z = self.p3_ext_sub(x_plus_y, z);
        x_plus_y_minus_z
    }

    fn connect_p3_ext(
        &mut self,
        x: &BinomialExtensionTarget<Target, E>,
        y: &BinomialExtensionTarget<Target, E>,
    ) {
        for i in 0..E {
            self.connect(x.value[i].clone(), y.value[i].clone());
        }
    }
}

pub struct VerifierConstraintFolderTarget<F, const E: usize> {
    pub main: OpenedValuesTarget<F, E>,
    pub is_first_row: BinomialExtensionTarget<F, E>,
    pub is_last_row: BinomialExtensionTarget<F, E>,
    pub is_transition: BinomialExtensionTarget<F, E>,
    pub alpha: BinomialExtensionTarget<F, E>,
    pub accumulator: BinomialExtensionTarget<F, E>,
}

pub struct FilteredAirBuilderTarget<'a, F, const E: usize> {
    pub inner: &'a mut VerifierConstraintFolderTarget<F, E>,
    pub condition: BinomialExtensionTarget<F, E>,
}

impl<const E: usize> VerifierConstraintFolderTarget<Target, E> {
    pub fn when<F: RicherField + Extendable<D>, const D: usize>(
        &mut self,
        condition: BinomialExtensionTarget<Target, E>,
    ) -> FilteredAirBuilderTarget<Target, E> {
        FilteredAirBuilderTarget {
            inner: self,
            condition: condition,
        }
    }

    pub fn when_first_row<F: RicherField + Extendable<D>, const D: usize>(
        &mut self,
    ) -> FilteredAirBuilderTarget<Target, E> {
        self.when::<F, D>(self.is_first_row.clone())
    }

    pub fn when_last_row<F: RicherField + Extendable<D>, const D: usize>(
        &mut self,
    ) -> FilteredAirBuilderTarget<Target, E> {
        self.when::<F, D>(self.is_last_row.clone())
    }

    pub fn when_transition<F: RicherField + Extendable<D>, const D: usize>(
        &mut self,
    ) -> FilteredAirBuilderTarget<Target, E> {
        self.when::<F, D>(self.is_transition.clone())
    }

    pub fn assert_zero<F: RicherField + Extendable<D>, const D: usize>(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        cb: &mut CircuitBuilder<F, D>,
    ) {
        self.accumulator = cb.p3_ext_mul_add(self.accumulator.clone(), self.alpha.clone(), x);
    }

    pub fn assert_eq<F: RicherField + Extendable<D>, const D: usize>(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        y: BinomialExtensionTarget<Target, E>,
        cb: &mut CircuitBuilder<F, D>,
    ) {
        let x_sub_y = cb.p3_ext_sub(x, y);
        self.assert_zero(x_sub_y, cb)
    }

    pub fn assert_bool<F: RicherField + Extendable<D>, const D: usize>(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        cb: &mut CircuitBuilder<F, D>,
    ) {
        let one = cb.p3_ext_one();
        let x_minus_one = cb.p3_ext_sub(x.clone(), one);
        let x_mul_x_minus_one = cb.p3_ext_mul(&x, &x_minus_one);

        self.assert_zero(x_mul_x_minus_one, cb);
    }
}

impl<'a, const E: usize> FilteredAirBuilderTarget<'a, Target, E> {
    pub fn assert_zero<F: RicherField + Extendable<D>, const D: usize>(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        cb: &mut CircuitBuilder<F, D>,
    ) {
        let x = cb.p3_ext_mul(&self.condition, &x);
        self.inner.assert_zero(x, cb)
    }

    pub fn assert_eq<F: RicherField + Extendable<D>, const D: usize>(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        y: BinomialExtensionTarget<Target, E>,
        cb: &mut CircuitBuilder<F, D>,
    ) {
        let x_sub_y = cb.p3_ext_sub(x, y);
        let x = cb.p3_ext_mul(&self.condition, &x_sub_y);
        self.inner.assert_zero(x, cb)
    }

    pub fn assert_bool<F: RicherField + Extendable<D>, const D: usize>(
        &mut self,
        x: BinomialExtensionTarget<Target, E>,
        cb: &mut CircuitBuilder<F, D>,
    ) {
        let x = cb.p3_ext_mul(&self.condition, &x);
        self.inner.assert_bool(x, cb)
    }
}

pub struct FriConfig {
    pub log_blowup: usize,
    pub num_queries: usize,
    pub proof_of_work_bits: usize,
}

pub struct FriChallenges<F, const E: usize> {
    pub query_indices: Vec<F>,
    pub betas: Vec<BinomialExtensionTarget<F, E>>,
}

#[derive(Debug, Clone)]
pub enum FriError {
    InvalidProofShape,
    CommitPhaseMmcsError,
    FinalPolyMismatch,
    InvalidPowWitness,
}

#[derive(Clone, Copy)]
pub struct Dimensions {
    pub width: usize,
    pub height: usize,
}

#[derive(Clone, Copy)]
pub struct TwoAdicMultiplicativeCoset {
    pub log_n: usize,
    pub shift: Target,
}

impl TwoAdicMultiplicativeCoset {
    const TWO_ADICITY: usize = 32;

    pub fn size(&self) -> usize {
        1 << self.log_n
    }

    pub fn first_point(&self) -> Target {
        self.shift
    }

    pub fn gen<F: RicherField + Extendable<D>, const D: usize>(
        &self,
        cb: &mut CircuitBuilder<F, D>,
    ) -> Target {
        assert!(self.log_n <= Self::TWO_ADICITY);

        let base = cb.constant(F::from_canonical_u64(1_753_635_133_440_165_772));
        cb.exp_power_of_2(base, Self::TWO_ADICITY - self.log_n)
    }

    pub fn next_point<F: RicherField + Extendable<D>, const D: usize, const E: usize>(
        &self,
        x: BinomialExtensionTarget<Target, E>,
        cb: &mut CircuitBuilder<F, D>,
    ) -> BinomialExtensionTarget<Target, E> {
        let gen = self.gen(cb);
        cb.p3_ext_mul_single(&x, gen)
    }

    pub fn natural_domain_for_degree<F: RicherField + Extendable<D>, const D: usize>(
        log_n_self: usize,
        degree: usize,
        cb: &mut CircuitBuilder<F, D>,
    ) -> TwoAdicMultiplicativeCoset {
        let log_n = log2_strict_usize(degree);
        assert!(log_n <= log_n_self);
        TwoAdicMultiplicativeCoset {
            log_n,
            shift: cb.one(),
        }
    }

    pub fn create_disjoint_domain<F: RicherField + Extendable<D>, const D: usize>(
        &self,
        min_size: usize,
        cb: &mut CircuitBuilder<F, D>,
    ) -> TwoAdicMultiplicativeCoset {
        let generator = cb.constant(F::from_canonical_u64(7));
        TwoAdicMultiplicativeCoset {
            log_n: log2_ceil_usize(min_size),
            shift: cb.mul(self.shift, generator),
        }
    }

    pub fn split_domains<F: RicherField + Extendable<D>, const D: usize, const E: usize>(
        &mut self,
        num_chunks: usize,
        cb: &mut CircuitBuilder<F, D>,
    ) -> Vec<TwoAdicMultiplicativeCoset> {
        let log_chunks = log2_strict_usize(num_chunks);
        let two_adicity_generator = self.gen(cb);

        (0..num_chunks)
            .map(|i| TwoAdicMultiplicativeCoset {
                log_n: self.log_n - log_chunks,
                shift: {
                    let two_adic_generator_powers_i = cb.exp_u64(two_adicity_generator, i as u64);
                    cb.mul(self.shift, two_adic_generator_powers_i)
                },
            })
            .collect()
    }

    pub fn selectors_at_point<F: RicherField + Extendable<D>, const D: usize, const E: usize>(
        &self,
        point: BinomialExtensionTarget<Target, E>,
        cb: &mut CircuitBuilder<F, D>,
    ) -> LagrangeSelectors<BinomialExtensionTarget<Target, E>> {
        let shift_inv = cb.inverse(self.shift);
        let unshifted_point = cb.p3_ext_mul_single(&point, shift_inv);
        let unshifted_point_exp_log_n =
            cb.p3_ext_exp_power_of_2(unshifted_point.clone(), self.log_n);
        let one = cb.p3_ext_one();

        let z_h = cb.p3_ext_sub(unshifted_point_exp_log_n, one.clone());

        let unshifted_point_minus_one = cb.p3_ext_sub(unshifted_point.clone(), one);
        let z_h_div_unshifted_point_minus_one =
            cb.p3_ext_div(z_h.clone(), unshifted_point_minus_one);

        let generator = self.gen(cb);
        let generator_inv = cb.inverse(generator);
        let unshifted_point_minus_generator_inv =
            cb.p3_ext_sub_single(unshifted_point, generator_inv.clone());
        let z_h_div_unshifted_point_minus_generator_inv =
            cb.p3_ext_div(z_h.clone(), unshifted_point_minus_generator_inv.clone());

        LagrangeSelectors {
            is_first_row: z_h_div_unshifted_point_minus_one,
            is_last_row: z_h_div_unshifted_point_minus_generator_inv,
            is_transition: unshifted_point_minus_generator_inv,
            inv_zeroifier: cb.p3_ext_inverse(z_h),
        }
    }

    pub fn zp_at_point<F: RicherField + Extendable<D>, const D: usize, const E: usize>(
        &self,
        point: BinomialExtensionTarget<Target, E>,
        cb: &mut CircuitBuilder<F, D>,
    ) -> BinomialExtensionTarget<Target, E> {
        let shift_inv = cb.inverse(self.shift);
        let point_mul_shift_inv = cb.p3_ext_mul_single(&point, shift_inv);
        let point_mul_shift_inv_powers_log_n =
            cb.p3_ext_exp_power_of_2(point_mul_shift_inv, self.log_n);
        let one = cb.p3_ext_one();
        cb.p3_ext_sub(point_mul_shift_inv_powers_log_n, one)
    }

    pub fn zp_at_single_point<F: RicherField + Extendable<D>, const D: usize>(
        &self,
        point: Target,
        cb: &mut CircuitBuilder<F, D>,
    ) -> Target {
        let shift_inv = cb.inverse(self.shift);
        let point_mul_shift_inv = cb.mul(shift_inv, point);
        let point_mul_shift_inv_powers_log_n = cb.exp_power_of_2(point_mul_shift_inv, self.log_n);
        let one = cb.one();
        cb.sub(point_mul_shift_inv_powers_log_n, one)
    }
}

pub struct LagrangeSelectors<T> {
    pub is_first_row: T,
    pub is_last_row: T,
    pub is_transition: T,
    pub inv_zeroifier: T,
}

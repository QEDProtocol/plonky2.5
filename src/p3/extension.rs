use plonky2::{
    field::extension::Extendable,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    common::richer_field::RicherField,
    p3::{constants::EXT_DEGREE, serde::proof::BinomialExtensionField, CircuitBuilderP3Arithmetic},
};

pub trait CircuitBuilderP3ExtArithmetic<F: RicherField + Extendable<D>, const D: usize> {
    fn p3_w(&mut self) -> Target;

    fn p3_two_adic_generator(&mut self, bits: usize) -> Target;

    fn p3_ext_two_adic_generator(&mut self, bits: usize) -> BinomialExtensionField<Target>;

    fn p3_dth_root(&mut self) -> Target;

    fn connect_p3_ext(
        &mut self,
        x: &BinomialExtensionField<Target>,
        y: &BinomialExtensionField<Target>,
    );

    fn p3_ext_if(
        &mut self,
        cond: BoolTarget,
        x: BinomialExtensionField<Target>,
        y: BinomialExtensionField<Target>,
    ) -> BinomialExtensionField<Target>;

    fn p3_ext_frobenius(
        &mut self,
        x: BinomialExtensionField<Target>,
    ) -> BinomialExtensionField<Target>;

    fn p3_ext_repeated_frobenius(
        &mut self,
        x: BinomialExtensionField<Target>,
        count: usize,
    ) -> BinomialExtensionField<Target>;

    fn p3_ext_frobenius_inv(
        &mut self,
        x: BinomialExtensionField<Target>,
    ) -> BinomialExtensionField<Target>;

    fn p3_ext_one(&mut self) -> BinomialExtensionField<Target>;

    fn p3_ext_zero(&mut self) -> BinomialExtensionField<Target>;

    fn p3_ext_div(
        &mut self,
        x: BinomialExtensionField<Target>,
        y: BinomialExtensionField<Target>,
    ) -> BinomialExtensionField<Target>;

    fn p3_ext_div_single(
        &mut self,
        x: BinomialExtensionField<Target>,
        y: Target,
    ) -> BinomialExtensionField<Target>;

    fn p3_ext_inverse(
        &mut self,
        x: BinomialExtensionField<Target>,
    ) -> BinomialExtensionField<Target>;

    fn p3_ext_neg(&mut self, x: BinomialExtensionField<Target>) -> BinomialExtensionField<Target>;

    fn p3_ext_add(
        &mut self,
        x: BinomialExtensionField<Target>,
        y: BinomialExtensionField<Target>,
    ) -> BinomialExtensionField<Target>;

    fn p3_ext_add_single(
        &mut self,
        x: BinomialExtensionField<Target>,
        y: Target,
    ) -> BinomialExtensionField<Target>;

    fn p3_ext_sub(
        &mut self,
        x: BinomialExtensionField<Target>,
        y: BinomialExtensionField<Target>,
    ) -> BinomialExtensionField<Target>;

    fn p3_ext_sub_single(
        &mut self,
        x: BinomialExtensionField<Target>,
        y: Target,
    ) -> BinomialExtensionField<Target>;

    fn p3_ext_arr<const SIZE: usize>(&mut self) -> [BinomialExtensionField<Target>; SIZE];

    fn p3_ext_arr_fn<const SIZE: usize>(
        &mut self,
        f: impl FnMut(usize) -> BinomialExtensionField<Target>,
    ) -> [BinomialExtensionField<Target>; SIZE];

    fn p3_ext_mul_single(
        &mut self,
        x: &BinomialExtensionField<Target>,
        y: Target,
    ) -> BinomialExtensionField<Target>;

    fn p3_ext_mul(
        &mut self,
        x: &BinomialExtensionField<Target>,
        y: &BinomialExtensionField<Target>,
    ) -> BinomialExtensionField<Target>;

    fn p3_ext_exp_power_of_2(
        &mut self,
        x: BinomialExtensionField<Target>,
        power_log: usize,
    ) -> BinomialExtensionField<Target>;

    fn p3_ext_powers(
        &mut self,
        x: BinomialExtensionField<Target>,
        n: usize,
    ) -> Vec<BinomialExtensionField<Target>>;

    fn p3_ext_monomial(&mut self, exponent: usize) -> BinomialExtensionField<Target>;

    fn p3_ext_mul_add(
        &mut self,
        x: BinomialExtensionField<Target>,
        y: BinomialExtensionField<Target>,
        z: BinomialExtensionField<Target>,
    ) -> BinomialExtensionField<Target>;

    fn p3_ext_add_sub(
        &mut self,
        x: BinomialExtensionField<Target>,
        y: BinomialExtensionField<Target>,
        z: BinomialExtensionField<Target>,
    ) -> BinomialExtensionField<Target>;
}

impl<F: RicherField + Extendable<D>, const D: usize> CircuitBuilderP3ExtArithmetic<F, D>
    for CircuitBuilder<F, D>
{
    fn p3_w(&mut self) -> Target {
        match EXT_DEGREE {
            2 => self.p3_constant(7u32),
            _ => panic!("Unsupported extension degree"),
        }
    }

    fn p3_two_adic_generator(&mut self, bits: usize) -> Target {
        let base = self.p3_constant(1_753_635_133_440_165_772u64);
        self.exp_power_of_2(base, 32 - bits)
    }

    fn p3_ext_two_adic_generator(&mut self, bits: usize) -> BinomialExtensionField<Target> {
        let base = self.p3_constant(1_753_635_133_440_165_772u64);
        let x = self.exp_power_of_2(base, 32 - bits);
        if bits == 33 {
            let mut value = self.p3_field_to_arr(x);
            value.reverse();
            BinomialExtensionField::<Target> { value }
        } else {
            BinomialExtensionField::<Target> {
                value: self.p3_field_to_arr(x),
            }
        }
    }

    fn p3_dth_root(&mut self) -> Target {
        // plonky3/goldilocks/src/extension.rs
        self.constant(F::from_canonical_u64(18446744069414584320))
    }

    fn p3_ext_frobenius(
        &mut self,
        x: BinomialExtensionField<Target>,
    ) -> BinomialExtensionField<Target> {
        self.p3_ext_repeated_frobenius(x, 1)
    }

    fn p3_ext_if(
        &mut self,
        cond: BoolTarget,
        x: BinomialExtensionField<Target>,
        y: BinomialExtensionField<Target>,
    ) -> BinomialExtensionField<Target> {
        let mut res = [self.zero(); EXT_DEGREE];
        for i in 0..EXT_DEGREE {
            res[i] = self._if(cond, x.value[i], y.value[i]);
        }
        BinomialExtensionField::<Target> { value: res }
    }

    fn p3_ext_repeated_frobenius(
        &mut self,
        x: BinomialExtensionField<Target>,
        count: usize,
    ) -> BinomialExtensionField<Target> {
        if count == 0 {
            return x.clone();
        } else if count >= EXT_DEGREE {
            // x |-> x^(n^D) is the identity, so x^(n^count) ==
            // x^(n^(count % D))
            return self.p3_ext_repeated_frobenius(x, count % EXT_DEGREE);
        }
        let arr: &[Target] = &x.value;

        // z0 = DTH_ROOT^count = W^(k * count) where k = floor((n-1)/D)
        let mut z0 = <Self as CircuitBuilderP3ExtArithmetic<F, D>>::p3_dth_root(self);
        for _ in 1..count {
            let dth_root = <Self as CircuitBuilderP3ExtArithmetic<F, D>>::p3_dth_root(self);
            z0 = self.mul(z0, dth_root);
        }

        let mut powers: [Target; EXT_DEGREE] = [z0.clone(); EXT_DEGREE];
        for i in 1..EXT_DEGREE {
            powers[i] = self.mul(powers[i - 1], z0.clone());
        }

        let mut res = [self.zero(); EXT_DEGREE];
        for (i, z) in powers.into_iter().enumerate() {
            res[i] = self.mul(arr[i], z);
        }

        BinomialExtensionField::<Target> { value: res }
    }

    fn p3_ext_frobenius_inv(
        &mut self,
        x: BinomialExtensionField<Target>,
    ) -> BinomialExtensionField<Target> {
        // Writing 'a' for self, we need to compute a^(r-1):
        // r = n^D-1/n-1 = n^(D-1)+n^(D-2)+...+n
        let mut f = self.p3_ext_one();
        for _ in 1..EXT_DEGREE {
            let x_mul_f = self.p3_ext_mul(&x, &f);
            f = self.p3_ext_frobenius(x_mul_f);
        }

        // g = a^r is in the base field, so only compute that
        // coefficient rather than the full product.
        let a = x.value;
        let b = f.value;
        let mut g = self.p3_constant(0u32);
        for i in 1..EXT_DEGREE {
            let a_i_mul_b_e_minus_i = self.mul(a[i], b[EXT_DEGREE - i]);
            g = self.add(a_i_mul_b_e_minus_i, g);
        }
        let w = <Self as CircuitBuilderP3ExtArithmetic<F, D>>::p3_w(self);
        g = self.mul(g, w);
        let a_0_mul_b_0 = self.mul(a[0], b[0]);
        g = self.add(a_0_mul_b_0, g);

        let g_inverse = self.inverse(g);
        self.p3_ext_mul_single(&f, g_inverse)
    }

    fn p3_ext_one(&mut self) -> BinomialExtensionField<Target> {
        let one = self.p3_constant(1u32);
        BinomialExtensionField::<Target> {
            value: self.p3_field_to_arr(one),
        }
    }

    fn p3_ext_zero(&mut self) -> BinomialExtensionField<Target> {
        let zero = self.p3_constant(0u32);
        BinomialExtensionField::<Target> {
            value: self.p3_field_to_arr(zero),
        }
    }

    fn p3_ext_div(
        &mut self,
        x: BinomialExtensionField<Target>,
        y: BinomialExtensionField<Target>,
    ) -> BinomialExtensionField<Target> {
        let y_inv = self.p3_ext_inverse(y);
        self.p3_ext_mul(&y_inv, &x)
    }

    fn p3_ext_div_single(
        &mut self,
        x: BinomialExtensionField<Target>,
        y: Target,
    ) -> BinomialExtensionField<Target> {
        let mut res = x.value;
        let y_inv = self.inverse(y);

        for r in res.iter_mut() {
            *r = self.mul(y_inv, *r);
        }
        BinomialExtensionField::<Target> { value: res }
    }

    fn p3_ext_inverse(
        &mut self,
        a: BinomialExtensionField<Target>,
    ) -> BinomialExtensionField<Target> {
        let w = <Self as CircuitBuilderP3ExtArithmetic<F, D>>::p3_w(self);
        match EXT_DEGREE {
            2 => {
                let a_0_square = self.square(a.value[0].clone());
                let a_1_square = self.square(a.value[1].clone());
                let w_mul_sqaure_a_1 = self.mul(w, a_1_square);
                let a_0_square_sub_w_mul_sqaure_a_1 = self.sub(a_0_square, w_mul_sqaure_a_1);

                let scalar = self.inverse(a_0_square_sub_w_mul_sqaure_a_1);
                let a_0_mul_scalar = self.mul(a.value[0].clone(), scalar);
                let a_1_neg = self.neg(a.value[1].clone());
                let a_1_neg_mul_scalar = self.mul(a_1_neg, scalar);

                let mut value = [self.zero(); EXT_DEGREE];
                value[0] = a_0_mul_scalar;
                value[1] = a_1_neg_mul_scalar;

                BinomialExtensionField::<Target> { value }
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
                let mut value = [self.zero(); EXT_DEGREE];
                value[0] = self.mul(scalar, a0_square_minus_a1_mul_a2w);
                value[1] = self.mul(scalar, a2w_mul_a2_sub_a0_a1);
                value[2] = self.mul(scalar, a1_square_minus_a0_mul_a2);

                BinomialExtensionField::<Target> { value }
            }
            _ => self.p3_ext_frobenius_inv(a),
        }
    }

    fn p3_ext_neg(&mut self, x: BinomialExtensionField<Target>) -> BinomialExtensionField<Target> {
        let mut res = x.value;
        for r in res.iter_mut() {
            let r_neg = self.neg(*r);
            *r = r_neg;
        }
        BinomialExtensionField::<Target> { value: res }
    }

    fn p3_ext_add(
        &mut self,
        x: BinomialExtensionField<Target>,
        y: BinomialExtensionField<Target>,
    ) -> BinomialExtensionField<Target> {
        let mut res = x.value;
        for (r, rhs_val) in res.iter_mut().zip(y.value) {
            *r = self.add(*r, rhs_val);
        }
        BinomialExtensionField::<Target> { value: res }
    }

    fn p3_ext_add_single(
        &mut self,
        x: BinomialExtensionField<Target>,
        y: Target,
    ) -> BinomialExtensionField<Target> {
        let mut res = x.value;
        res[0] = self.add(res[0], y);
        BinomialExtensionField::<Target> { value: res }
    }

    fn p3_ext_sub(
        &mut self,
        x: BinomialExtensionField<Target>,
        y: BinomialExtensionField<Target>,
    ) -> BinomialExtensionField<Target> {
        let mut res = x.value;
        for (r, rhs_val) in res.iter_mut().zip(y.value) {
            *r = self.sub(*r, rhs_val);
        }
        BinomialExtensionField::<Target> { value: res }
    }

    fn p3_ext_sub_single(
        &mut self,
        x: BinomialExtensionField<Target>,
        y: Target,
    ) -> BinomialExtensionField<Target> {
        let mut res = x.value;
        res[0] = self.sub(res[0], y);
        BinomialExtensionField::<Target> { value: res }
    }

    fn p3_ext_arr<const SIZE: usize>(&mut self) -> [BinomialExtensionField<Target>; SIZE] {
        core::array::from_fn(|_| BinomialExtensionField::<Target> {
            value: self.p3_arr(),
        })
    }

    fn p3_ext_arr_fn<const SIZE: usize>(
        &mut self,
        f: impl FnMut(usize) -> BinomialExtensionField<Target>,
    ) -> [BinomialExtensionField<Target>; SIZE] {
        core::array::from_fn(f)
    }

    fn p3_ext_mul_single(
        &mut self,
        x: &BinomialExtensionField<Target>,
        y: Target,
    ) -> BinomialExtensionField<Target> {
        BinomialExtensionField::<Target> {
            value: x.value.map(|item| self.mul(item, y.clone())),
        }
    }

    fn p3_ext_mul(
        &mut self,
        x: &BinomialExtensionField<Target>,
        y: &BinomialExtensionField<Target>,
    ) -> BinomialExtensionField<Target> {
        let w_af = <Self as CircuitBuilderP3ExtArithmetic<F, D>>::p3_w(self);
        let mut res = BinomialExtensionField::<Target> {
            value: self.p3_arr(),
        };
        match EXT_DEGREE {
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
                for i in 0..EXT_DEGREE {
                    for j in 0..EXT_DEGREE {
                        if i + j >= EXT_DEGREE {
                            let x_i_mul_w_af = self.mul(x.value[i].clone(), w_af.clone());
                            let x_i_mul_w_af_mul_y_j = self.mul(x_i_mul_w_af, y.value[j].clone());
                            res.value[i + j - EXT_DEGREE] =
                                self.add(res.value[i + j - EXT_DEGREE], x_i_mul_w_af_mul_y_j);
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
        x: BinomialExtensionField<Target>,
        power_log: usize,
    ) -> BinomialExtensionField<Target> {
        let mut res = x.clone();
        for _ in 0..power_log {
            res = self.p3_ext_mul(&res, &res);
        }
        res
    }

    fn p3_ext_powers(
        &mut self,
        x: BinomialExtensionField<Target>,
        n: usize,
    ) -> Vec<BinomialExtensionField<Target>> {
        let mut res = vec![x.clone()];
        for i in 1..n {
            res.push(self.p3_ext_mul(&x, &res[i - 1]));
        }
        res
    }

    fn p3_ext_monomial(&mut self, exponent: usize) -> BinomialExtensionField<Target> {
        let mut value = [self.zero(); EXT_DEGREE];
        value[exponent] = self.one();
        BinomialExtensionField::<Target> { value }
    }

    fn p3_ext_mul_add(
        &mut self,
        x: BinomialExtensionField<Target>,
        y: BinomialExtensionField<Target>,
        z: BinomialExtensionField<Target>,
    ) -> BinomialExtensionField<Target> {
        let x_mul_y = self.p3_ext_mul(&x, &y);
        let x_mul_y_plus_z = self.p3_ext_add(x_mul_y, z);
        x_mul_y_plus_z
    }

    fn p3_ext_add_sub(
        &mut self,
        x: BinomialExtensionField<Target>,
        y: BinomialExtensionField<Target>,
        z: BinomialExtensionField<Target>,
    ) -> BinomialExtensionField<Target> {
        let x_plus_y = self.p3_ext_add(x, y);
        let x_plus_y_minus_z = self.p3_ext_sub(x_plus_y, z);
        x_plus_y_minus_z
    }

    fn connect_p3_ext(
        &mut self,
        x: &BinomialExtensionField<Target>,
        y: &BinomialExtensionField<Target>,
    ) {
        for i in 0..EXT_DEGREE {
            self.connect(x.value[i].clone(), y.value[i].clone());
        }
    }
}

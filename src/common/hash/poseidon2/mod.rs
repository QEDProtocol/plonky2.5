pub mod constants;

use core::marker::PhantomData;

use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};

#[derive(Clone, Debug)]
pub struct Poseidon2Target<F, const D: usize> {
    pub t: usize,
    pub d: usize,
    pub rounds_f_beginning: usize,
    pub rounds_p: usize,
    pub rounds_f_end: usize,
    pub rounds: usize,
    pub mat_internal_diag_m_1: Vec<Target>,
    pub round_constants: Vec<Vec<Target>>,
    _marker: PhantomData<F>,
}

impl<F, const D: usize> Poseidon2Target<F, D>
where
    F: RichField + Extendable<D>,
{
    pub fn new(
        t: usize,
        d: usize,
        rounds_f: usize,
        rounds_p: usize,
        mat_internal_diag_m_1: Vec<Target>,
        round_constants: Vec<Vec<Target>>,
    ) -> Self {
        assert!(d == 3 || d == 5 || d == 7 || d == 11);
        assert_eq!(rounds_f % 2, 0);
        let r = rounds_f / 2;
        let rounds = rounds_f + rounds_p;

        Poseidon2Target {
            t,
            d,
            rounds_f_beginning: r,
            rounds_p,
            rounds_f_end: r,
            rounds,
            mat_internal_diag_m_1: mat_internal_diag_m_1,
            round_constants: round_constants,
            _marker: PhantomData,
        }
    }

    fn sbox(&self, input: &mut [Target], cb: &mut CircuitBuilder<F, D>) {
        input
            .iter_mut()
            .for_each(|item| *item = self.sbox_p(*item, cb))
    }

    fn sbox_p(&self, input: Target, cb: &mut CircuitBuilder<F, D>) -> Target {
        let input2 = cb.mul(input, input);
        if self.d == 3 {
            return cb.mul(input2, input);
        } else if self.d == 5 {
            let input4 = cb.mul(input2, input2);
            return cb.mul(input4, input);
        } else if self.d == 7 {
            let input4 = cb.mul(input2, input2);
            let input3 = cb.mul(input2, input);

            return cb.mul(input4, input3);
        } else {
            panic!("Invalid d paramter, must be 3, 5 or 7");
        }
    }

    fn matmul_internal(&self, input: &mut [Target], cb: &mut CircuitBuilder<F, D>) {
        let t = self.t;
        if t == 2 {
            let sum = cb.add(input[0], input[1]);
            input[0] = cb.add(input[0], sum);
            let input1_plus_input1 = cb.add(input[1], input[1]);
            input[1] = cb.add(input1_plus_input1, sum);
        } else if t == 3 {
            let input0_plus_input1 = cb.add(input[0], input[1]);
            let sum = cb.add(input0_plus_input1, input[2]);
            input[0] = cb.add(input[0], sum);
            input[1] = cb.add(input[1], sum);
            let input2_plus_input2 = cb.add(input[2], input[2]);
            input[2] = cb.add(input2_plus_input2, sum);
        } else if t == 4 || t == 8 || t == 12 || t == 16 || t == 20 || t == 24 {
            let mut sum = input[0];
            for i in 1..t {
                sum = cb.add(sum, input[i]);
            }
            for i in 0..input.len() {
                let mat_internal_diag_m_1_mul_input_i =
                    cb.mul(self.mat_internal_diag_m_1[i], input[i]);
                input[i] = cb.add(mat_internal_diag_m_1_mul_input_i, sum);
            }
        } else {
            panic!("Invalid t parameter, must be 2, 3, 4, 8, 12, 16, 20 or 24");
        }
    }

    fn matmul_external(&self, input: &mut [Target], cb: &mut CircuitBuilder<F, D>) {
        let t = self.t;
        match t {
            2 => {
                // Matrix circ(2, 1)
                let sum = cb.add(input[0], input[1]);
                input[0] = cb.add(input[0], sum);
                input[1] = cb.add(input[1], sum);
            }
            3 => {
                // Matrix circ(2, 1, 1)
                let input0_plus_input1 = cb.add(input[0], input[1]);
                let sum = cb.add(input0_plus_input1, input[2]);
                input[0] = cb.add(input[0], sum);
                input[1] = cb.add(input[1], sum);
                input[2] = cb.add(input[2], sum);
            }
            4 | 8 | 12 | 16 | 20 | 24 => {
                let t4 = t / 4;
                for i in 0..t4 {
                    let start_index = i * 4;
                    let mut t_0 = input[start_index];
                    t_0 = cb.add(t_0, input[start_index + 1]);

                    let mut t_1 = input[start_index + 2];
                    t_1 = cb.add(t_1, input[start_index + 3]);

                    let mut t_2 = input[start_index + 1];
                    t_2 = cb.add(t_2, t_2);
                    t_2 = cb.add(t_2, t_1);

                    let mut t_3 = input[start_index + 3];
                    t_3 = cb.add(t_3, t_3);
                    t_3 = cb.add(t_3, t_0);

                    let mut t_4 = t_1;
                    t_4 = cb.add(t_4, t_4);
                    t_4 = cb.add(t_4, t_4);
                    t_4 = cb.add(t_4, t_3);

                    let mut t_5 = t_0;
                    t_5 = cb.add(t_5, t_5);
                    t_5 = cb.add(t_5, t_5);

                    t_5 = cb.add(t_5, t_2);
                    let mut t_6 = t_3;
                    t_6 = cb.add(t_6, t_5);

                    let mut t_7 = t_2;
                    t_7 = cb.add(t_7, t_4);

                    input[start_index] = t_6;
                    input[start_index + 1] = t_5;
                    input[start_index + 2] = t_7;
                    input[start_index + 3] = t_4;
                }
                let mut stored = [cb.zero(), cb.zero(), cb.zero(), cb.zero()];
                for l in 0..4 {
                    stored[l] = input[l];
                    for j in 1..t4 {
                        stored[l] = cb.add(stored[l], input[4 * j + l]);
                    }
                }
                for i in 0..input.len() {
                    input[i] = cb.add(input[i], stored[i % 4]);
                }
            }
            _ => {
                panic!("Invalid t parameter, must be 2, 3, 4, 8, 12, 16, 20 or 24")
            }
        }
    }

    fn add_rc(&self, input: &mut [Target], rc: &[Target], cb: &mut CircuitBuilder<F, D>) {
        input
            .iter_mut()
            .zip(rc)
            .for_each(|(x, c)| *x = cb.add(*x, *c))
    }

    pub fn permute_mut(&self, input: &mut [Target], cb: &mut CircuitBuilder<F, D>) {
        let t = self.t;
        if input.len() != t {
            panic!("Invalid input length");
        }

        let current_state = input;
        self.matmul_external(current_state, cb);

        for r in 0..self.rounds_f_beginning {
            self.add_rc(current_state, &self.round_constants[r], cb);
            self.sbox(current_state, cb);
            self.matmul_external(current_state, cb);
        }

        let p_end = self.rounds_f_beginning + self.rounds_p;
        for r in self.rounds_f_beginning..p_end {
            current_state[0] = cb.add(current_state[0], self.round_constants[r][0]);
            current_state[0] = self.sbox_p(current_state[0], cb);
            self.matmul_internal(current_state, cb);
        }

        for r in p_end..self.rounds {
            self.add_rc(current_state, &self.round_constants[r], cb);
            self.sbox(current_state, cb);
            self.matmul_external(current_state, cb);
        }
    }
}

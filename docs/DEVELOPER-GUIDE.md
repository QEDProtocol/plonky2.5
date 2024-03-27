# Developer Guide


## Air setup

1. Plonky3

```rust
pub const NUM_FIBONACCI_COLS: usize = 3;

pub struct FibonacciAir {}

impl<F> BaseAir<F> for FibonacciAir {
    fn width(&self) -> usize {
        NUM_FIBONACCI_COLS
    }
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct FibonacciCols<T> {
    pub a: T,
    pub b: T,
    pub c: T,
}

impl<T> Borrow<FibonacciCols<T>> for [T] {
    fn borrow(&self) -> &FibonacciCols<T> {
        debug_assert_eq!(self.len(), NUM_FIBONACCI_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<FibonacciCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<FibonacciCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut FibonacciCols<T> {
        debug_assert_eq!(self.len(), NUM_FIBONACCI_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<FibonacciCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

impl<AB: AirBuilder> Air<AB> for FibonacciAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &FibonacciCols<AB::Var> = main.row_slice(0).borrow();
        let next: &FibonacciCols<AB::Var> = main.row_slice(1).borrow();

        builder.assert_zero(local.a + local.b - local.c);

        let one = AB::Expr::one();
        builder.when_first_row().assert_eq(one.clone(), local.a);
        builder.when_first_row().assert_eq(one, local.b);

        // 1 1 2
        // 1 2 3
        // 2 3 5
        builder
            .when_transition()
            .assert_eq(next.a, local.b);
        builder
            .when_transition()
            .assert_eq(next.b, local.c);
    }
}
```

2. Plonky2.5

```rust
pub const NUM_FIBONACCI_COLS: usize = 3;

pub struct FibonacciAir {}

#[repr(C)]
pub struct FibnacciCols<T> {
    a: T,
    b: T,
    c: T,
}

impl Air for FibonacciAir {
    fn name(&self) -> String {
        "Fibonacci".to_string()
    }

    fn width(&self) -> usize {
        NUM_FIBONACCI_COLS
    }

    fn eval<F: RicherField + Extendable<D>, const D: usize>(
        &self,
        folder: &mut VerifierConstraintFolder<Target>,
        cb: &mut CircuitBuilder<F, D>,
    ) {
        let local = FibnacciCols::<BinomialExtensionField<Target>> {
            a: folder.main.trace_local[0].clone(),
            b: folder.main.trace_local[1].clone(),
            c: folder.main.trace_local[2].clone(),
        };

        let next = FibnacciCols::<BinomialExtensionField<Target>> {
            a: folder.main.trace_next[0].clone(),
            b: folder.main.trace_next[1].clone(),
            c: folder.main.trace_next[2].clone(),
        };

        let local_a_plus_b = cb.p3_ext_add(local.a.clone(), local.b.clone());
        folder.assert_eq(local_a_plus_b, local.c.clone(), cb);

        let one = cb.p3_ext_one();
        folder
            .when_first_row::<F, D>()
            .assert_eq(one.clone(), local.a.clone(), cb);
        folder
            .when_first_row::<F, D>()
            .assert_eq(one.clone(), local.b.clone(), cb);

        folder
            .when_transition::<F, D>()
            .assert_eq(next.a.clone(), local.b, cb);
        folder
            .when_transition::<F, D>()
            .assert_eq(next.b, local.c, cb);
    }
}
```

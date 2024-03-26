pub mod fri;
pub mod proof;
pub mod two_adic;

#[derive(Clone, Copy)]
pub struct Dimensions {
    pub width: usize,
    pub height: usize,
}

pub struct LagrangeSelectors<T> {
    pub is_first_row: T,
    pub is_last_row: T,
    pub is_transition: T,
    pub inv_zeroifier: T,
}

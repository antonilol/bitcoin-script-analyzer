use crate::expr::Expr;
use core::array;
use core::cmp::max;

#[derive(Clone)]
pub struct Stack {
    elements: Vec<Expr>,
    next_element_id: u32,
}

impl Stack {
    pub fn new() -> Self {
        Self {
            elements: Vec::new(),
            next_element_id: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.elements.len()
    }

    pub fn items_used(&self) -> u32 {
        self.next_element_id
    }

    fn grow_to(&mut self, min_len: usize) {
        if self.elements.len() >= min_len {
            return;
        }

        let to_insert = min_len - self.elements.len();
        self.next_element_id += to_insert as u32;
        self.elements.splice(
            0..0,
            (0..to_insert).map(|i| Expr::stack(self.next_element_id - i as u32 - 1)),
        );
    }

    pub fn get_back(&mut self, index: usize) -> &Expr {
        self.grow_to(index + 1);

        &self.elements[self.len() - 1 - index]
    }

    pub fn push(&mut self, value: Expr) {
        self.elements.push(value);
    }

    pub fn extend_from_within_back(&mut self, amount: usize, offset: usize) {
        self.grow_to(amount + offset);

        let to = self.len() - offset;
        let from = to - amount;
        self.elements.extend_from_within(from..to);
    }

    pub fn remove_back(&mut self, index: usize) -> Expr {
        self.grow_to(index + 1);

        self.elements.remove(self.len() - 1 - index)
    }

    pub fn swap_back(&mut self, a: usize, b: usize) {
        self.grow_to(max(a, b) + 1);

        let last = self.len() - 1;
        self.elements.swap(last - a, last - b);
    }

    pub fn pop<const N: usize>(&mut self) -> [Expr; N] {
        self.grow_to(N);

        let mut drain = self.elements.drain(self.len() - N..);
        array::from_fn(|_| drain.next().unwrap())
    }

    pub fn pop_to_box(&mut self, amount: usize) -> Box<[Expr]> {
        self.grow_to(amount);

        self.elements
            .split_off(self.len() - amount)
            .into_boxed_slice()
    }
}

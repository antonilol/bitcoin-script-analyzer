// From the Bitcoin Core source code, file src/script/interpreter.cpp at commit b1a2021f78099c17360dc2179cbcb948059b5969
// Edited for use in this software

// Orignal Bitcoin Core copyright header:
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/// A data type to abstract out the condition stack during script execution.
///
/// Conceptually it acts like a vector of booleans, one for each level of nested
/// IF/THEN/ELSE, indicating whether we're in the active or inactive branch of
/// each.
///
/// The elements on the stack cannot be observed individually; we only need to
/// expose whether the stack is empty and whether or not any false values are
/// present at all. To implement OP_ELSE, a toggle_top modifier is added, which
/// flips the last value without returning it.
///
/// This uses an optimized implementation that does not materialize the
/// actual stack. Instead, it just stores the size of the would-be stack,
/// and the position of the first false value in it.
#[derive(Clone)]
pub struct ConditionStack {
    /// The size of the implied stack.
    m_stack_size: u32,
    /// The position of the first false value on the implied stack, or NO_FALSE if all true.
    m_first_false_pos: u32,
}

impl Default for ConditionStack {
    fn default() -> Self {
        Self::new()
    }
}

impl ConditionStack {
    /// A constant for m_first_false_pos to indicate there are no falses.
    const NO_FALSE: u32 = u32::MAX;

    pub fn new() -> Self {
        Self {
            m_stack_size: 0,
            m_first_false_pos: Self::NO_FALSE,
        }
    }

    pub fn empty(&self) -> bool {
        self.m_stack_size == 0
    }

    pub fn all_true(&self) -> bool {
        self.m_first_false_pos == Self::NO_FALSE
    }

    pub fn push_back(&mut self, f: bool) {
        if self.m_first_false_pos == Self::NO_FALSE && !f {
            // The stack consists of all true values, and a false is added.
            // The first false value will appear at the current size.
            self.m_first_false_pos = self.m_stack_size;
        }
        self.m_stack_size += 1;
    }

    pub fn pop_back(&mut self) {
        self.m_stack_size -= 1;
        if self.m_first_false_pos == self.m_stack_size {
            // When popping off the first false value, everything becomes true.
            self.m_first_false_pos = Self::NO_FALSE;
        }
    }

    pub fn toggle_top(&mut self) {
        if self.m_first_false_pos == Self::NO_FALSE {
            // The current stack is all true values; the first false will be the top.
            self.m_first_false_pos = self.m_stack_size - 1;
        } else if self.m_first_false_pos == self.m_stack_size - 1 {
            // The top is the first false value; toggling it will make everything true.
            self.m_first_false_pos = Self::NO_FALSE;
        } // else {
          // There is a false value, but not on top. No action is needed as toggling
          // anything but the first false value is unobservable.
          // }
    }
}

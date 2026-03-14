use std::collections::VecDeque;

use crate::protocol::sequence24::Sequence24;

#[derive(Debug, Clone)]
pub struct ReliableTracker {
    base: Sequence24,
    seen_ahead: VecDeque<bool>,
    max_window: usize,
}

impl ReliableTracker {
    pub fn new(max_window: usize) -> Self {
        Self {
            base: Sequence24::new(0),
            seen_ahead: VecDeque::new(),
            max_window,
        }
    }

    pub fn see(&mut self, ridx: Sequence24) -> bool {
        if ridx == self.base {
            self.base = self.base.next();
            self.advance_base();
            return true;
        }

        let distance = self.base.distance_to(ridx);
        if distance == 0 || distance as usize > self.max_window {
            return false;
        }

        let offset = distance as usize - 1;
        if self.seen_ahead.len() <= offset {
            self.seen_ahead.resize(offset + 1, false);
        }

        if self.seen_ahead[offset] {
            return false;
        }

        self.seen_ahead[offset] = true;
        true
    }

    pub fn has_seen(&self, ridx: Sequence24) -> bool {
        if ridx == self.base {
            return false;
        }

        let distance = self.base.distance_to(ridx);
        if distance == 0 {
            return true;
        }
        if distance as usize > self.max_window {
            return false;
        }

        let offset = distance as usize - 1;
        self.seen_ahead.get(offset).copied().unwrap_or(false)
    }

    fn advance_base(&mut self) {
        while let Some(true) = self.seen_ahead.front().copied() {
            self.seen_ahead.pop_front();
            self.base = self.base.next();
        }
    }
}

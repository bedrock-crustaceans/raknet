use std::collections::VecDeque;

use crate::protocol::ack::SequenceRange;

#[derive(Debug, Clone)]
pub struct AckQueue {
    max_ranges: usize,
    queue: VecDeque<SequenceRange>,
}

impl AckQueue {
    pub fn new(max_ranges: usize) -> Self {
        Self {
            max_ranges,
            queue: VecDeque::new(),
        }
    }

    pub fn push(&mut self, range: SequenceRange) {
        if self.queue.len() >= self.max_ranges {
            return;
        }

        if let Some(last) = self.queue.back_mut() {
            if last.end.next() == range.start {
                last.end = range.end;
                return;
            }

            if last.end >= range.start && range.end >= last.start {
                last.start = std::cmp::min(last.start, range.start);
                last.end = std::cmp::max(last.end, range.end);
                return;
            }
        }

        if let Some((left, right)) = range.split_wrapping() {
            self.push(left);
            self.push(right);
            return;
        }

        self.queue.push_back(range);
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn pop_for_mtu(
        &mut self,
        mtu: usize,
        base_overhead: usize,
        max_ranges: usize,
    ) -> Vec<SequenceRange> {
        if max_ranges == 0 {
            return Vec::new();
        }

        let mut used = base_overhead;
        let mut out = Vec::new();

        while let Some(front) = self.queue.front() {
            if out.len() >= max_ranges {
                break;
            }

            let size = if let Some((left, right)) = front.split_wrapping() {
                left.encoded_size() + right.encoded_size()
            } else {
                front.encoded_size()
            };

            if !out.is_empty() && used + size > mtu {
                break;
            }

            used += size;
            out.push(self.queue.pop_front().expect("front exists"));
        }

        out
    }
}

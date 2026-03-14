use std::collections::BTreeMap;

use crate::protocol::frame::Frame;
use crate::protocol::sequence24::Sequence24;

struct ChannelState {
    expected_order: Sequence24,
    last_sequence: Option<Sequence24>,
    pending_ordered: BTreeMap<u32, Frame>,
}

impl Default for ChannelState {
    fn default() -> Self {
        Self {
            expected_order: Sequence24::new(0),
            last_sequence: None,
            pending_ordered: BTreeMap::new(),
        }
    }
}

pub enum OrderedResult {
    Ready(Vec<Frame>),
    Buffered,
    DroppedStale,
    DroppedBufferFull,
}

pub enum SequencedResult {
    Accept,
    DropMissingSequence,
    DropStale,
}

pub struct OrderingChannels {
    channels: Vec<ChannelState>,
    max_pending_per_channel: usize,
    max_gap: u32,
}

impl OrderingChannels {
    pub fn new(max_channels: usize, max_pending_per_channel: usize, max_gap: u32) -> Self {
        let count = max_channels.max(1);
        let mut channels = Vec::with_capacity(count);
        for _ in 0..count {
            channels.push(ChannelState::default());
        }

        Self {
            channels,
            max_pending_per_channel: max_pending_per_channel.max(1),
            max_gap: max_gap.max(1),
        }
    }

    pub fn handle_ordered(&mut self, frame: Frame) -> OrderedResult {
        let Some(order_idx) = frame.ordering_index else {
            return OrderedResult::Ready(vec![frame]);
        };

        let max_gap = self.max_gap;
        let max_pending_per_channel = self.max_pending_per_channel;
        let channel = frame.ordering_channel.unwrap_or(0);
        let state = self.channel_state_mut(channel);

        let distance = state.expected_order.distance_to(order_idx);
        if distance == 0 {
            let mut ready = vec![frame];
            state.expected_order = state.expected_order.next();

            while let Some(next) = state.pending_ordered.remove(&state.expected_order.value()) {
                ready.push(next);
                state.expected_order = state.expected_order.next();
            }

            return OrderedResult::Ready(ready);
        }

        if distance > max_gap {
            return OrderedResult::DroppedStale;
        }

        if state.pending_ordered.len() >= max_pending_per_channel {
            return OrderedResult::DroppedBufferFull;
        }

        state
            .pending_ordered
            .entry(order_idx.value())
            .or_insert(frame);
        OrderedResult::Buffered
    }

    pub fn handle_sequenced(&mut self, frame: &Frame) -> SequencedResult {
        let Some(sequence_idx) = frame.sequence_index else {
            return SequencedResult::DropMissingSequence;
        };

        let max_gap = self.max_gap;
        let channel = frame.ordering_channel.unwrap_or(0);
        let state = self.channel_state_mut(channel);

        if let Some(last) = state.last_sequence {
            let distance = last.distance_to(sequence_idx);
            if distance == 0 || distance > max_gap {
                return SequencedResult::DropStale;
            }
        }

        state.last_sequence = Some(sequence_idx);
        SequencedResult::Accept
    }

    pub fn drain_pending_ordered_frames(&mut self) -> Vec<Frame> {
        let mut out = Vec::new();
        for state in &mut self.channels {
            let pending = std::mem::take(&mut state.pending_ordered);
            out.extend(pending.into_values());
        }
        out
    }

    fn channel_state_mut(&mut self, channel: u8) -> &mut ChannelState {
        let idx = channel as usize;
        if idx >= self.channels.len() {
            self.channels.resize_with(idx + 1, ChannelState::default);
        }
        &mut self.channels[idx]
    }
}

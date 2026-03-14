use std::collections::VecDeque;

use crate::protocol::frame::Frame;
use crate::session::SessionState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineFrameAction {
    Deliver,
    Queued,
    Overflow,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SessionPipelineMetricsSnapshot {
    pub pending_unhandled_frames: usize,
    pub pending_unhandled_bytes: usize,
    pub unhandled_frames_queued: u64,
    pub unhandled_frames_flushed: u64,
    pub unhandled_frames_dropped: u64,
}

#[derive(Debug, Clone)]
pub struct SessionPipeline {
    pending_unhandled: VecDeque<Frame>,
    pending_unhandled_bytes: usize,
    max_unhandled_frames: usize,
    max_unhandled_bytes: usize,
    unhandled_frames_queued: u64,
    unhandled_frames_flushed: u64,
    unhandled_frames_dropped: u64,
}

impl SessionPipeline {
    pub fn new(max_unhandled_frames: usize, max_unhandled_bytes: usize) -> Self {
        Self {
            pending_unhandled: VecDeque::new(),
            pending_unhandled_bytes: 0,
            max_unhandled_frames: max_unhandled_frames.max(1),
            max_unhandled_bytes: max_unhandled_bytes.max(1),
            unhandled_frames_queued: 0,
            unhandled_frames_flushed: 0,
            unhandled_frames_dropped: 0,
        }
    }

    pub fn route_inbound_app_frame(
        &mut self,
        state: SessionState,
        frame: Frame,
        out: &mut Vec<Frame>,
    ) -> PipelineFrameAction {
        if state == SessionState::Connected {
            out.push(frame);
            return PipelineFrameAction::Deliver;
        }

        let frame_bytes = frame.payload.len();
        if self.pending_unhandled.len() >= self.max_unhandled_frames
            || self.pending_unhandled_bytes.saturating_add(frame_bytes) > self.max_unhandled_bytes
        {
            self.unhandled_frames_dropped = self.unhandled_frames_dropped.saturating_add(1);
            return PipelineFrameAction::Overflow;
        }

        self.pending_unhandled_bytes = self.pending_unhandled_bytes.saturating_add(frame_bytes);
        self.pending_unhandled.push_back(frame);
        self.unhandled_frames_queued = self.unhandled_frames_queued.saturating_add(1);
        PipelineFrameAction::Queued
    }

    pub fn flush_if_connected(&mut self, state: SessionState, out: &mut Vec<Frame>) -> usize {
        if state != SessionState::Connected || self.pending_unhandled.is_empty() {
            return 0;
        }

        let mut flushed = 0usize;
        while let Some(frame) = self.pending_unhandled.pop_front() {
            self.pending_unhandled_bytes = self
                .pending_unhandled_bytes
                .saturating_sub(frame.payload.len());
            out.push(frame);
            flushed = flushed.saturating_add(1);
        }
        self.unhandled_frames_flushed =
            self.unhandled_frames_flushed.saturating_add(flushed as u64);
        flushed
    }

    pub fn metrics_snapshot(&self) -> SessionPipelineMetricsSnapshot {
        SessionPipelineMetricsSnapshot {
            pending_unhandled_frames: self.pending_unhandled.len(),
            pending_unhandled_bytes: self.pending_unhandled_bytes,
            unhandled_frames_queued: self.unhandled_frames_queued,
            unhandled_frames_flushed: self.unhandled_frames_flushed,
            unhandled_frames_dropped: self.unhandled_frames_dropped,
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{PipelineFrameAction, SessionPipeline};
    use crate::protocol::frame::Frame;
    use crate::protocol::frame_header::FrameHeader;
    use crate::protocol::reliability::Reliability;
    use crate::session::SessionState;

    fn test_frame(payload: &'static [u8]) -> Frame {
        Frame {
            header: FrameHeader::new(Reliability::ReliableOrdered, false, false),
            bit_length: (payload.len() as u16) << 3,
            reliable_index: None,
            sequence_index: None,
            ordering_index: None,
            ordering_channel: None,
            split: None,
            payload: Bytes::from_static(payload),
        }
    }

    #[test]
    fn unhandled_frames_are_buffered_and_flushed_on_connected() {
        let mut pipeline = SessionPipeline::new(4, 1024);
        let mut delivered = Vec::new();

        let action = pipeline.route_inbound_app_frame(
            SessionState::Reply2Sent,
            test_frame(b"\xfehello"),
            &mut delivered,
        );
        assert_eq!(action, PipelineFrameAction::Queued);
        assert!(delivered.is_empty());

        assert_eq!(
            pipeline.flush_if_connected(SessionState::Reply2Sent, &mut delivered),
            0
        );
        assert_eq!(
            pipeline.flush_if_connected(SessionState::Connected, &mut delivered),
            1
        );
        assert_eq!(delivered.len(), 1);

        let metrics = pipeline.metrics_snapshot();
        assert_eq!(metrics.pending_unhandled_frames, 0);
        assert_eq!(metrics.unhandled_frames_queued, 1);
        assert_eq!(metrics.unhandled_frames_flushed, 1);
        assert_eq!(metrics.unhandled_frames_dropped, 0);
    }

    #[test]
    fn overflow_drops_frame_and_reports_overflow() {
        let mut pipeline = SessionPipeline::new(1, 1024);
        let mut delivered = Vec::new();

        let first = pipeline.route_inbound_app_frame(
            SessionState::Reply2Sent,
            test_frame(b"\xfeone"),
            &mut delivered,
        );
        let second = pipeline.route_inbound_app_frame(
            SessionState::Reply2Sent,
            test_frame(b"\xfetwo"),
            &mut delivered,
        );

        assert_eq!(first, PipelineFrameAction::Queued);
        assert_eq!(second, PipelineFrameAction::Overflow);

        let metrics = pipeline.metrics_snapshot();
        assert_eq!(metrics.pending_unhandled_frames, 1);
        assert_eq!(metrics.unhandled_frames_queued, 1);
        assert_eq!(metrics.unhandled_frames_dropped, 1);
    }

    #[test]
    fn connected_state_delivers_immediately_without_queueing() {
        let mut pipeline = SessionPipeline::new(2, 32);
        let mut delivered = Vec::new();

        let action = pipeline.route_inbound_app_frame(
            SessionState::Connected,
            test_frame(b"\xfelive"),
            &mut delivered,
        );

        assert_eq!(action, PipelineFrameAction::Deliver);
        assert_eq!(delivered.len(), 1);

        let metrics = pipeline.metrics_snapshot();
        assert_eq!(metrics.pending_unhandled_frames, 0);
        assert_eq!(metrics.pending_unhandled_bytes, 0);
        assert_eq!(metrics.unhandled_frames_queued, 0);
        assert_eq!(metrics.unhandled_frames_flushed, 0);
        assert_eq!(metrics.unhandled_frames_dropped, 0);
    }

    #[test]
    fn overflow_can_be_triggered_by_byte_budget() {
        let mut pipeline = SessionPipeline::new(4, 6);
        let mut delivered = Vec::new();

        let first = pipeline.route_inbound_app_frame(
            SessionState::Reply2Sent,
            test_frame(b"1234"),
            &mut delivered,
        );
        let second = pipeline.route_inbound_app_frame(
            SessionState::Reply2Sent,
            test_frame(b"5678"),
            &mut delivered,
        );

        assert_eq!(first, PipelineFrameAction::Queued);
        assert_eq!(second, PipelineFrameAction::Overflow);

        let metrics = pipeline.metrics_snapshot();
        assert_eq!(metrics.pending_unhandled_frames, 1);
        assert_eq!(metrics.pending_unhandled_bytes, 4);
        assert_eq!(metrics.unhandled_frames_dropped, 1);
    }
}

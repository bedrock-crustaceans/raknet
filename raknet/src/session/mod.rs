pub mod config;
pub mod congestion_controller;
pub mod error;
pub mod input;
pub mod output;
pub mod state;

use crate::protocol::codec::RakCodec;
use crate::protocol::packets::ack::Ack;
use crate::protocol::packets::connected_ping::ConnectedPing;
use crate::protocol::packets::connected_pong::ConnectedPong;
use crate::protocol::packets::disconnect::Disconnect;
use crate::protocol::packets::frame_set::FrameSet;
use crate::protocol::types::frame::Frame;
use crate::sans::Sans;
use crate::session::congestion_controller::{RakCongestionController, RakCongestionSnapshot};
use crate::session::error::RakSessionError;
use crate::session::input::RakSessionInput;
use crate::session::output::{RakDisconnectReason, RakSessionOutput};
use crate::types::priority::RakPriority;
use crate::types::reliability::RakReliability;
use crate::util::constants::{DGRAM_HEADER_SIZE, DGRAM_MTU_OVERHEAD, UDP_HEADER_SIZE};
use crate::util::socket_addr::get_overhead;
use crate::util::{flags, packet_id, u24};
use config::RakSessionConfig;
use state::RakSessionState;
use std::cmp::{Reverse, min};
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::io::Cursor;
use std::mem::take;
use std::net::{AddrParseError, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::debug;

#[derive(Default, Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct RakSessionId(pub u64);

const RELIABLE_WINDOW: usize = 8192;
const DATAGRAM_WINDOW: usize = 2048;
const ORDER_WINDOW: usize = 2048;
const MAX_SPLIT_COUNT: u32 = 512;
const MAX_CONCURRENT_SPLITS: usize = 16;
const SESSION_TIMEOUT: Duration = Duration::from_millis(15000);

#[derive(Clone, Debug)]
pub struct RakSession {
    pub id: RakSessionId,
    pub addr: SocketAddr,
    pub state: RakSessionState,
    pub guid: u64,
    pub mtu: u16,
    config: RakSessionConfig,

    last_tick: SystemTime,
    last_ping: SystemTime,
    last_recv: SystemTime,
    last_pong: SystemTime,

    congestion_controller: RakCongestionController,
    bandwidth_limited: bool,

    queue: VecDeque<(Box<[u8]>, SocketAddr)>,

    sequences_recv: HashSet<u32>,
    sequences_lost: HashSet<u32>,

    outbound_seq: u32,
    outbound_spl: u16,
    pub(crate) outbound_rel: u32,
    outbound_queue: [VecDeque<Frame>; 4],
    outbound_cache: HashMap<u32, FrameSet>,
    outbound_resend: BinaryHeap<(Reverse<SystemTime>, u32)>,
    outbound_ord_idx: [u32; 32],
    outbound_seq_idx: [u32; 32],

    inbound_seq: u32,
    inbound_rel_seen: HashSet<u32>,
    inbound_rel_order: VecDeque<u32>,
    inbound_spl_queue: HashMap<u16, HashMap<u32, Frame>>,
    inbound_spl_bytes: usize,
    inbound_spl_last: HashMap<u16, SystemTime>,
    inbound_ord_queue: HashMap<u8, HashMap<u32, Frame>>,
    inbound_ord_bytes: usize,
    inbound_ord_idx: [u32; 32],
    inbound_seq_idx: [u32; 32],

    output: VecDeque<RakSessionOutput>,
}

/// [`RakSession`] in a serializable form, so a session can be moved to another process
/// and resumed there.
///
/// Times are milliseconds from [`RakSessionSnapshot::epoch_ms`], and the queues are
/// `Vec`s, since `SystemTime`, `VecDeque` and `BinaryHeap` have no `Facet` impl. Pending
/// output is not carried - drain it with `poll()` before taking a snapshot.
#[derive(Clone, Debug, facet::Facet)]
pub struct RakSessionSnapshot {
    pub id: u64,
    /// Text form: facet-json cannot construct a `SocketAddr` on the way back in.
    pub addr: String,
    pub state: RakSessionState,
    pub guid: u64,
    pub mtu: u16,
    pub config: RakSessionConfig,

    /// Wall clock the offsets below are measured from.
    pub epoch_ms: u64,
    pub last_tick_ms: u64,
    pub last_ping_ms: u64,
    pub last_recv_ms: u64,
    pub last_pong_ms: u64,

    pub congestion_controller: RakCongestionSnapshot,

    pub queue: Vec<(Box<[u8]>, String)>,

    pub sequences_recv: HashSet<u32>,
    pub sequences_lost: HashSet<u32>,

    pub outbound_seq: u32,
    pub outbound_spl: u16,
    pub outbound_rel: u32,
    pub outbound_queue: Vec<Vec<Frame>>,
    pub outbound_cache: Vec<(u32, FrameSet)>,
    pub outbound_resend: Vec<(u64, u32)>,
    pub outbound_ord_idx: [u32; 32],
    pub outbound_seq_idx: [u32; 32],

    pub inbound_seq: u32,
    pub inbound_rel_seen: HashSet<u32>,
    pub inbound_rel_order: Vec<u32>,
    pub inbound_spl_queue: Vec<(u16, Vec<(u32, Frame)>)>,
    pub inbound_ord_queue: Vec<(u8, Vec<(u32, Frame)>)>,
    pub inbound_ord_idx: [u32; 32],
    pub inbound_seq_idx: [u32; 32],
}

impl RakSession {
    /// Captures this session's protocol state.
    pub fn snapshot(&self) -> RakSessionSnapshot {
        let epoch = UNIX_EPOCH;
        RakSessionSnapshot {
            id: self.id.0,
            addr: self.addr.to_string(),
            state: self.state,
            guid: self.guid,
            mtu: self.mtu,
            config: self.config.clone(),

            epoch_ms: 0,
            last_tick_ms: millis_since(epoch, self.last_tick),
            last_ping_ms: millis_since(epoch, self.last_ping),
            last_recv_ms: millis_since(epoch, self.last_recv),
            last_pong_ms: millis_since(epoch, self.last_pong),

            congestion_controller: self.congestion_controller.snapshot(epoch),

            queue: self
                .queue
                .iter()
                .map(|(bytes, addr)| (bytes.clone(), addr.to_string()))
                .collect(),

            sequences_recv: self.sequences_recv.clone(),
            sequences_lost: self.sequences_lost.clone(),

            outbound_seq: self.outbound_seq,
            outbound_spl: self.outbound_spl,
            outbound_rel: self.outbound_rel,
            outbound_queue: self
                .outbound_queue
                .iter()
                .map(|q| q.iter().cloned().collect())
                .collect(),
            outbound_cache: self.outbound_cache.clone().into_iter().collect(),
            outbound_resend: self
                .outbound_resend
                .iter()
                .map(|(at, seq)| (millis_since(epoch, at.0), *seq))
                .collect(),
            outbound_ord_idx: self.outbound_ord_idx,
            outbound_seq_idx: self.outbound_seq_idx,

            inbound_seq: self.inbound_seq,
            inbound_rel_seen: self.inbound_rel_seen.clone(),
            inbound_rel_order: self.inbound_rel_order.iter().copied().collect(),
            inbound_spl_queue: flatten_nested(&self.inbound_spl_queue),
            inbound_ord_queue: flatten_nested(&self.inbound_ord_queue),
            inbound_ord_idx: self.inbound_ord_idx,
            inbound_seq_idx: self.inbound_seq_idx,
        }
    }

    /// Rebuilds a session from [`RakSession::snapshot`].
    pub fn restore(snapshot: RakSessionSnapshot) -> Result<Self, AddrParseError> {
        let epoch = UNIX_EPOCH + Duration::from_millis(snapshot.epoch_ms);
        let at = |offset: u64| epoch + Duration::from_millis(offset);

        let mut outbound_queue: [VecDeque<Frame>; 4] = Default::default();
        for (channel, frames) in snapshot.outbound_queue.into_iter().enumerate().take(4) {
            outbound_queue[channel] = frames.into();
        }

        let inbound_spl_queue = rebuild_nested(snapshot.inbound_spl_queue);
        let inbound_spl_bytes = payload_bytes(&inbound_spl_queue);
        let inbound_spl_last = inbound_spl_queue
            .keys()
            .map(|&split_id| (split_id, at(snapshot.last_recv_ms)))
            .collect();
        let inbound_ord_queue = rebuild_nested(snapshot.inbound_ord_queue);
        let inbound_ord_bytes = payload_bytes(&inbound_ord_queue);

        let queue = snapshot
            .queue
            .into_iter()
            .map(|(bytes, addr)| Ok((bytes, addr.parse()?)))
            .collect::<Result<VecDeque<_>, AddrParseError>>()?;

        Ok(Self {
            id: RakSessionId(snapshot.id),
            addr: snapshot.addr.parse()?,
            state: snapshot.state,
            guid: snapshot.guid,
            mtu: snapshot.mtu,
            config: snapshot.config,

            last_tick: at(snapshot.last_tick_ms),
            last_ping: at(snapshot.last_ping_ms),
            last_recv: at(snapshot.last_recv_ms),
            last_pong: at(snapshot.last_pong_ms),

            congestion_controller: RakCongestionController::restore(
                snapshot.congestion_controller,
                epoch,
            ),
            bandwidth_limited: false,

            queue,

            sequences_recv: snapshot.sequences_recv,
            sequences_lost: snapshot.sequences_lost,

            outbound_seq: snapshot.outbound_seq,
            outbound_spl: snapshot.outbound_spl,
            outbound_rel: snapshot.outbound_rel,
            outbound_queue,
            outbound_cache: snapshot.outbound_cache.into_iter().collect(),
            outbound_resend: snapshot
                .outbound_resend
                .into_iter()
                .map(|(offset, seq)| (Reverse(at(offset)), seq))
                .collect(),
            outbound_ord_idx: snapshot.outbound_ord_idx,
            outbound_seq_idx: snapshot.outbound_seq_idx,

            inbound_seq: snapshot.inbound_seq,
            inbound_rel_seen: snapshot.inbound_rel_seen,
            inbound_rel_order: snapshot.inbound_rel_order.into(),
            inbound_spl_queue,
            inbound_spl_bytes,
            inbound_spl_last,
            inbound_ord_queue,
            inbound_ord_bytes,
            inbound_ord_idx: snapshot.inbound_ord_idx,
            inbound_seq_idx: snapshot.inbound_seq_idx,

            output: VecDeque::new(),
        })
    }
}

fn payload_bytes<K>(map: &HashMap<K, HashMap<u32, Frame>>) -> usize {
    map.values()
        .flat_map(HashMap::values)
        .map(|f| f.payload.len())
        .sum()
}

fn millis_since(epoch: SystemTime, at: SystemTime) -> u64 {
    at.duration_since(epoch).unwrap_or_default().as_millis() as u64
}

/// JSON object keys are strings, so maps keyed by an integer are carried as pairs.
fn flatten_nested<K: Copy + Eq + std::hash::Hash>(
    map: &HashMap<K, HashMap<u32, Frame>>,
) -> Vec<(K, Vec<(u32, Frame)>)> {
    map.iter()
        .map(|(key, inner)| (*key, inner.clone().into_iter().collect()))
        .collect()
}

fn rebuild_nested<K: Eq + std::hash::Hash>(
    pairs: Vec<(K, Vec<(u32, Frame)>)>,
) -> HashMap<K, HashMap<u32, Frame>> {
    pairs
        .into_iter()
        .map(|(key, inner)| (key, inner.into_iter().collect()))
        .collect()
}

impl Sans for RakSession {
    type Input = RakSessionInput;
    type Output = RakSessionOutput;
    type Error = RakSessionError;

    fn handle(&mut self, msg: Self::Input) -> Result<(), Self::Error> {
        if matches!(self.state, RakSessionState::Disconnected) {
            return Err(RakSessionError::Closed);
        }

        match msg {
            RakSessionInput::Datagram(buf, now) => {
                self.last_recv = now;

                let Some(&b) = buf.first() else {
                    return Ok(());
                };

                let mut cursor = Cursor::new(buf.as_ref());
                match b {
                    _ if b & flags::VALID == 0 => debug!(
                        "received unknown online packet {:#04X} from {}",
                        b, self.addr
                    ),
                    _ if b & (flags::ACK | flags::NACK) != 0 => {
                        self.handle_ack(&mut cursor, now)?
                    }
                    _ => self.handle_frame_set(&mut cursor, now)?,
                }
            }
            RakSessionInput::Send(buf, reliability, priority, now) => {
                self.send_frame(Frame::new(reliability, buf), priority, now)?
            }
            RakSessionInput::Update(now) => self.handle_timeout(now)?,
            RakSessionInput::Disconnect(now) => {
                self.disconnect(true, RakDisconnectReason::Requested, now)?
            }
        }
        Ok(())
    }

    fn poll(&mut self) -> Option<Self::Output> {
        self.output.pop_front()
    }
}

impl RakSession {
    pub fn new<F>(id: RakSessionId, addr: SocketAddr, guid: u64, mtu: u16, conf: F) -> Self
    where
        F: FnOnce(&mut RakSessionConfig),
    {
        let mtu = mtu - UDP_HEADER_SIZE - get_overhead(&addr);
        let mut config = RakSessionConfig::default();
        conf(&mut config);

        let now = SystemTime::now();

        Self {
            id,
            addr,
            guid,
            mtu,
            config,

            last_tick: now,
            last_ping: now,
            last_recv: now,
            last_pong: now,

            state: RakSessionState::Connected,
            congestion_controller: RakCongestionController::new(mtu as usize),
            bandwidth_limited: false,

            sequences_recv: HashSet::new(),
            sequences_lost: HashSet::new(),

            queue: VecDeque::new(),

            outbound_seq: 0,
            outbound_spl: 0,
            outbound_rel: 0,
            outbound_queue: [
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
            ],
            outbound_cache: HashMap::new(),
            outbound_resend: BinaryHeap::new(),
            outbound_ord_idx: [0; 32],
            outbound_seq_idx: [0; 32],

            inbound_seq: 0,
            inbound_rel_seen: HashSet::new(),
            inbound_rel_order: VecDeque::new(),
            inbound_spl_queue: HashMap::new(),
            inbound_spl_bytes: 0,
            inbound_spl_last: HashMap::new(),
            inbound_ord_queue: HashMap::new(),
            inbound_ord_bytes: 0,
            inbound_ord_idx: [0; 32],
            inbound_seq_idx: [0; 32],

            output: VecDeque::new(),
        }
    }

    pub fn get_addr(self) -> SocketAddr {
        self.addr
    }

    pub fn get_state(&self) -> RakSessionState {
        self.state
    }

    pub fn rtt(&self) -> Duration {
        self.congestion_controller.rtt()
    }

    pub fn max_message_len(&self) -> usize {
        usize::try_from(self.config.max_queued_bytes)
            .unwrap_or(0)
            .max(self.mtu as usize)
    }

    fn handle_timeout(&mut self, now: SystemTime) -> Result<(), RakSessionError> {
        if now >= self.last_recv + SESSION_TIMEOUT {
            debug!(
                "detected stale connection from {}, disconnecting...",
                self.addr
            );

            self.disconnect(true, RakDisconnectReason::Timeout, now)?;
            return Ok(());
        }

        self.evict_stale_splits(now);

        if self.config.autoflush && now >= self.last_tick + self.config.autoflush_interval_ms {
            self.tick(now)?;

            self.last_tick = now;
        }

        if now >= self.last_ping + Duration::from_millis(2000) {
            let ping = ConnectedPing {
                timestamp: now.duration_since(UNIX_EPOCH)?.as_millis() as u64,
            };

            let mut buf = Vec::with_capacity(ping.size_hint());
            ping.serialize(&mut buf)?;
            let buf = buf.into_boxed_slice();

            let reliability = RakReliability::Unreliable;
            let priority = RakPriority::Immediate;
            self.handle(RakSessionInput::Send(buf, reliability, priority, now))?;

            self.last_ping = now;
        }

        let mut next = min(
            self.last_ping + Duration::from_millis(2000),
            self.last_recv + SESSION_TIMEOUT,
        );
        if self.config.autoflush {
            next = min(next, self.last_tick + self.config.autoflush_interval_ms);
        }

        let duration = next.duration_since(now).unwrap_or(Duration::from_secs(0));

        self.output.push_back(RakSessionOutput::Wait(duration));
        Ok(())
    }

    fn evict_stale_splits(&mut self, now: SystemTime) {
        let last = &self.inbound_spl_last;
        let mut freed = 0;
        self.inbound_spl_queue.retain(|split_id, fragments| {
            let fresh = last
                .get(split_id)
                .is_some_and(|&at| now < at + SESSION_TIMEOUT);
            if !fresh {
                freed += fragments.values().map(|f| f.payload.len()).sum::<usize>();
            }
            fresh
        });
        let queue = &self.inbound_spl_queue;
        self.inbound_spl_last
            .retain(|split_id, _| queue.contains_key(split_id));
        self.inbound_spl_bytes = self.inbound_spl_bytes.saturating_sub(freed);

        if freed > 0 {
            debug!(
                "evicted {} bytes of stale partial splits from {}",
                freed, self.addr
            );
        }
    }

    pub fn tick(&mut self, now: SystemTime) -> Result<(), RakSessionError> {
        if matches!(self.state, RakSessionState::Disconnected) {
            return Ok(());
        }

        let received = self.sequences_recv.drain().collect();
        self.queue_acks(received, false)?;
        let lost = self.sequences_lost.drain().collect();
        self.queue_acks(lost, true)?;

        self.send_stale(now)?;
        self.send_queue(now)?;
        self.flush();
        Ok(())
    }

    fn queue_acks(&mut self, sequences: Vec<u32>, is_nack: bool) -> Result<(), RakSessionError> {
        for ack in Ack::split(sequences, is_nack, self.mtu as usize) {
            let mut buf = Vec::with_capacity(ack.size_hint());
            ack.serialize(&mut buf)?;
            self.queue.push_back((buf.into_boxed_slice(), self.addr));
        }
        Ok(())
    }

    fn send_stale(&mut self, now: SystemTime) -> Result<(), RakSessionError> {
        let mut pending = Vec::new();

        let mut bandwidth = self.congestion_controller.retransmission_bandwidth();

        while let Some(&(Reverse(sent), seq)) = self.outbound_resend.peek() {
            if sent > now {
                break;
            }

            let Some(set) = self.outbound_cache.get(&seq) else {
                self.outbound_resend.pop();
                continue;
            };

            let size = set.size_hint();
            if size > bandwidth {
                break;
            }
            bandwidth -= size;

            self.outbound_resend.pop();

            self.congestion_controller
                .resent(self.outbound_seq, self.bandwidth_limited);

            let set = self.outbound_cache.remove(&seq).expect("unreachable");
            pending.push(set);
        }

        for set in pending {
            self.send_frame_set(set, false, false, now)?;
        }
        Ok(())
    }

    fn send_queue(&mut self, now: SystemTime) -> Result<(), RakSessionError> {
        let mut bandwidth = self.congestion_controller.transmission_bandwidth();

        let mut frames = Vec::new();
        for queue in &mut self.outbound_queue {
            while let Some(frame) = queue.pop_front_if(|f| f.size_hint() <= bandwidth) {
                bandwidth -= frame.size_hint();
                frames.push(frame);
            }
        }
        self.bandwidth_limited = self.outbound_queue.iter().any(|queue| !queue.is_empty());

        if frames.is_empty() {
            return Ok(());
        };

        let sets = self.make_sets(frames);
        for set in sets {
            self.send_frame_set(set, false, true, now)?;
        }
        Ok(())
    }

    fn make_sets(&mut self, frames: Vec<Frame>) -> Vec<FrameSet> {
        let mut sets = Vec::new();

        let max = (self.mtu - DGRAM_HEADER_SIZE) as usize;

        let mut batch = Vec::new();
        let mut size = DGRAM_HEADER_SIZE as usize;

        for frame in frames {
            let frame_size = frame.size_hint();

            if frame_size > max {
                // TODO: make this an error instead of panic
                panic!(
                    "Frame too large for FrameSet, size: {}, max size: {}",
                    frame_size, max
                );
            }

            if size + frame_size > max {
                let continuous_send = batch.iter().any(Frame::is_split);

                sets.push(FrameSet {
                    sequence: self.outbound_seq,
                    frames: take(&mut batch),
                    continuous_send,
                    needs_b_and_as: true,
                    is_pair: false,
                });
                self.outbound_seq = u24::add(self.outbound_seq, 1);

                size = DGRAM_HEADER_SIZE as usize;
            }

            size += frame_size;
            batch.push(frame);
        }

        if !batch.is_empty() {
            let continuous_send = batch.iter().any(Frame::is_split);

            sets.push(FrameSet {
                sequence: self.outbound_seq,
                frames: batch,
                continuous_send,
                needs_b_and_as: true,
                is_pair: false,
            });
            self.outbound_seq = u24::add(self.outbound_seq, 1);
        }

        sets
    }

    fn send_frame_set(
        &mut self,
        frameset: FrameSet,
        immediate: bool,
        first_send: bool,
        now: SystemTime,
    ) -> Result<(), RakSessionError> {
        let mut buf = Vec::with_capacity(frameset.size_hint());
        frameset.serialize(&mut buf)?;
        let buf = buf.into_boxed_slice();

        match immediate {
            true => self
                .output
                .push_back(RakSessionOutput::Datagram(buf, self.addr)),
            false => {
                self.queue.push_back((buf, self.addr));
            }
        }

        let reliable = frameset.frames.iter().any(|f| f.reliability.is_reliable());
        if reliable {
            let resend = now + self.congestion_controller.retransmission_timeout();

            if first_send {
                self.congestion_controller
                    .sent(frameset.sequence, frameset.size_hint(), now);
            }
            self.outbound_resend
                .push((Reverse(resend), frameset.sequence));
            self.outbound_cache.insert(frameset.sequence, frameset);
        }
        Ok(())
    }

    fn flush(&mut self) {
        for (buf, addr) in self.queue.drain(..) {
            self.output.push_back(RakSessionOutput::Datagram(buf, addr));
        }
    }

    fn send_frame(
        &mut self,
        frame: Frame,
        priority: RakPriority,
        now: SystemTime,
    ) -> Result<(), RakSessionError> {
        let max_size = (self.mtu - DGRAM_MTU_OVERHEAD) as usize;

        let order_channel = frame.order_channel;

        let mut reliability = frame.reliability;
        let mut split_id = 0;

        let payloads = if frame.size_hint() > max_size {
            reliability = match reliability {
                RakReliability::Unreliable => RakReliability::Reliable,
                RakReliability::UnreliableSequenced => RakReliability::ReliableSequenced,
                RakReliability::UnreliableWithAckReceipt => RakReliability::ReliableWithAckReceipt,
                val => val,
            };
            split_id = self.outbound_spl;
            self.outbound_spl = self.outbound_spl.wrapping_add(1);

            let split_size = frame.payload.len().div_ceil(max_size);

            let mut payloads = Vec::with_capacity(split_size);
            for i in 0..split_size {
                let start = i * max_size;
                let end = min(start + max_size, frame.payload.len());

                payloads.push(frame.payload[start..end].into());
            }
            payloads
        } else {
            vec![frame.payload]
        };

        let mut ord_idx = 0;
        let mut seq_idx = 0;
        if frame.reliability.is_sequenced() {
            ord_idx = self.outbound_ord_idx[order_channel as usize];
            seq_idx = {
                let r = &mut self.outbound_seq_idx[order_channel as usize];
                let val = *r;
                *r = u24::add(val, 1);
                val
            };
        } else if frame.reliability.is_ordered() {
            ord_idx = {
                let r = &mut self.outbound_ord_idx[order_channel as usize];
                let val = *r;
                *r = u24::add(val, 1);
                val
            };
            self.outbound_seq_idx[order_channel as usize] = 0;
        }

        let split_size = payloads.len();
        let frames = payloads
            .into_iter()
            .enumerate()
            .map(|(i, payload)| Frame {
                reliability,
                payload,
                reliable_index: match reliability.is_reliable() {
                    true => {
                        let val = self.outbound_rel;
                        self.outbound_rel = u24::add(val, 1);
                        val
                    }
                    false => 0,
                },
                sequence_index: seq_idx,
                order_index: ord_idx,
                order_channel,
                split_size: if split_size > 1 { split_size as u32 } else { 0 },
                split_id,
                split_index: i as u32,
            })
            .collect();

        self.queue_frames(frames, priority, now)?;
        Ok(())
    }

    fn queue_frames(
        &mut self,
        frames: Vec<Frame>,
        priority: RakPriority,
        now: SystemTime,
    ) -> Result<(), RakSessionError> {
        match priority {
            RakPriority::Immediate => {
                let sets = self.make_sets(frames);
                for set in sets {
                    self.send_frame_set(set, true, true, now)?;
                }
            }
            _ => self.outbound_queue[priority as usize].extend(frames),
        }
        Ok(())
    }

    fn handle_ack(
        &mut self,
        buf: &mut Cursor<&[u8]>,
        now: SystemTime,
    ) -> Result<(), RakSessionError> {
        let ack = Ack::deserialize(buf)?;

        for seq in ack.sequences {
            let Some(set) = self.outbound_cache.remove(&seq) else {
                continue;
            };
            match ack.is_nack {
                true => {
                    self.congestion_controller
                        .lost(set.sequence, set.size_hint());
                    self.queue_frames(set.frames, RakPriority::Immediate, now)?;
                    self.congestion_controller.nacked(self.bandwidth_limited);
                }
                false => {
                    self.congestion_controller.acked(
                        now,
                        set.sequence,
                        set.size_hint(),
                        self.bandwidth_limited,
                    );
                }
            }
        }
        Ok(())
    }

    fn handle_frame_set(
        &mut self,
        buf: &mut Cursor<&[u8]>,
        now: SystemTime,
    ) -> Result<(), RakSessionError> {
        let set = FrameSet::deserialize(buf)?;

        let ahead = u24::distance(self.inbound_seq, set.sequence);
        if ahead >= DATAGRAM_WINDOW as i32 {
            debug!(
                "dropping FrameSet {} from {}, too far ahead of {}",
                set.sequence, self.addr, self.inbound_seq
            );
            return Ok(());
        }

        if !self.sequences_recv.insert(set.sequence) {
            debug!(
                "received duplicate FrameSet {} from {}",
                set.sequence, self.addr
            );
            return Ok(());
        }

        self.sequences_lost.remove(&set.sequence);

        if ahead < 0 {
            debug!(
                "received out of order FrameSet {} from {}, expected {}",
                set.sequence, self.addr, self.inbound_seq
            );
        } else {
            let mut missing = self.inbound_seq;
            while missing != set.sequence && self.sequences_lost.len() < DATAGRAM_WINDOW {
                self.sequences_lost.insert(missing);
                missing = u24::add(missing, 1);
            }
            self.inbound_seq = u24::add(set.sequence, 1);
        }

        for frame in set.frames {
            if matches!(self.state, RakSessionState::Disconnected) {
                break;
            }
            self.handle_frame(frame, now)?;
        }
        Ok(())
    }

    fn handle_frame(&mut self, frame: Frame, now: SystemTime) -> Result<(), RakSessionError> {
        if frame.reliability.is_reliable() && !self.track_reliable(frame.reliable_index) {
            debug!(
                "received duplicate reliable frame {} from {}",
                frame.reliable_index, self.addr
            );
            return Ok(());
        }

        let max_channels = (self.config.ordering_channels as usize).min(self.inbound_ord_idx.len());
        if (frame.reliability.is_ordered() || frame.reliability.is_sequenced())
            && frame.order_channel as usize >= max_channels
        {
            debug!(
                "received frame with out of range order channel {} from {}",
                frame.order_channel, self.addr
            );
            return Ok(());
        }

        match frame.is_split() {
            true => self.handle_split_frame(frame, now)?,
            false => self.handle_full_frame(frame, now)?,
        }
        Ok(())
    }

    fn track_reliable(&mut self, index: u32) -> bool {
        if !self.inbound_rel_seen.insert(index) {
            return false;
        }

        self.inbound_rel_order.push_back(index);

        while self.inbound_rel_order.len() > RELIABLE_WINDOW {
            if let Some(old) = self.inbound_rel_order.pop_front() {
                self.inbound_rel_seen.remove(&old);
            }
        }

        true
    }

    fn handle_full_frame(&mut self, frame: Frame, now: SystemTime) -> Result<(), RakSessionError> {
        let channel = frame.order_channel as usize;

        if frame.reliability.is_sequenced() {
            if u24::distance(self.inbound_seq_idx[channel], frame.sequence_index) < 0
                || u24::distance(self.inbound_ord_idx[channel], frame.order_index) < 0
            {
                debug!(
                    "received out of order FrameSet {} from {}",
                    frame.order_channel, self.addr
                );
            }

            self.inbound_seq_idx[channel] = u24::add(frame.sequence_index, 1);

            return self.handle_packet(frame.payload, now);
        }

        if frame.reliability.is_ordered() {
            let ahead = u24::distance(self.inbound_ord_idx[channel], frame.order_index);

            if ahead == 0 {
                self.inbound_seq_idx[channel] = 0;
                self.inbound_ord_idx[channel] = u24::add(frame.order_index, 1);

                self.handle_packet(frame.payload, now)?;

                let mut idx = self.inbound_ord_idx[channel];

                let mut packets = Vec::new();
                {
                    let unord_queue = self
                        .inbound_ord_queue
                        .entry(frame.order_channel)
                        .or_default();
                    while let Some(unord_frame) = unord_queue.remove(&idx) {
                        self.inbound_ord_bytes = self
                            .inbound_ord_bytes
                            .saturating_sub(unord_frame.payload.len());
                        packets.push(unord_frame.payload);

                        idx = u24::add(idx, 1);
                    }
                }
                self.inbound_ord_idx[channel] = idx;

                for packet in packets {
                    self.handle_packet(packet, now)?;
                }
                return Ok(());
            }

            if ahead >= ORDER_WINDOW as i32 {
                debug!(
                    "closing session with {}, order index {} too far ahead of {}",
                    self.addr, frame.order_index, self.inbound_ord_idx[channel]
                );
                return self.disconnect(true, RakDisconnectReason::ProtocolViolation, now);
            }

            if ahead > 0 {
                if self.exceeds_queued_bytes(frame.payload.len()) {
                    debug!(
                        "closing session with {}, buffered ordered bytes would exceed max_queued_bytes",
                        self.addr
                    );
                    return self.disconnect(true, RakDisconnectReason::ProtocolViolation, now);
                }

                self.inbound_ord_bytes += frame.payload.len();
                if let Some(replaced) = self
                    .inbound_ord_queue
                    .entry(frame.order_channel)
                    .or_default()
                    .insert(frame.order_index, frame)
                {
                    self.inbound_ord_bytes = self
                        .inbound_ord_bytes
                        .saturating_sub(replaced.payload.len());
                }
            }
            return Ok(());
        }

        self.handle_packet(frame.payload, now)?;
        Ok(())
    }

    fn handle_split_frame(&mut self, frame: Frame, now: SystemTime) -> Result<(), RakSessionError> {
        if frame.split_index >= frame.split_size {
            debug!(
                "received split frame with out of range index {} (size {}) from {}",
                frame.split_index, frame.split_size, self.addr
            );
            return Ok(());
        }

        if let Some(reason) = self.split_violation(&frame) {
            debug!("closing session with {}, {}", self.addr, reason);
            return self.disconnect(true, RakDisconnectReason::ProtocolViolation, now);
        }

        if self.exceeds_queued_bytes(frame.payload.len()) {
            debug!(
                "dropping split frame from {}, buffered split bytes would exceed max_queued_bytes",
                self.addr
            );
            return Ok(());
        }

        let split_id = frame.split_id;
        let split_size = frame.split_size;

        let fragments = self.inbound_spl_queue.entry(split_id).or_default();
        if fragments.contains_key(&frame.split_index) {
            return Ok(());
        }
        self.inbound_spl_bytes += frame.payload.len();
        fragments.insert(frame.split_index, frame);
        self.inbound_spl_last.insert(split_id, now);

        if fragments.len() as u32 != split_size {
            return Ok(());
        }

        self.inbound_spl_last.remove(&split_id);
        let Some(mut fragments) = self.inbound_spl_queue.remove(&split_id) else {
            return Ok(());
        };
        let buffered: usize = fragments.values().map(|f| f.payload.len()).sum();
        self.inbound_spl_bytes = self.inbound_spl_bytes.saturating_sub(buffered);

        let mut payload = Vec::with_capacity(buffered);
        let mut whole = None;
        for i in 0..split_size {
            let Some(fragment) = fragments.remove(&i) else {
                return Ok(());
            };
            payload.extend_from_slice(&fragment.payload);
            whole.get_or_insert(fragment);
        }
        let Some(mut whole) = whole else {
            return Ok(());
        };

        whole.payload = payload.into_boxed_slice();
        whole.split_size = 0;
        whole.split_id = 0;
        whole.split_index = 0;

        self.handle_full_frame(whole, now)
    }

    fn exceeds_queued_bytes(&self, additional: usize) -> bool {
        self.inbound_spl_bytes + self.inbound_ord_bytes + additional
            > self.config.max_queued_bytes as usize
    }

    fn split_violation(&self, frame: &Frame) -> Option<&'static str> {
        if frame.payload.is_empty() {
            return Some("empty split fragment");
        }
        if frame.split_size > MAX_SPLIT_COUNT {
            return Some("split count exceeds the maximum");
        }
        match self.inbound_spl_queue.get(&frame.split_id) {
            Some(fragments) => fragments
                .values()
                .next()
                .is_some_and(|f| f.split_size != frame.split_size)
                .then_some("split count changed mid-split"),
            None => (self.inbound_spl_queue.len() >= MAX_CONCURRENT_SPLITS)
                .then_some("too many concurrent splits"),
        }
    }

    fn handle_packet(&mut self, buf: Box<[u8]>, now: SystemTime) -> Result<(), RakSessionError> {
        let Some(&b) = buf.first() else {
            return Ok(());
        };

        let mut cursor = Cursor::new(buf.as_ref());
        match b {
            packet_id::CONNECTED_PING => self.handle_connected_ping(&mut cursor, now)?,
            packet_id::CONNECTED_PONG => self.handle_connected_pong(&mut cursor, now)?,
            packet_id::DISCONNECT => self.handle_disconnect(&mut cursor, now)?,
            _ => self.output.push_back(RakSessionOutput::Packet(buf)),
        };
        Ok(())
    }

    fn handle_connected_ping(
        &mut self,
        buf: &mut Cursor<&[u8]>,
        now: SystemTime,
    ) -> Result<(), RakSessionError> {
        let ping = ConnectedPing::deserialize(buf)?;

        let pong = ConnectedPong {
            ping_timestamp: ping.timestamp,
            timestamp: now.duration_since(UNIX_EPOCH)?.as_millis() as u64,
        };

        let mut buf = Vec::with_capacity(pong.size_hint());
        pong.serialize(&mut buf)?;
        let buf = buf.into_boxed_slice();

        let reliability = RakReliability::Unreliable;
        let priority = RakPriority::Immediate;
        _ = self.handle(RakSessionInput::Send(buf, reliability, priority, now));
        Ok(())
    }

    fn handle_connected_pong(
        &mut self,
        buf: &mut Cursor<&[u8]>,
        now: SystemTime,
    ) -> Result<(), RakSessionError> {
        let pong = ConnectedPong::deserialize(buf)?;

        if UNIX_EPOCH + Duration::from_millis(pong.ping_timestamp) >= self.last_ping {
            self.last_pong = now;
        }
        Ok(())
    }

    fn handle_disconnect(
        &mut self,
        buf: &mut Cursor<&[u8]>,
        now: SystemTime,
    ) -> Result<(), RakSessionError> {
        Disconnect::deserialize(buf)?;

        debug!("session closed by {}", self.addr);

        self.disconnect(false, RakDisconnectReason::Remote, now)?;
        Ok(())
    }

    fn disconnect(
        &mut self,
        send: bool,
        reason: RakDisconnectReason,
        now: SystemTime,
    ) -> Result<(), RakSessionError> {
        if matches!(self.state, RakSessionState::Disconnected) {
            return Err(RakSessionError::Closed);
        }

        if send {
            let disconnect = Disconnect;

            let frame = Frame::new(RakReliability::ReliableOrdered, {
                let mut buf = Vec::with_capacity(disconnect.size_hint());
                disconnect.serialize(&mut buf)?;
                buf.into_boxed_slice()
            });

            self.send_frame(frame, RakPriority::Immediate, now)?;
        }

        self.state = RakSessionState::Disconnected;

        self.output
            .push_back(RakSessionOutput::Disconnected(self.id, reason));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::packets::ack::MAX_ACK_ENTRIES;

    #[test]
    fn a_snapshot_round_trips_through_json_and_resumes_where_it_left_off() {
        let mut session = RakSession::new(
            RakSessionId(42),
            "127.0.0.1:19132".parse().unwrap(),
            0xDEAD_BEEF,
            crate::util::constants::MAX_MTU_SIZE,
            |_| {},
        );

        let now = SystemTime::now();
        session
            .handle(RakSessionInput::Send(
                Box::from(*b"hello"),
                RakReliability::ReliableOrdered,
                RakPriority::Immediate,
                now,
            ))
            .unwrap();
        while session.poll().is_some() {}

        let before_seq = session.outbound_rel;
        assert!(
            before_seq > 0,
            "sending a reliable frame should advance outbound_rel"
        );

        let json = facet_json::to_string(&session.snapshot()).expect("snapshot must serialize");
        let mut resumed =
            RakSession::restore(facet_json::from_str(&json).expect("snapshot must deserialize"))
                .expect("a snapshot's own address must parse");

        assert_eq!(resumed.id, session.id);
        assert_eq!(resumed.addr, session.addr);
        assert_eq!(resumed.guid, session.guid);
        assert_eq!(resumed.outbound_rel, before_seq);

        resumed
            .handle(RakSessionInput::Send(
                Box::from(*b"world"),
                RakReliability::ReliableOrdered,
                RakPriority::Immediate,
                now,
            ))
            .unwrap();
        assert_eq!(resumed.outbound_rel, before_seq + 1);
    }

    /// JSON has no infinity, and an unmeasured RTT is infinite - it must not come back
    /// as zero.
    #[test]
    fn an_unmeasured_rtt_survives_a_json_round_trip() {
        let session = RakSession::new(
            RakSessionId(1),
            "127.0.0.1:19132".parse().unwrap(),
            0,
            crate::util::constants::MAX_MTU_SIZE,
            |_| {},
        );

        let json = facet_json::to_string(&session.snapshot()).unwrap();
        let resumed = RakSession::restore(facet_json::from_str(&json).unwrap()).unwrap();

        assert_eq!(
            resumed.congestion_controller.retransmission_timeout(),
            session.congestion_controller.retransmission_timeout()
        );
    }

    #[test]
    fn out_of_range_order_channel_does_not_panic() {
        let mut session = RakSession::new(
            RakSessionId(0),
            "127.0.0.1:19132".parse().unwrap(),
            0,
            crate::util::constants::MAX_MTU_SIZE,
            |_| {},
        );

        let mut frame = Frame::new(RakReliability::ReliableOrdered, Box::new([]));
        frame.order_channel = u8::MAX;

        session.handle_frame(frame, SystemTime::now()).unwrap();
    }

    #[test]
    fn max_message_len_is_the_queued_byte_budget() {
        let session = RakSession::new(
            RakSessionId(0),
            "127.0.0.1:19132".parse().unwrap(),
            0,
            crate::util::constants::MAX_MTU_SIZE,
            |_| {},
        );

        assert_eq!(
            session.max_message_len(),
            crate::util::constants::MAX_QUEUED_BYTES as usize
        );
    }

    #[test]
    fn max_message_len_is_at_least_one_unsplit_frame() {
        let session = RakSession::new(
            RakSessionId(0),
            "127.0.0.1:19132".parse().unwrap(),
            0,
            crate::util::constants::MAX_MTU_SIZE,
            |conf| conf.max_queued_bytes = 4,
        );

        assert_eq!(session.max_message_len(), session.mtu as usize);
    }

    #[test]
    fn honors_configured_ordering_channels() {
        let mut session = RakSession::new(
            RakSessionId(0),
            "127.0.0.1:19132".parse().unwrap(),
            0,
            crate::util::constants::MAX_MTU_SIZE,
            |conf| conf.ordering_channels = 4,
        );

        let mut frame = Frame::new(RakReliability::ReliableOrdered, Box::new([1]));
        frame.order_channel = 4;

        session.handle_frame(frame, SystemTime::now()).unwrap();

        assert_eq!(session.inbound_ord_idx[4], 0);
    }

    #[test]
    fn priority_routes_to_separate_queues() {
        let mut session = RakSession::new(
            RakSessionId(0),
            "127.0.0.1:19132".parse().unwrap(),
            0,
            crate::util::constants::MAX_MTU_SIZE,
            |_| {},
        );

        let now = SystemTime::now();
        session
            .send_frame(
                Frame::new(RakReliability::Unreliable, Box::new([1])),
                RakPriority::Low,
                now,
            )
            .unwrap();
        session
            .send_frame(
                Frame::new(RakReliability::Unreliable, Box::new([2])),
                RakPriority::High,
                now,
            )
            .unwrap();

        assert_eq!(session.outbound_queue[RakPriority::High as usize].len(), 1);
        assert_eq!(session.outbound_queue[RakPriority::Low as usize].len(), 1);
    }

    #[test]
    fn rejects_out_of_range_split_index() {
        let mut session = RakSession::new(
            RakSessionId(0),
            "127.0.0.1:19132".parse().unwrap(),
            0,
            crate::util::constants::MAX_MTU_SIZE,
            |_| {},
        );

        let mut frame = Frame::new(RakReliability::Reliable, Box::new([1, 2, 3]));
        frame.split_size = 2;
        frame.split_index = 5;
        frame.split_id = 1;

        session.handle_frame(frame, SystemTime::now()).unwrap();

        assert!(session.inbound_spl_queue.is_empty());
    }

    #[test]
    fn drops_split_frame_exceeding_max_queued_bytes() {
        let mut session = RakSession::new(
            RakSessionId(0),
            "127.0.0.1:19132".parse().unwrap(),
            0,
            crate::util::constants::MAX_MTU_SIZE,
            |conf| conf.max_queued_bytes = 4,
        );

        let mut frame = Frame::new(RakReliability::Reliable, vec![0u8; 8].into_boxed_slice());
        frame.split_size = 2;
        frame.split_index = 0;
        frame.split_id = 1;

        session.handle_frame(frame, SystemTime::now()).unwrap();

        assert!(session.inbound_spl_queue.is_empty());
    }

    #[test]
    fn disconnect_reason_matches_cause() {
        let mut session = RakSession::new(
            RakSessionId(0),
            "127.0.0.1:19132".parse().unwrap(),
            0,
            crate::util::constants::MAX_MTU_SIZE,
            |_| {},
        );

        session
            .handle(RakSessionInput::Disconnect(SystemTime::now()))
            .unwrap();

        let reason = session
            .output
            .iter()
            .find_map(|out| match out {
                RakSessionOutput::Disconnected(_, reason) => Some(*reason),
                _ => None,
            })
            .unwrap();

        assert_eq!(reason, RakDisconnectReason::Requested);
    }

    fn session(id: u64, port: u16) -> RakSession {
        RakSession::new(
            RakSessionId(id),
            SocketAddr::from(([127, 0, 0, 1], port)),
            id,
            crate::util::constants::MAX_MTU_SIZE,
            |_| {},
        )
    }

    fn deliver(from: &mut RakSession, to: &mut RakSession, now: SystemTime) {
        let datagrams: Vec<Box<[u8]>> = std::iter::from_fn(|| from.poll())
            .filter_map(|out| match out {
                RakSessionOutput::Datagram(buf, _) => Some(buf),
                _ => None,
            })
            .collect();
        for buf in datagrams {
            to.handle(RakSessionInput::Datagram(buf, now)).unwrap();
        }
    }

    fn packets(session: &mut RakSession) -> Vec<Box<[u8]>> {
        std::iter::from_fn(|| session.poll())
            .filter_map(|out| match out {
                RakSessionOutput::Packet(buf) => Some(buf),
                _ => None,
            })
            .collect()
    }

    fn datagram(sequence: u32, frames: Vec<Frame>) -> RakSessionInput {
        let set = FrameSet::new(sequence, frames, false, true, false);
        let mut buf = Vec::with_capacity(set.size_hint());
        set.serialize(&mut buf).unwrap();
        RakSessionInput::Datagram(buf.into_boxed_slice(), SystemTime::now())
    }

    fn unreliable(byte: u8) -> Vec<Frame> {
        vec![Frame::new(
            RakReliability::Unreliable,
            Box::new([0xFE, byte]),
        )]
    }

    #[test]
    fn datagram_gap_within_window_is_nacked() {
        let mut session = session(0, 1);

        session.handle(datagram(0, unreliable(0))).unwrap();
        session.handle(datagram(3, unreliable(3))).unwrap();

        assert_eq!(session.sequences_lost, HashSet::from([1, 2]));
        assert_eq!(session.inbound_seq, 4);
    }

    #[test]
    fn datagram_beyond_window_is_dropped() {
        let mut session = session(0, 1);

        session
            .handle(datagram(DATAGRAM_WINDOW as u32 * 50, unreliable(0)))
            .unwrap();

        assert!(
            session.sequences_lost.is_empty(),
            "a datagram far ahead must not mark {} sequences lost",
            session.sequences_lost.len()
        );
        assert_eq!(session.inbound_seq, 0);
        assert!(packets(&mut session).is_empty());
    }

    #[test]
    fn late_datagram_does_not_move_inbound_seq_backwards() {
        let mut session = session(0, 1);

        session.handle(datagram(0, unreliable(0))).unwrap();
        session.handle(datagram(5, unreliable(5))).unwrap();
        session.handle(datagram(3, unreliable(3))).unwrap();

        assert_eq!(session.inbound_seq, 6);
        assert_eq!(session.sequences_lost, HashSet::from([1, 2, 4]));
        assert_eq!(packets(&mut session).len(), 3);
    }

    #[test]
    fn lost_sequences_stay_bounded_under_repeated_gaps() {
        let mut session = session(0, 1);

        let step = DATAGRAM_WINDOW as u32 - 1;
        for i in 1..=16 {
            session.handle(datagram(i * step, unreliable(0))).unwrap();
        }

        assert!(session.sequences_lost.len() <= DATAGRAM_WINDOW);
    }

    fn ordered(order_index: u32) -> Frame {
        let mut frame = Frame::new(RakReliability::ReliableOrdered, Box::new([0xFE]));
        frame.order_index = order_index;
        frame
    }

    fn disconnect_reason(session: &RakSession) -> Option<RakDisconnectReason> {
        session.output.iter().find_map(|out| match out {
            RakSessionOutput::Disconnected(_, reason) => Some(*reason),
            _ => None,
        })
    }

    #[test]
    fn ordered_frame_within_window_is_queued() {
        let mut session = session(0, 1);

        session
            .handle_frame(ordered(ORDER_WINDOW as u32 - 1), SystemTime::now())
            .unwrap();

        assert_eq!(session.inbound_ord_queue[&0].len(), 1);
        assert_eq!(session.state, RakSessionState::Connected);
    }

    #[test]
    fn ordered_frame_beyond_window_closes_the_session() {
        let mut session = session(0, 1);

        session
            .handle_frame(ordered(ORDER_WINDOW as u32), SystemTime::now())
            .unwrap();

        assert!(
            session.inbound_ord_queue.values().all(HashMap::is_empty),
            "a frame {ORDER_WINDOW} ahead must not be buffered"
        );
        assert_eq!(session.state, RakSessionState::Disconnected);
        assert_eq!(
            disconnect_reason(&session),
            Some(RakDisconnectReason::ProtocolViolation)
        );
    }

    fn fragment(split_id: u16, split_size: u32, split_index: u32, payload: &[u8]) -> Frame {
        let mut frame = Frame::new(RakReliability::Unreliable, payload.into());
        frame.split_id = split_id;
        frame.split_size = split_size;
        frame.split_index = split_index;
        frame
    }

    fn assert_closed_for_violation(session: &RakSession) {
        assert_eq!(session.state, RakSessionState::Disconnected);
        assert_eq!(
            disconnect_reason(session),
            Some(RakDisconnectReason::ProtocolViolation)
        );
    }

    #[test]
    fn split_count_above_limit_closes_the_session() {
        let mut session = session(0, 1);

        session
            .handle_frame(
                fragment(1, MAX_SPLIT_COUNT + 1, 0, &[0xFE]),
                SystemTime::now(),
            )
            .unwrap();

        assert!(session.inbound_spl_queue.is_empty());
        assert_closed_for_violation(&session);
    }

    #[test]
    fn concurrent_splits_above_limit_close_the_session() {
        let mut session = session(0, 1);

        let now = SystemTime::now();
        for split_id in 0..=MAX_CONCURRENT_SPLITS as u16 {
            session
                .handle_frame(fragment(split_id, 2, 0, &[0xFE]), now)
                .unwrap();
        }

        assert!(session.inbound_spl_queue.len() <= MAX_CONCURRENT_SPLITS);
        assert_closed_for_violation(&session);
    }

    #[test]
    fn empty_split_fragment_closes_the_session() {
        let mut session = session(0, 1);

        session
            .handle_frame(fragment(1, 2, 0, &[]), SystemTime::now())
            .unwrap();

        assert!(session.inbound_spl_queue.is_empty());
        assert_closed_for_violation(&session);
    }

    #[test]
    fn split_size_mismatch_closes_the_session() {
        let mut session = session(0, 1);

        let now = SystemTime::now();
        session
            .handle_frame(fragment(1, 3, 0, &[0xFE]), now)
            .unwrap();
        session
            .handle_frame(fragment(1, 2, 1, &[0xFF]), now)
            .unwrap();

        assert_closed_for_violation(&session);
    }

    #[test]
    fn completed_split_is_delivered_and_releases_its_byte_budget() {
        let mut session = session(0, 1);
        session.config.max_queued_bytes = 4;

        let now = SystemTime::now();
        session
            .handle_frame(fragment(1, 2, 0, &[0xFE, 1]), now)
            .unwrap();
        session
            .handle_frame(fragment(1, 2, 1, &[2, 3]), now)
            .unwrap();
        session
            .handle_frame(fragment(2, 2, 0, &[0xFE, 4, 5, 6]), now)
            .unwrap();

        assert_eq!(packets(&mut session), vec![Box::from([0xFE, 1, 2, 3])]);
        assert_eq!(session.inbound_spl_queue[&2].len(), 1);
    }

    #[test]
    fn counters_wrap_at_24_bits_in_both_directions() {
        let near_top = crate::util::u24::MASK - 1;

        let mut sender = session(1, 1);
        sender.outbound_seq = near_top;
        sender.outbound_rel = near_top;
        sender.outbound_ord_idx[0] = near_top;

        let mut receiver = session(2, 2);
        receiver.inbound_seq = near_top;
        receiver.inbound_ord_idx[0] = near_top;

        let now = SystemTime::now();
        for i in 0..4u8 {
            sender
                .handle(RakSessionInput::Send(
                    Box::new([0xFE, i]),
                    RakReliability::ReliableOrdered,
                    RakPriority::Immediate,
                    now,
                ))
                .unwrap();
            deliver(&mut sender, &mut receiver, now);
        }

        let received = packets(&mut receiver);
        let expected: Vec<Box<[u8]>> = (0..4u8).map(|i| Box::from([0xFE, i])).collect();
        assert_eq!(
            received, expected,
            "every packet across the wrap must arrive in order"
        );
        assert_eq!(sender.outbound_seq, 2);
        assert_eq!(sender.outbound_rel, 2);
        assert_eq!(sender.outbound_ord_idx[0], 2);
        assert_eq!(receiver.inbound_ord_idx[0], 2);
    }

    fn outbound_acks(session: &mut RakSession) -> Vec<Box<[u8]>> {
        std::iter::from_fn(|| session.poll())
            .filter_map(|out| match out {
                RakSessionOutput::Datagram(buf, _) if buf[0] & (flags::ACK | flags::NACK) != 0 => {
                    Some(buf)
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn outbound_acks_fit_the_mtu() {
        let mut session = session(0, 1);

        let received: Vec<u32> = (0..DATAGRAM_WINDOW as u32).map(|i| i * 2).collect();
        for &sequence in &received {
            session.handle(datagram(sequence, unreliable(0))).unwrap();
        }
        session.tick(SystemTime::now()).unwrap();

        let mut acked = Vec::new();
        let mut nacked = Vec::new();
        for buf in outbound_acks(&mut session) {
            assert!(
                buf.len() <= session.mtu as usize,
                "an ACK of {} bytes exceeds the {} byte MTU",
                buf.len(),
                session.mtu
            );
            let ack = Ack::deserialize(&mut buf.as_ref()).unwrap();
            match ack.is_nack {
                true => nacked.extend(ack.sequences),
                false => acked.extend(ack.sequences),
            }
        }
        acked.sort_unstable();
        nacked.sort_unstable();

        assert_eq!(acked, received);
        assert_eq!(nacked.len(), DATAGRAM_WINDOW - 1);
    }

    #[test]
    fn outbound_acks_respect_the_entry_cap() {
        let mut session = session(0, 1);

        let received = MAX_ACK_ENTRIES as u32 * 2 + 1;
        for sequence in 0..received {
            session.handle(datagram(sequence, unreliable(0))).unwrap();
        }
        session.tick(SystemTime::now()).unwrap();

        let mut acked = Vec::new();
        for buf in outbound_acks(&mut session) {
            let ack = Ack::deserialize(&mut buf.as_ref());
            assert!(
                ack.is_ok(),
                "every outbound ACK must decode under the entry cap, got {ack:?}"
            );
            acked.extend(ack.unwrap().sequences);
        }
        acked.sort_unstable();

        assert_eq!(acked, (0..received).collect::<Vec<_>>());
    }

    fn ordered_payload(order_index: u32, payload: &[u8]) -> Frame {
        let mut frame = Frame::new(RakReliability::ReliableOrdered, payload.into());
        frame.order_index = order_index;
        frame.reliable_index = order_index;
        frame
    }

    #[test]
    fn ordered_frames_beyond_max_queued_bytes_close_the_session() {
        let mut session = session(0, 1);
        session.config.max_queued_bytes = 4;

        session
            .handle_frame(ordered_payload(1, &[0xFE, 1, 2, 3, 4]), SystemTime::now())
            .unwrap();

        assert!(session.inbound_ord_queue.values().all(HashMap::is_empty));
        assert_closed_for_violation(&session);
    }

    #[test]
    fn ordered_queue_shares_the_byte_budget_with_split_reassembly() {
        let mut session = session(0, 1);
        session.config.max_queued_bytes = 4;

        let now = SystemTime::now();
        session
            .handle_frame(fragment(1, 2, 0, &[0xFE, 1, 2]), now)
            .unwrap();
        session
            .handle_frame(ordered_payload(1, &[0xFE, 1]), now)
            .unwrap();

        assert_closed_for_violation(&session);
    }

    #[test]
    fn delivered_ordered_frames_release_their_byte_budget() {
        let mut session = session(0, 1);
        session.config.max_queued_bytes = 4;

        let now = SystemTime::now();
        session
            .handle_frame(ordered_payload(1, &[0xFE, 1, 2]), now)
            .unwrap();
        session
            .handle_frame(ordered_payload(0, &[0xFE]), now)
            .unwrap();
        session
            .handle_frame(ordered_payload(3, &[0xFE, 3, 4]), now)
            .unwrap();

        assert_eq!(session.state, RakSessionState::Connected);
        assert_eq!(packets(&mut session).len(), 2);
        assert_eq!(session.inbound_ord_queue[&0].len(), 1);
    }

    fn datagram_at(sequence: u32, frames: Vec<Frame>, now: SystemTime) -> RakSessionInput {
        let RakSessionInput::Datagram(buf, _) = datagram(sequence, frames) else {
            unreachable!()
        };
        RakSessionInput::Datagram(buf, now)
    }

    #[test]
    fn partial_split_without_a_fragment_for_the_session_timeout_is_evicted() {
        let mut session = session(0, 1);
        let start = SystemTime::now();

        session
            .handle(datagram_at(0, vec![fragment(1, 2, 0, &[0xFE, 1])], start))
            .unwrap();
        session
            .handle(datagram_at(1, unreliable(0), start + SESSION_TIMEOUT / 2))
            .unwrap();
        session
            .handle(RakSessionInput::Update(
                start + SESSION_TIMEOUT + Duration::from_millis(1),
            ))
            .unwrap();

        assert_eq!(session.state, RakSessionState::Connected);
        assert!(
            session.inbound_spl_queue.is_empty(),
            "a split idle for the session timeout must be evicted"
        );
        assert_eq!(session.inbound_spl_bytes, 0);
    }

    #[test]
    fn partial_split_receiving_fragments_is_kept() {
        let mut session = session(0, 1);
        let start = SystemTime::now();

        session
            .handle(datagram_at(0, vec![fragment(1, 3, 0, &[0xFE])], start))
            .unwrap();
        session
            .handle(datagram_at(
                1,
                vec![fragment(1, 3, 1, &[1])],
                start + SESSION_TIMEOUT / 2,
            ))
            .unwrap();
        session
            .handle(RakSessionInput::Update(
                start + SESSION_TIMEOUT + Duration::from_millis(1),
            ))
            .unwrap();

        assert_eq!(session.inbound_spl_queue[&1].len(), 2);
        assert_eq!(session.inbound_spl_bytes, 2);
    }

    #[test]
    fn large_sends_split_into_datagrams_within_the_mtu() {
        let reliabilities = [
            RakReliability::Unreliable,
            RakReliability::UnreliableSequenced,
            RakReliability::Reliable,
            RakReliability::ReliableOrdered,
            RakReliability::ReliableSequenced,
            RakReliability::UnreliableWithAckReceipt,
            RakReliability::ReliableWithAckReceipt,
            RakReliability::ReliableOrderedWithAckReceipt,
        ];
        let now = SystemTime::now();

        for mtu in crate::util::constants::MTU_SIZES {
            for reliability in reliabilities {
                let mut session = RakSession::new(
                    RakSessionId(0),
                    "[::1]:19132".parse().unwrap(),
                    0,
                    mtu,
                    |_| {},
                );
                for priority in [RakPriority::Immediate, RakPriority::Normal] {
                    session
                        .handle(RakSessionInput::Send(
                            vec![0xFE; 64 * 1024].into_boxed_slice(),
                            reliability,
                            priority,
                            now,
                        ))
                        .unwrap();
                }
                session.tick(now).unwrap();

                let max = session.mtu as usize;
                for out in std::iter::from_fn(|| session.poll()) {
                    if let RakSessionOutput::Datagram(buf, _) = out {
                        assert!(
                            buf.len() <= max,
                            "{reliability:?} at mtu {mtu} sent {} bytes",
                            buf.len()
                        );
                    }
                }
            }
        }
    }
}

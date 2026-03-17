use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};

use bytes::Bytes;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

use crate::concurrency::FastMutex;
use crate::server::{PeerDisconnectReason, PeerId, SendOptions};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Stable identifier for a [`Connection`].
pub struct ConnectionId(u64);

impl ConnectionId {
    /// Creates an id from raw `u64`.
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// Returns raw id value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl From<PeerId> for ConnectionId {
    fn from(value: PeerId) -> Self {
        Self::from_u64(value.as_u64())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Immutable connection identity snapshot.
pub struct ConnectionMetadata {
    id: ConnectionId,
    remote_addr: SocketAddr,
}

impl ConnectionMetadata {
    /// Returns connection id.
    pub const fn id(self) -> ConnectionId {
        self.id
    }

    /// Returns remote peer socket address.
    pub const fn remote_addr(self) -> SocketAddr {
        self.remote_addr
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Remote-side reason mapped from RakNet disconnect semantics.
pub enum RemoteDisconnectReason {
    Requested,
    RemoteDisconnectionNotification { reason_code: Option<u8> },
    RemoteDetectLostConnection,
    WorkerStopped { shard_id: usize },
}

impl From<PeerDisconnectReason> for RemoteDisconnectReason {
    fn from(value: PeerDisconnectReason) -> Self {
        match value {
            PeerDisconnectReason::Requested => Self::Requested,
            PeerDisconnectReason::RemoteDisconnectionNotification { reason_code } => {
                Self::RemoteDisconnectionNotification { reason_code }
            }
            PeerDisconnectReason::RemoteDetectLostConnection => Self::RemoteDetectLostConnection,
            PeerDisconnectReason::WorkerStopped { shard_id } => Self::WorkerStopped { shard_id },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Local close reason recorded by [`Connection`].
pub enum ConnectionCloseReason {
    RequestedByLocal,
    PeerDisconnected(RemoteDisconnectReason),
    ListenerStopped,
    InboundBackpressure,
    TransportError(String),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
/// Receive-side errors from [`Connection::recv`] / [`Connection::recv_bytes`].
pub enum RecvError {
    #[error("connection closed: {reason:?}")]
    ConnectionClosed { reason: ConnectionCloseReason },
    #[error("decode error: {message}")]
    DecodeError { message: String },
    #[error("connection receive channel closed")]
    ChannelClosed,
}

pub mod queue {
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    /// Errors produced by connection send queue operations.
    pub enum SendQueueError {
        #[error("connection command channel closed")]
        CommandChannelClosed,
        #[error("connection command response dropped")]
        ResponseDropped,
        #[error("transport send failed: {message}")]
        Transport { message: String },
    }
}

#[derive(Debug)]
pub(crate) enum ConnectionInbound {
    Packet(Bytes),
    DecodeError(String),
    Closed(ConnectionCloseReason),
}

#[derive(Debug)]
pub(crate) enum ConnectionCommand {
    Send {
        peer_id: PeerId,
        payload: Bytes,
        options: SendOptions,
        response: oneshot::Sender<io::Result<()>>,
    },
    Disconnect {
        peer_id: PeerId,
        response: oneshot::Sender<io::Result<()>>,
    },
    DisconnectNoWait {
        peer_id: PeerId,
    },
    Shutdown {
        response: oneshot::Sender<io::Result<()>>,
    },
}

#[derive(Debug)]
pub(crate) struct ConnectionSharedState {
    closed: AtomicBool,
    close_reason: FastMutex<Option<ConnectionCloseReason>>,
}

impl ConnectionSharedState {
    pub(crate) fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            close_reason: FastMutex::new(None),
        }
    }

    pub(crate) fn mark_closed(&self, reason: ConnectionCloseReason) {
        self.closed.store(true, Ordering::Release);
        *self.close_reason.lock() = Some(reason);
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub(crate) fn close_reason(&self) -> Option<ConnectionCloseReason> {
        self.close_reason.lock().clone()
    }
}

type BoxSendFuture = Pin<Box<dyn Future<Output = Result<(), queue::SendQueueError>> + Send>>;
type BoxIoFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

struct PendingWrite {
    len: usize,
    fut: BoxSendFuture,
}

fn is_eof_close_reason(reason: &ConnectionCloseReason) -> bool {
    matches!(
        reason,
        ConnectionCloseReason::RequestedByLocal
            | ConnectionCloseReason::PeerDisconnected(_)
            | ConnectionCloseReason::ListenerStopped
    )
}

fn close_reason_to_io_error(reason: ConnectionCloseReason) -> io::Error {
    if is_eof_close_reason(&reason) {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("connection closed: {reason:?}"),
        )
    } else {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!("connection closed: {reason:?}"),
        )
    }
}

fn send_queue_error_to_io_error(error: queue::SendQueueError) -> io::Error {
    match error {
        queue::SendQueueError::CommandChannelClosed => io::Error::new(
            io::ErrorKind::BrokenPipe,
            "connection command channel closed",
        ),
        queue::SendQueueError::ResponseDropped => io::Error::new(
            io::ErrorKind::BrokenPipe,
            "connection command response dropped",
        ),
        queue::SendQueueError::Transport { message } => {
            io::Error::new(io::ErrorKind::BrokenPipe, message)
        }
    }
}

fn send_command_future(
    shared: Arc<ConnectionSharedState>,
    command_tx: mpsc::Sender<ConnectionCommand>,
    peer_id: PeerId,
    payload: Bytes,
    options: SendOptions,
) -> BoxSendFuture {
    Box::pin(async move {
        if shared.is_closed() {
            return Err(queue::SendQueueError::Transport {
                message: "connection already closed".to_string(),
            });
        }

        let (response_tx, response_rx) = oneshot::channel();
        command_tx
            .send(ConnectionCommand::Send {
                peer_id,
                payload,
                options,
                response: response_tx,
            })
            .await
            .map_err(|_| queue::SendQueueError::CommandChannelClosed)?;

        match response_rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(queue::SendQueueError::Transport {
                message: err.to_string(),
            }),
            Err(_) => Err(queue::SendQueueError::ResponseDropped),
        }
    })
}

fn disconnect_command_future(
    shared: Arc<ConnectionSharedState>,
    command_tx: mpsc::Sender<ConnectionCommand>,
    peer_id: PeerId,
) -> BoxIoFuture {
    Box::pin(async move {
        if shared.is_closed() {
            return Ok(());
        }

        let (response_tx, response_rx) = oneshot::channel();
        command_tx
            .send(ConnectionCommand::Disconnect {
                peer_id,
                response: response_tx,
            })
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "connection command channel closed",
                )
            })?;

        match response_rx.await {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connection command response dropped",
            )),
        }
    })
}

fn fill_read_buf_from_payload(read_buf: &mut ReadBuf<'_>, payload: &mut Bytes) {
    let copy_len = payload.len().min(read_buf.remaining());
    if copy_len == 0 {
        return;
    }

    let copied = payload.split_to(copy_len);
    read_buf.put_slice(&copied);
}

pub struct Connection {
    remote_addr: SocketAddr,
    id: ConnectionId,
    peer_id: PeerId,
    command_tx: mpsc::Sender<ConnectionCommand>,
    inbound_rx: mpsc::Receiver<ConnectionInbound>,
    shared: Arc<ConnectionSharedState>,
}

impl Connection {
    pub(crate) fn new(
        peer_id: PeerId,
        address: SocketAddr,
        command_tx: mpsc::Sender<ConnectionCommand>,
        inbound_rx: mpsc::Receiver<ConnectionInbound>,
        shared: Arc<ConnectionSharedState>,
    ) -> Self {
        Self {
            remote_addr: address,
            id: ConnectionId::from(peer_id),
            peer_id,
            command_tx,
            inbound_rx,
            shared,
        }
    }

    /// Returns connection id.
    pub fn id(&self) -> ConnectionId {
        self.id
    }

    /// Returns remote peer address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Returns immutable metadata snapshot.
    pub fn metadata(&self) -> ConnectionMetadata {
        ConnectionMetadata {
            id: self.id,
            remote_addr: self.remote_addr,
        }
    }

    pub(crate) fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns close reason if connection is closed.
    pub fn close_reason(&self) -> Option<ConnectionCloseReason> {
        self.shared.close_reason()
    }

    pub(crate) async fn send_with_options(
        &self,
        payload: impl Into<Bytes>,
        options: SendOptions,
    ) -> Result<(), queue::SendQueueError> {
        send_command_future(
            self.shared.clone(),
            self.command_tx.clone(),
            self.peer_id,
            payload.into(),
            options,
        )
        .await
    }

    /// Sends bytes using default send options.
    pub async fn send_bytes(&self, payload: impl Into<Bytes>) -> Result<(), queue::SendQueueError> {
        self.send_with_options(payload, SendOptions::default())
            .await
    }

    /// Sends borrowed bytes, copying into an owned payload buffer.
    pub async fn send(&self, payload: impl AsRef<[u8]>) -> Result<(), queue::SendQueueError> {
        self.send_bytes(Bytes::copy_from_slice(payload.as_ref()))
            .await
    }

    /// Compatibility helper matching stream-like send signatures.
    pub async fn send_compat(
        &self,
        stream: &[u8],
        _immediate: bool,
    ) -> Result<(), queue::SendQueueError> {
        self.send(stream).await
    }

    /// Receives next payload as zero-copy [`Bytes`].
    pub async fn recv_bytes(&mut self) -> Result<Bytes, RecvError> {
        match self.inbound_rx.recv().await {
            Some(ConnectionInbound::Packet(payload)) => Ok(payload),
            Some(ConnectionInbound::DecodeError(message)) => {
                Err(RecvError::DecodeError { message })
            }
            Some(ConnectionInbound::Closed(reason)) => {
                self.shared.mark_closed(reason.clone());
                Err(RecvError::ConnectionClosed { reason })
            }
            None => {
                if let Some(reason) = self.shared.close_reason() {
                    Err(RecvError::ConnectionClosed { reason })
                } else {
                    self.shared
                        .mark_closed(ConnectionCloseReason::ListenerStopped);
                    Err(RecvError::ChannelClosed)
                }
            }
        }
    }

    /// Receives next payload as owned `Vec<u8>`.
    pub async fn recv(&mut self) -> Result<Vec<u8>, RecvError> {
        self.recv_bytes().await.map(|payload| payload.to_vec())
    }

    /// Gracefully closes this connection.
    pub async fn close(&self) {
        if self.shared.is_closed() {
            return;
        }

        let (response_tx, response_rx) = oneshot::channel();
        if self
            .command_tx
            .send(ConnectionCommand::Disconnect {
                peer_id: self.peer_id,
                response: response_tx,
            })
            .await
            .is_err()
        {
            self.shared
                .mark_closed(ConnectionCloseReason::ListenerStopped);
            return;
        }

        if response_rx.await.is_ok() {
            self.shared
                .mark_closed(ConnectionCloseReason::RequestedByLocal);
        }
    }

    /// Returns whether connection is currently closed.
    pub async fn is_closed(&self) -> bool {
        self.shared.is_closed()
    }

    /// Converts into Tokio AsyncRead/AsyncWrite adapter.
    pub fn into_io(self) -> ConnectionIo {
        ConnectionIo::new(self)
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if self.shared.is_closed() {
            return;
        }

        let _ = self
            .command_tx
            .try_send(ConnectionCommand::DisconnectNoWait {
                peer_id: self.peer_id,
            });
    }
}

/// Tokio AsyncRead/AsyncWrite adapter over [`Connection`].
pub struct ConnectionIo {
    connection: Connection,
    read_remainder: Option<Bytes>,
    write_in_flight: Option<PendingWrite>,
    shutdown_in_flight: Option<BoxIoFuture>,
}

impl ConnectionIo {
    fn new(connection: Connection) -> Self {
        Self {
            connection,
            read_remainder: None,
            write_in_flight: None,
            shutdown_in_flight: None,
        }
    }

    /// Returns immutable underlying connection reference.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Returns mutable underlying connection reference.
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }

    /// Returns underlying connection and consumes adapter.
    pub fn into_inner(self) -> Connection {
        self.connection
    }

    fn poll_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<usize>>> {
        let Some(mut state) = self.write_in_flight.take() else {
            return Poll::Ready(Ok(None));
        };

        match state.fut.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(Some(state.len))),
            Poll::Ready(Err(error)) => Poll::Ready(Err(send_queue_error_to_io_error(error))),
            Poll::Pending => {
                self.write_in_flight = Some(state);
                Poll::Pending
            }
        }
    }
}

impl AsyncRead for ConnectionIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        read_buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if read_buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        if let Some(mut remainder) = self.read_remainder.take() {
            fill_read_buf_from_payload(read_buf, &mut remainder);
            if !remainder.is_empty() {
                self.read_remainder = Some(remainder);
            }
            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut self.connection.inbound_rx).poll_recv(cx) {
            Poll::Ready(Some(ConnectionInbound::Packet(mut payload))) => {
                fill_read_buf_from_payload(read_buf, &mut payload);
                if !payload.is_empty() {
                    self.read_remainder = Some(payload);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(ConnectionInbound::DecodeError(message))) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, message)))
            }
            Poll::Ready(Some(ConnectionInbound::Closed(reason))) => {
                self.connection.shared.mark_closed(reason.clone());
                if is_eof_close_reason(&reason) {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Ready(Err(close_reason_to_io_error(reason)))
                }
            }
            Poll::Ready(None) => {
                if let Some(reason) = self.connection.shared.close_reason() {
                    if is_eof_close_reason(&reason) {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Ready(Err(close_reason_to_io_error(reason)))
                    }
                } else {
                    self.connection
                        .shared
                        .mark_closed(ConnectionCloseReason::ListenerStopped);
                    Poll::Ready(Ok(()))
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for ConnectionIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shutdown_in_flight.is_some() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connection shutdown already in progress",
            )));
        }

        match self.as_mut().get_mut().poll_pending_write(cx) {
            Poll::Ready(Ok(Some(written))) => return Poll::Ready(Ok(written)),
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(None)) => {}
            Poll::Pending => return Poll::Pending,
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if self.connection.shared.is_closed() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connection already closed",
            )));
        }

        let payload = Bytes::copy_from_slice(buf);
        self.write_in_flight = Some(PendingWrite {
            len: buf.len(),
            fut: send_command_future(
                self.connection.shared.clone(),
                self.connection.command_tx.clone(),
                self.connection.peer_id,
                payload,
                SendOptions::default(),
            ),
        });

        match self.as_mut().get_mut().poll_pending_write(cx) {
            Poll::Ready(Ok(Some(written))) => Poll::Ready(Ok(written)),
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(0)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut().poll_pending_write(cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }

        if self.connection.shared.is_closed() {
            return Poll::Ready(Ok(()));
        }

        if self.shutdown_in_flight.is_none() {
            self.shutdown_in_flight = Some(disconnect_command_future(
                self.connection.shared.clone(),
                self.connection.command_tx.clone(),
                self.connection.peer_id,
            ));
        }

        let Some(mut shutdown_future) = self.shutdown_in_flight.take() else {
            return Poll::Ready(Ok(()));
        };

        match shutdown_future.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                self.connection
                    .shared
                    .mark_closed(ConnectionCloseReason::RequestedByLocal);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => {
                self.shutdown_in_flight = Some(shutdown_future);
                Poll::Pending
            }
        }
    }
}

macro_rules! declare_modules {
    (
        pub: [ $( $pub_mod:ident ),* $(,)? ],
        private: [ $( $priv_mod:ident ),* $(,)? ]
    ) => {
        $( pub mod $pub_mod; )*
        $( mod $priv_mod; )*
    };
}

macro_rules! reexport {
    (
        $(
            $module:ident => { $($item:ident),* $(,)? }
        ),* $(,)?
    ) => {
        $(
            pub use $module::{ $($item),* };
        )*
    };
}

macro_rules! low_level_namespace {
    (
        protocol => { $($p:item)* },
        session  => { $($s:item)* },
        transport => { $($t:item)* }
    ) => {
        pub mod low_level {
            pub mod protocol {
                $($p)*
            }
            pub mod session {
                $($s)*
            }
            pub mod transport {
                $($t)*
            }
        }
    };
}

macro_rules! reexport_low_level {
    () => {
        pub use low_level::protocol::{ ConnectedControlPacket, Reliability, Sequence24 };
        pub use low_level::session::RakPriority;
        pub use low_level::transport::{
            EventOverflowPolicy, ShardedRuntimeConfig, TransportConfig, TransportMetricsSnapshot,
        };
    };
}

declare_modules! {
    pub: [client, connection, error, event, listener, protocol, proxy, server, telemetry],
    private: [concurrency, session, transport]
}

reexport! {
    connection => {
        Connection, ConnectionCloseReason, ConnectionId, ConnectionIo,
        ConnectionMetadata, RecvError
    },
    error => { ConfigValidationError, DecodeError, EncodeError },
    listener => { Incoming, Listener, ListenerMetadata }
}

low_level_namespace! {
    protocol => {
        pub use crate::protocol::{
            AckNackPayload, ConnectedControlPacket, Datagram, DatagramHeader, DatagramPayload,
            Frame, FrameHeader, RaknetCodec, Reliability, Sequence24, SequenceRange, SplitInfo,
            ack, codec, connected, constants, datagram, frame, frame_header, primitives,
            reliability, sequence24,
        };
    },

    session => {
        pub use crate::session::tunables;
        pub use crate::session::{
            QueuePayloadResult, RakPriority, ReceiptProgress, Session,
            SessionMetricsSnapshot, SessionState, TrackedDatagram,
        };
    },

    transport => {
        pub use crate::transport::{
            ConnectedFrameDelivery, EventOverflowPolicy, HandshakeHeuristicsConfig,
            IdentityProxyRouter, InboundProxyRoute, OutboundProxyRoute, ProxyRouter,
            QueueDispatchResult, RemoteDisconnectReason, SessionTunables,
            ShardedRuntimeCommand, ShardedRuntimeConfig, ShardedRuntimeEvent,
            ShardedRuntimeHandle, ShardedSendPayload, TransportConfig, TransportEvent,
            TransportMetricsSnapshot, TransportRateLimitConfig, TransportServer,
        };
    }
}

reexport_low_level!();
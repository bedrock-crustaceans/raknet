macro_rules! expose {
    (
        // internal modules
        mods: [
            $(
                $module:ident $(=> { $($item:ident),* $(,)? })?
            ),* $(,)?
        ],

        // external re-exports
        externals: [
            $(
                $path:path => { $($ext_item:ident),* $(,)? }
            ),* $(,)?
        ]
    ) => {
        $(
            mod $module;
            $(
                pub use $module::{ $($item),* };
            )?
        )*

        $(
            pub use $path::{ $($ext_item),* };
        )*
    };
}

expose! {
    mods: [
        config => { HandshakeHeuristicsConfig, TransportConfig },
        proxy => { IdentityProxyRouter, InboundProxyRoute, OutboundProxyRoute, ProxyRouter },
        rate_limiter,
        runtime => {
            EventOverflowPolicy,
            ShardedRuntimeCommand,
            ShardedRuntimeConfig,
            ShardedRuntimeEvent,
            ShardedRuntimeHandle,
            ShardedSendPayload,
            spawn_sharded_runtime
        },
        server => {
            ConnectedFrameDelivery,
            QueueDispatchResult,
            RemoteDisconnectReason,
            TransportEvent,
            TransportMetricsSnapshot,
            TransportRateLimitConfig,
            TransportServer
        },
        session_pipeline
    ],

    externals: [
        crate::session::tunables => { SessionTunables }
    ]
}
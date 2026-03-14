use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundProxyRoute {
    Local { session_addr: SocketAddr },
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundProxyRoute {
    Send { target_addr: SocketAddr },
    Drop,
}

pub trait ProxyRouter: Send + Sync + 'static {
    fn route_inbound(
        &self,
        observed_src: SocketAddr,
        _local_addr: SocketAddr,
    ) -> InboundProxyRoute {
        InboundProxyRoute::Local {
            session_addr: observed_src,
        }
    }

    fn route_outbound(
        &self,
        session_addr: SocketAddr,
        _local_addr: SocketAddr,
    ) -> OutboundProxyRoute {
        OutboundProxyRoute::Send {
            target_addr: session_addr,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct IdentityProxyRouter;

impl ProxyRouter for IdentityProxyRouter {}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{IdentityProxyRouter, InboundProxyRoute, OutboundProxyRoute, ProxyRouter};

    struct CustomProxyRouter {
        inbound: InboundProxyRoute,
        outbound: OutboundProxyRoute,
    }

    impl ProxyRouter for CustomProxyRouter {
        fn route_inbound(
            &self,
            _observed_src: SocketAddr,
            _local_addr: SocketAddr,
        ) -> InboundProxyRoute {
            self.inbound
        }

        fn route_outbound(
            &self,
            _session_addr: SocketAddr,
            _local_addr: SocketAddr,
        ) -> OutboundProxyRoute {
            self.outbound
        }
    }

    struct DefaultTraitRouter;

    impl ProxyRouter for DefaultTraitRouter {}

    #[test]
    fn identity_router_keeps_addresses_unchanged() {
        let router = IdentityProxyRouter;
        let src = "127.0.0.1:19132"
            .parse::<SocketAddr>()
            .expect("valid socket addr");
        let local = "0.0.0.0:19132"
            .parse::<SocketAddr>()
            .expect("valid socket addr");

        assert_eq!(
            router.route_inbound(src, local),
            InboundProxyRoute::Local { session_addr: src }
        );
        assert_eq!(
            router.route_outbound(src, local),
            OutboundProxyRoute::Send { target_addr: src }
        );
    }

    #[test]
    fn custom_router_can_reroute_inbound_and_drop_outbound() {
        let rerouted = "10.0.0.9:20000"
            .parse::<SocketAddr>()
            .expect("valid socket addr");
        let router = CustomProxyRouter {
            inbound: InboundProxyRoute::Local {
                session_addr: rerouted,
            },
            outbound: OutboundProxyRoute::Drop,
        };
        let src = "127.0.0.1:19132"
            .parse::<SocketAddr>()
            .expect("valid socket addr");
        let local = "0.0.0.0:19132"
            .parse::<SocketAddr>()
            .expect("valid socket addr");

        assert_eq!(
            router.route_inbound(src, local),
            InboundProxyRoute::Local {
                session_addr: rerouted
            }
        );
        assert_eq!(router.route_outbound(src, local), OutboundProxyRoute::Drop);
    }

    #[test]
    fn trait_default_methods_behave_like_identity_router() {
        let router = DefaultTraitRouter;
        let src = "192.168.1.50:19132"
            .parse::<SocketAddr>()
            .expect("valid socket addr");
        let local = "0.0.0.0:19132"
            .parse::<SocketAddr>()
            .expect("valid socket addr");

        assert_eq!(
            router.route_inbound(src, local),
            InboundProxyRoute::Local { session_addr: src }
        );
        assert_eq!(
            router.route_outbound(src, local),
            OutboundProxyRoute::Send { target_addr: src }
        );
    }
}

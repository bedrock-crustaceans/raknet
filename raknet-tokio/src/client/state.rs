use crate::client::msg::RakClientMsg;
use raknet::prelude::RakClientConfig;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinHandle;

pub enum RakClientState {
    Initialized {
        config: RakClientConfig,
    },
    Running {
        handle: JoinHandle<()>,
        msg_tx: UnboundedSender<RakClientMsg>,
    },
    Shutdown,
}

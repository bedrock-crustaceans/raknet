#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Offline,
    Req1Recv,
    Reply1Sent,
    Req2Recv,
    Reply2Sent,
    ConnReqRecv,
    ConnReqAcceptedSent,
    NewIncomingRecv,
    Connected,
    Closing,
    Closed,
}

impl SessionState {
    pub fn can_transition_to(self, next: SessionState) -> bool {
        use SessionState as S;

        if self == next {
            return true;
        }

        matches!(
            (self, next),
            (S::Offline, S::Req1Recv)
                | (S::Req1Recv, S::Reply1Sent)
                | (S::Reply1Sent, S::Req2Recv)
                | (S::Req2Recv, S::Reply2Sent)
                | (S::Reply2Sent, S::ConnReqRecv)
                | (S::ConnReqRecv, S::ConnReqAcceptedSent)
                | (S::ConnReqAcceptedSent, S::NewIncomingRecv)
                | (S::NewIncomingRecv, S::Connected)
                | (S::Connected, S::Closing)
                | (S::Closing, S::Closed)
        )
    }
}

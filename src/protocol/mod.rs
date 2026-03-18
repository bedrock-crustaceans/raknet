macro_rules! expose_modules {
    (
        $(
            $module:ident => { $($item:ident),* }
        ),* $(,)?
    ) => {
        $(
            pub mod $module;
            pub use $module::{ $($item),* };
        )*
    };
}

expose_modules! {
    ack => { AckNackPayload, SequenceRange },
    codec => { RaknetCodec },
    connected => { ConnectedControlPacket },
    datagram => { Datagram, DatagramHeader, DatagramPayload },
    frame => { Frame, SplitInfo },
    frame_header => { FrameHeader },
    reliability => { Reliability },
    sequence24 => { Sequence24 }
}

pub mod constants;
pub mod packet;
pub mod primitives;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default, PartialEq, Eq, Debug, Clone, Copy)]
pub struct OutboundStats {
    pub bytes_sent: u64,
    pub packets_sent: u64,
}
#[derive(Default, PartialEq, Eq, Debug, Clone, Copy)]
pub struct InboundStats {
    pub bytes_received: u64,
    pub packets_received: u64,
}

//potentially there could be mismatch between packets sent and bytes sent,
//because it possible that bytes_sent field is updated and packets_sent is not
//Atomic operations are separated. But it is not big deal we just want statistics, not super precise value
#[derive(Default)]
pub struct OutboundStatsAtomic {
    pub bytes_sent: AtomicU64,
    pub packets_sent: AtomicU64,
}
impl OutboundStatsAtomic {
    pub fn to_outbound_stats(&self) -> OutboundStats {
        OutboundStats {
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
        }
    }
}

#[derive(Default)]
pub struct InboundStatsAtomic {
    pub bytes_received: AtomicU64,
    pub packets_received: AtomicU64,
}

impl InboundStatsAtomic {
    pub fn to_inbound_stats(&self) -> InboundStats {
        InboundStats {
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
        }
    }
}

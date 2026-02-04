//
// /usr/include/linux/if_link.h
//

///
/// struct rtnl_link_stats - The main device statistics structure.
///
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(C)]
pub struct RtnlLinkStats {
    pub rx_packets: u32,
    pub tx_packets: u32,
    pub rx_bytes: u32,
    pub tx_bytes: u32,
    pub rx_errors: u32,
    pub tx_errors: u32,
    pub rx_dropped: u32,
    pub tx_dropped: u32,
    pub multicast: u32,
    pub collisions: u32,
    pub rx_length_errors: u32,
    pub rx_over_errors: u32,
    pub rx_crc_errors: u32,
    pub rx_frame_errors: u32,
    pub rx_fifo_errors: u32,
    pub rx_missed_errors: u32,
    pub tx_aborted_errors: u32,
    pub tx_carrier_errors: u32,
    pub tx_fifo_errors: u32,
    pub tx_heartbeat_errors: u32,
    pub tx_window_errors: u32,
    pub rx_compressed: u32,
    pub tx_compressed: u32,
    pub rx_no_handler: u32,
}

///
/// struct rtnl_link_stats64 - The main device statistics structure.
///
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(C)]
pub struct RtnlLinkStats64 {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub multicast: u64,
    pub collisions: u64,
    pub rx_length_errors: u64,
    pub rx_over_errors: u64,
    pub rx_crc_errors: u64,
    pub rx_frame_errors: u64,
    pub rx_fifo_errors: u64,
    pub rx_missed_errors: u64,
    pub tx_aborted_errors: u64,
    pub tx_carrier_errors: u64,
    pub tx_fifo_errors: u64,
    pub tx_heartbeat_errors: u64,
    pub tx_window_errors: u64,
    pub rx_compressed: u64,
    pub tx_compressed: u64,
    pub rx_no_handler: u64,
}

impl From<RtnlLinkStats> for RtnlLinkStats64 {
    fn from(value: RtnlLinkStats) -> Self {
        Self {
            rx_packets: value.rx_packets.into(),
            tx_packets: value.tx_packets.into(),
            rx_bytes: value.rx_bytes.into(),
            tx_bytes: value.tx_bytes.into(),
            rx_errors: value.rx_errors.into(),
            tx_errors: value.tx_errors.into(),
            rx_dropped: value.rx_dropped.into(),
            tx_dropped: value.tx_dropped.into(),
            multicast: value.multicast.into(),
            collisions: value.collisions.into(),
            rx_length_errors: value.rx_length_errors.into(),
            rx_over_errors: value.rx_over_errors.into(),
            rx_crc_errors: value.rx_crc_errors.into(),
            rx_frame_errors: value.rx_frame_errors.into(),
            rx_fifo_errors: value.rx_fifo_errors.into(),
            rx_missed_errors: value.rx_missed_errors.into(),
            tx_aborted_errors: value.tx_aborted_errors.into(),
            tx_carrier_errors: value.tx_carrier_errors.into(),
            tx_fifo_errors: value.tx_fifo_errors.into(),
            tx_heartbeat_errors: value.tx_heartbeat_errors.into(),
            tx_window_errors: value.tx_window_errors.into(),
            rx_compressed: value.rx_compressed.into(),
            tx_compressed: value.tx_compressed.into(),
            rx_no_handler: value.rx_no_handler.into(),
        }
    }
}

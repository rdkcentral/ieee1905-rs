use crate::next_task_id;
use indexmap::map::Entry;
use indexmap::IndexMap;
use pnet::datalink::MacAddr;
use pnet::packet::ethernet::{EtherType, EthernetPacket};
use pnet::packet::Packet;
use std::io::ErrorKind;
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::task::JoinSet;
use tracing::{error, instrument};

///////////////////////////////////////////////////////////////////////////
// EthernetReceiverObserver
///////////////////////////////////////////////////////////////////////////
pub trait EthernetReceiverObserver: Send + 'static {
    fn on_frame(
        &mut self,
        interface_mac: MacAddr,
        frame: &[u8],
        source_mac: MacAddr,
        destination_mac: MacAddr,
    );
}

///////////////////////////////////////////////////////////////////////////
// EthernetReceiverInterface
///////////////////////////////////////////////////////////////////////////
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct EthernetReceiverInterface {
    pub mac: MacAddr,
    pub if_index: u32,
}

impl EthernetReceiverInterface {
    pub fn find(if_name: &str) -> anyhow::Result<Self> {
        let interfaces = pnet::datalink::interfaces();
        let Some(interface) = interfaces.iter().find(|e| e.name == if_name) else {
            anyhow::bail!("Interface not found: {if_name}");
        };
        let Some(mac) = interface.mac else {
            anyhow::bail!("Failed to retrieve MAC address for interface {if_name}");
        };

        Ok(Self {
            mac,
            if_index: interface.index,
        })
    }
}

///////////////////////////////////////////////////////////////////////////
// EthernetReceiver
///////////////////////////////////////////////////////////////////////////
pub struct EthernetReceiver {
    map: IndexMap<EthernetReceiverInterface, EthernetReceiverRecord>,
}

struct EthernetReceiverRecord {
    socket: EthernetReceiverSocket,
    observers: Vec<(EtherType, Box<dyn EthernetReceiverObserver>)>,
}

impl EthernetReceiver {
    pub const ETHER_TYPE: EtherType = EtherType(0x893A);
    pub const LLDP_TYPE: EtherType = EtherType(0x88CC);

    const RETRY_TIMEOUT_MIN: Duration = Duration::from_millis(10);
    const RETRY_TIMEOUT_MAX: Duration = Duration::from_secs(1);

    pub fn new() -> Self {
        Self {
            map: Default::default(),
        }
    }

    pub fn subscribe(
        &mut self,
        interface: EthernetReceiverInterface,
        ether_type: EtherType,
        observer: impl EthernetReceiverObserver,
    ) -> anyhow::Result<()> {
        let record = match self.map.entry(interface) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => e.insert(EthernetReceiverRecord {
                socket: EthernetReceiverSocket::open(&interface)?,
                observers: vec![],
            }),
        };
        Ok(record.observers.push((ether_type, Box::new(observer))))
    }

    pub fn start(self) -> anyhow::Result<JoinSet<()>> {
        let mut join_set = JoinSet::new();
        for (interface, record) in self.map {
            let socket = AsyncFd::with_interest(record.socket, Interest::READABLE)?;
            join_set.spawn(worker(socket, interface, record.observers));
        }
        Ok(join_set)
    }
}

///////////////////////////////////////////////////////////////////////////
// EthernetReceiverWorker
///////////////////////////////////////////////////////////////////////////
#[instrument(skip_all, name = "ethernet_receiver", fields(task = next_task_id()))]
async fn worker(
    socket: AsyncFd<EthernetReceiverSocket>,
    interface: EthernetReceiverInterface,
    mut observers: Vec<(EtherType, Box<dyn EthernetReceiverObserver>)>,
) {
    let mut socket_addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut socket_addr_len: libc::socklen_t = 0;
    let mut retry_timeout = EthernetReceiver::RETRY_TIMEOUT_MIN;
    let mut buffer = [0u8; 8192];

    loop {
        let mut guard = match socket.readable().await {
            Ok(e) => {
                retry_timeout = EthernetReceiver::RETRY_TIMEOUT_MIN;
                e
            }
            Err(e) => {
                if e.kind() != ErrorKind::TimedOut {
                    error!("Error polling ethernet frame: {e}");
                    std::thread::sleep(retry_timeout);
                    retry_timeout = (retry_timeout * 4).min(EthernetReceiver::RETRY_TIMEOUT_MAX);
                }
                continue;
            }
        };

        let recv_result = unsafe {
            libc::recvfrom(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
                std::ptr::from_mut(&mut socket_addr).cast(),
                std::ptr::from_mut(&mut socket_addr_len).cast(),
            )
        };

        // handle error if any
        if recv_result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == ErrorKind::WouldBlock {
                guard.clear_ready();
            } else {
                error!("Error reading ethernet frame: {error}");
            }
            continue;
        }

        // the peer has performed an orderly shutdown
        if recv_result == 0 {
            continue;
        }

        let Some(buffer) = buffer.get(..recv_result as usize) else {
            error!("libc::recvfrom returned invalid range: {recv_result}");
            continue;
        };

        let Some(packet) = EthernetPacket::new(buffer) else {
            error!("Failed to parse Ethernet frame");
            continue;
        };

        for (observer_ether_type, observer) in observers.iter_mut() {
            if packet.get_ethertype() != *observer_ether_type {
                continue;
            }
            observer.on_frame(
                interface.mac,
                packet.payload(),
                packet.get_source(),
                packet.get_destination(),
            );
        }
    }
}

///////////////////////////////////////////////////////////////////////////
// EthernetReceiverSocket
///////////////////////////////////////////////////////////////////////////
#[derive(Debug)]
#[repr(transparent)]
struct EthernetReceiverSocket(RawFd);

impl EthernetReceiverSocket {
    pub fn open(interface: &EthernetReceiverInterface) -> std::io::Result<Self> {
        let socket_type = libc::SOCK_RAW;
        let socket_proto = libc::ETH_P_ALL;

        let socket = unsafe { libc::socket(libc::AF_PACKET, socket_type, socket_proto.to_be()) };
        let socket = match socket {
            -1 => return Err(std::io::Error::last_os_error()),
            _ => Self(socket),
        };

        // Bind to interface
        let mut socket_addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        unsafe {
            let sll: &mut libc::sockaddr_ll = std::mem::transmute(&mut socket_addr_storage);
            sll.sll_family = libc::AF_PACKET as libc::sa_family_t;
            let [a, b, c, d, e, f] = interface.mac.octets();
            sll.sll_addr = [a, b, c, d, e, f, 0, 0];
            sll.sll_protocol = (socket_proto as u16).to_be();
            sll.sll_halen = 6;
            sll.sll_ifindex = interface.if_index as i32;
        };

        let send_addr_len = size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        let send_addr = std::ptr::from_ref(&socket_addr_storage).cast::<libc::sockaddr>();

        let result = unsafe { libc::bind(socket.0, send_addr, send_addr_len) };
        if result == -1 {
            return Err(std::io::Error::last_os_error());
        }

        // Enable promiscuous capture
        let mut packet_mreq: libc::packet_mreq = unsafe { std::mem::zeroed() };
        packet_mreq.mr_ifindex = interface.if_index as i32;
        packet_mreq.mr_type = libc::PACKET_MR_PROMISC as u16;

        let packet_mreq_len = size_of::<libc::packet_mreq>() as libc::socklen_t;
        let packet_mreq_ptr = std::ptr::from_ref(&packet_mreq).cast();
        let result = unsafe {
            libc::setsockopt(
                socket.0,
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                packet_mreq_ptr,
                packet_mreq_len,
            )
        };

        if result == -1 {
            return Err(std::io::Error::last_os_error());
        }

        // Enable nonblocking
        let result = unsafe { libc::fcntl(socket.0, libc::F_SETFL, libc::O_NONBLOCK) };
        if result == -1 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(socket)
    }
}

impl Drop for EthernetReceiverSocket {
    fn drop(&mut self) {
        let _ = unsafe { libc::close(self.as_raw_fd()) };
    }
}

impl AsRawFd for EthernetReceiverSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

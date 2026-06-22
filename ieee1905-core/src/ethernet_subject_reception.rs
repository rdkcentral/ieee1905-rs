/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2025 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

use crate::interface_manager::{InterfaceInfo, get_interface_info};
use crate::{next_task_id, spawn_join_set_named};
use anyhow::bail;
use async_trait::async_trait;
use pnet::datalink::EtherType;
use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::mem::size_of_val;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Duration;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::task::JoinSet;
use tracing::{debug, error, info, instrument, warn};

/// Observer trait for handling specific Ethernet frame types
#[async_trait]
pub trait EthernetFrameObserver: Send + Sync + 'static {
    async fn on_frame(&self, if_info: &InterfaceInfo, packet: &EthernetPacket);
    fn get_ethertype(&self) -> u16;
}

#[derive(Default)]
pub struct EthernetReceiver {
    map: HashMap<String, HashMap<u16, Box<dyn EthernetFrameObserver>>>,
}

impl EthernetReceiver {
    ///////////////////////////////////////////////////////////////////////////
    pub fn subscribe(&mut self, interface_name: &str, observer: impl EthernetFrameObserver) {
        let ether_type = observer.get_ethertype();
        let observers = self.map.entry(interface_name.to_string()).or_default();

        match observers.entry(ether_type) {
            Entry::Occupied(_) => {
                warn!(
                    "observer for EtherType 0x{ether_type:04X} is already subscribed — skipping duplicate"
                );
            }
            Entry::Vacant(e) => {
                e.insert(Box::new(observer));
            }
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    pub fn run(self) -> anyhow::Result<JoinSet<()>> {
        let mut join_set = JoinSet::new();
        for (interface_name, observers) in self.map {
            let Some(if_info) = get_interface_info(&interface_name) else {
                bail!("Interface not found: {interface_name}");
            };

            let socket = AsyncSocket::open(&if_info)?;

            spawn_join_set_named(
                format!("eth_recv/{interface_name}"),
                None,
                &mut join_set,
                Self::run_socket_worker(if_info, socket, observers),
            );
        }
        Ok(join_set)
    }

    ///////////////////////////////////////////////////////////////////////////
    #[instrument(
        skip_all,
        name = "ethernet_receiver",
        fields(task = next_task_id(), if_name = if_info.if_name)
    )]
    async fn run_socket_worker(
        if_info: InterfaceInfo,
        socket: AsyncSocket,
        observers: HashMap<EtherType, Box<dyn EthernetFrameObserver>>,
    ) {
        info!("listening on {}", if_info.mac);

        let mut buffer = [0u8; 2048];
        loop {
            let length = socket.recv(&mut buffer).await;

            let Some(packet) = EthernetPacket::new(&buffer[..length]) else {
                error!("failed to parse Ethernet frame.");
                continue;
            };

            let ether_type = packet.get_ethertype().0;
            let Some(observer) = observers.get(&ether_type) else {
                continue;
            };

            debug!(
                eth_type = format!("0x{ether_type:04X}"),
                src = %packet.get_source(),
                dst = %packet.get_destination(),
                payload_len = packet.payload().len(),
                "received Ethernet frame"
            );

            observer.on_frame(&if_info, &packet).await;
        }
    }
}

pub(crate) struct AsyncSocket {
    async_fd: AsyncFd<OwnedFd>,
    if_index: i32,
}

impl AsyncSocket {
    const RETRY_TIMEOUT_MIN: Duration = Duration::from_millis(10);
    const RETRY_TIMEOUT_MAX: Duration = Duration::from_secs(1);

    ///////////////////////////////////////////////////////////////////////////
    pub(crate) fn open(if_info: &InterfaceInfo) -> anyhow::Result<Self> {
        // ETH_P_ALL so the socket receives every ether-type on the interface
        let protocol = Protocol::from(i32::from((libc::ETH_P_ALL as u16).to_be()));
        let socket = Socket::new(Domain::PACKET, Type::RAW, Some(protocol))?;
        socket.set_nonblocking(true)?;

        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        sll.sll_ifindex = if_info.if_index as i32;

        // SAFETY: `sll` is a fully-initialised sockaddr_ll and the passed length matches it.
        let ret = unsafe {
            libc::bind(
                socket.as_raw_fd(),
                std::ptr::from_ref(&sll).cast(),
                size_of_val(&sll) as libc::socklen_t,
            )
        };

        if ret != 0 {
            bail!(
                "failed to bind AF_PACKET socket to interface {} (os error {})",
                if_info.if_name,
                std::io::Error::last_os_error(),
            );
        }

        let owned_fd = OwnedFd::from(socket);
        let async_fd = AsyncFd::with_interest(owned_fd, Interest::READABLE | Interest::WRITABLE)?;
        Ok(Self {
            async_fd,
            if_index: if_info.if_index as i32,
        })
    }

    ///////////////////////////////////////////////////////////////////////////
    async fn recv(&self, buffer: &mut [u8]) -> usize {
        let mut retry_timeout = Self::RETRY_TIMEOUT_MIN;

        loop {
            // Async, non-blocking read driven by the tokio reactor — no blocking task.
            let read = self
                .async_fd
                .async_io(Interest::READABLE, |fd| {
                    // SAFETY: reading into a valid buffer; src/src_len are valid out-params.
                    let n = unsafe {
                        let mut sll = std::mem::zeroed::<libc::sockaddr_ll>();
                        let mut sll_len = size_of_val(&sll) as libc::socklen_t;
                        libc::recvfrom(
                            fd.as_raw_fd(),
                            buffer.as_mut_ptr().cast(),
                            buffer.len(),
                            0,
                            std::ptr::from_mut(&mut sll).cast(),
                            &mut sll_len,
                        )
                    };
                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                })
                .await;

            match read {
                Ok(n) => return n,
                Err(e) => {
                    error!("error receiving Ethernet frame: {e}");
                    tokio::time::sleep(retry_timeout).await;
                    retry_timeout = (retry_timeout * 4).min(Self::RETRY_TIMEOUT_MAX);
                }
            };
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    pub(crate) async fn send(&self, buffer: &[u8]) -> std::io::Result<usize> {
        // Async, non-blocking write driven by the tokio reactor — no blocking call.
        self.async_fd
            .async_io(Interest::WRITABLE, |fd| {
                // SAFETY: sending a valid buffer to a correctly-sized, fully-initialised sockaddr_ll.
                let n = unsafe {
                    // Destination link-layer address (as pnet does): the kernel uses sll_ifindex to choose
                    // the outgoing interface; for SOCK_RAW the frame already carries the ethernet header.
                    let mut sll = std::mem::zeroed::<libc::sockaddr_ll>();
                    sll.sll_family = libc::AF_PACKET as u16;
                    sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
                    sll.sll_ifindex = self.if_index;

                    libc::sendto(
                        fd.as_raw_fd(),
                        buffer.as_ptr().cast(),
                        buffer.len(),
                        0,
                        std::ptr::from_ref(&sll).cast(),
                        size_of_val(&sll) as libc::socklen_t,
                    )
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            })
            .await
    }
}

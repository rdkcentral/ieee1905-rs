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

#![deny(warnings)]
use clap::Parser;
use ieee1905::al_sap::AlServiceAccessPoint;
use ieee1905::cmdu_handler::*;
use ieee1905::cmdu_message_id_generator::get_message_id_generator;
use ieee1905::cmdu_proxy::cmdu_topology_discovery_transmission_worker;
use ieee1905::ethernet_subject_reception::EthernetReceiver;
use ieee1905::ethernet_subject_transmission::EthernetSender;
use ieee1905::interface_manager::*;
use ieee1905::lldpdu_observer::LLDPObserver;
use ieee1905::lldpdu_proxy::lldp_discovery_worker;
use ieee1905::topology_manager::*;
use ieee1905::{next_task_id, CMDUObserver};
//use ieee1905::crypto_engine::CRYPTO_CONTEXT;
use std::sync::Arc;
use std::time::Duration;
use anyhow::anyhow;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::oneshot;
use tokio::sync::Mutex;
use tracing::instrument;
use tracing_subscriber::{prelude::*, EnvFilter};
use tracing_appender::rolling;
use tracing_subscriber::fmt::format::FmtSpan;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct CliArgs {
    /// Turn on the topology text UI
    #[arg(short, long, default_value_t = false)]
    topology_ui: bool,
    /// Ethernet interface to be used
    #[arg(long,short,default_value_t=String::from("eth0"))]
    interface: String,
    /// Control socket path
    #[arg(long,default_value_t=String::from("/tmp/al_control_socket"))]
    sap_control_path: String,
    /// Data socket path
    #[arg(long,default_value_t=String::from("/tmp/al_data_socket"))]
    sap_data_path: String,
    /// Tracing filter
    #[arg(long,short,default_value_t=String::from("info"))]
    filter: String,
    /// Enable console subscriber for tokio-console
    #[cfg(feature = "enable_tokio_console")]
    #[arg(short, long, default_value_t = false)]
    console_subscriber: bool,
    /// Enable file appender
    #[arg(long, default_value_t = false)]
    file_appender: bool,
    /// Disable stdout log
    #[arg(short, long, default_value_t = false)]
    stdout_apender: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = CliArgs::parse();

    // Start the Tokio console subscriber
    std::env::set_var("RUST_CONSOLE_BIND", "0.0.0.0:6669");

    // Modify this filter for your tracing during run time
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(cli.filter.clone())); //add 'tokio=trace' to debug the runtime

    // To show logs in stdout
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_level(true)
        .with_span_events(FmtSpan::CLOSE);

    let file_appender = rolling::daily("logs", "app.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(non_blocking)
        .with_target(true)
        .with_level(true)
        .with_span_events(FmtSpan::CLOSE);

    #[cfg(feature = "enable_tokio_console")]
    {
        // To register your tracing
        if cli.console_subscriber {
            if cli.topology_ui {
                tracing_subscriber::registry()
                    .with(file_layer)
                    .with(filter)
                    .with(console_subscriber::spawn())
                    .init();
            } else {
                tracing_subscriber::registry()
                    .with(file_layer)
                    .with(filter)
                    .with(fmt_layer)
                    .with(console_subscriber::spawn())
                    .init();
            }
        } else {
            if cli.topology_ui {
                tracing_subscriber::registry()
                    .with(file_layer)
                    .with(filter)
                    .init();
            } else {
                tracing_subscriber::registry()
                    .with(file_layer)
                    .with(filter)
                    .with(fmt_layer)
                    .init();
            }
        }
    }

    #[cfg(not(feature = "enable_tokio_console"))]
    {
        tracing::info!("Tokio console: Disabled");
        if cli.topology_ui {
            tracing_subscriber::registry()
                .with(file_layer)
                .with(filter)
                //.with(fmt_layer)
                .init();
        } else {
            tracing_subscriber::registry()
                .with(file_layer)
                .with(filter)
                .with(fmt_layer)
                .init();
        }
    }

    tracing::debug!("Logger initialized with RUST_LOG."); // Start your application tracing

    tracing::info!("Tracing initialized!");

    tracing::info!("Fragmentation type: SIZE BASED");

    #[cfg(feature = "enable_tokio_console")]
    tracing::info!("Tokio console: Enabled");

    #[cfg(not(feature = "enable_tokio_console"))]
    tracing::info!("Tokio console: Disabled");

    tracing::info!("TOPOLOGY_UI {:?}", cli.topology_ui);

    //ADDING logic for CRYPTO_CONTEXT here
    //let context = CRYPTO_CONTEXT.clone();
    //let ctx = context.lock().await;
    //the keys are stored in  ctx.gtk_key and ctx.pmk_key
    //We need to insert the PIN value to access softHSM2 as env variable or hardcoded

    loop {
        tracing::info!("Starting runtime");
        let runtime = tokio::runtime::Runtime::new()?;

        tracing::info!("Runtime started");
        if runtime.block_on(run_main_logic(&cli))? {
            break;
        }

        tracing::info!("Releasing runtime");
        // timeout is used for blocking tasks, which in our case are related to datalink channels.
        // all such tasks are configured to have a 1-second timeout, so will die at most in 1 second.
        runtime.shutdown_timeout(Duration::from_secs(2));
        tracing::info!("Runtime released");
    }
    
    tracing::info!("Closing app.");
    Ok(())
}

#[instrument(skip_all, name = "main", fields(task = next_task_id()))]
async fn run_main_logic(cli: &CliArgs) -> anyhow::Result<bool> {
    let mut join_sets = Vec::new();

    //Set AL MAC & test MAC addresses
    let forwarding_interface =
        if let Some(iface) = get_forwarding_interface_name(cli.interface.clone()) {
            tracing::info!("Forwarding interface: {}", iface);
            iface
        } else {
            tracing::debug!("No Ethernet interface found for forwarding, using default.");
            "eth_default".to_string() // Default interface name if none found
        };


    // Calculate AL MAC Address (Derived from Forwarding Ethernet Interface)
    let al_mac = get_local_al_mac(cli.interface.clone()).ok_or_else(|| {
        anyhow!("failed to get local al mac")
    })?;
    tracing::info!("AL MAC address: {}", al_mac);

    // // Initialize Database

    let topology_db = TopologyDatabase::get_instance(al_mac, cli.interface.clone()).await;
    let _db_workers = topology_db.start_workers();

    // Upon every loop restart topology database role can change
    topology_db.set_local_role(None).await;

    // Find Forwarding MAC Address (Ethernet Interface)
    let forwarding_mac = topology_db.get_forwarding_interface_mac().await;
    tracing::info!("Forwarding MAC address: {}", forwarding_mac);

    //we initilize here the values for LLDP input parameters
    let chassis_id = al_mac;

    tracing::debug!("Topology Database initialized with AL MAC: {:?}", al_mac);

    // Initialize Message ID Generator for CMDUs
    let message_id_generator = get_message_id_generator().await;

    // Initialization for Tx

    // Create shared mutex for exclusive access to network interfaces for transmission
    let mutex_tx = Arc::new(Mutex::new(()));

    // Initialize Ethernet Sender

    let forwarding_interface_tx = forwarding_interface.clone();
    let sender = Arc::new(EthernetSender::new(&forwarding_interface_tx, Arc::clone(&mutex_tx)));

    // Initialization for adaptation layer SAP

    //Initialization of the socket paths
    let sap_control_path = cli.sap_control_path.clone();
    let sap_data_path = cli.sap_data_path.clone();

    // Clonning of Tx structures to be used from the AL-SAP
    let sender_clone = Arc::clone(&sender);
    let forwarding_interface_clone = forwarding_interface.clone();

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    // Launch of AL-SAP as independent task
    tokio::task::spawn(AlServiceAccessPoint::initialize_and_store(
        sap_control_path,
        sap_data_path,
        sender_clone,
        forwarding_interface_clone,
        shutdown_tx,
    ));

    // Initialization of the CMDU handler
    let cmdu_handler = Arc::new(
        CMDUHandler::new(
            Arc::clone(&sender),
            Arc::clone(&message_id_generator),
            al_mac,
            forwarding_interface.clone(),
        )
            .await,
    );

    // Initialize CMDU Observer
    let cmdu_observer = CMDUObserver::new(Arc::clone(&cmdu_handler));
    // FLAG to enable and disable LLDP
    // Initialize LLDP Observer with chassis_id assuming al_mac an chassis id have the same value as idicated in IEEE1905
    let lldp_observer = LLDPObserver::new(chassis_id, cli.interface.clone());

    tracing::info!("LLDP and CMDU observers initilized with local MAC: {al_mac}");

    // Initialize Ethernet Receiver
    let mut receiver = EthernetReceiver::new();

    // Subscription of observers
    receiver.subscribe(cmdu_observer);
    tracing::info!("CMDU observers subscribed with local MAC: {al_mac}");

    // Launch of receiver, take in account logic for Rx is sperated from Logic for Tx, so we clone the forwarding_interface
    join_sets.push(receiver.run(&forwarding_interface)?);

    // Sart of the discovery process

    for interface in get_physical_ethernet_interfaces() {
        tracing::info!("Starting LLDP Discovery on {}/{}", interface.name, interface.mac);

        let mut lldp_receiver = EthernetReceiver::new();
        lldp_receiver.subscribe(lldp_observer.clone());
        join_sets.push(lldp_receiver.run(&interface.name)?);

        let lldp_sender = EthernetSender::new(&interface.name, Arc::clone(&mutex_tx));
        tokio::task::spawn(lldp_discovery_worker(lldp_sender, chassis_id, interface.mac, interface.name));
    }

    let discovery_interface_ieee1905 = forwarding_interface.clone();

    tracing::debug!("Starting IEEE1905 Discovery on {}", forwarding_interface);

    tokio::task::spawn(cmdu_topology_discovery_transmission_worker(
        discovery_interface_ieee1905,
        Arc::clone(&sender),
        Arc::clone(&message_id_generator),
        al_mac,
        forwarding_mac,
    ));

    let mut signal_terminate = signal(SignalKind::terminate())?;
    let mut signal_interrupt = signal(SignalKind::interrupt())?;

    // if topology_cli is running
    // you can close app by pressing q
    let mut exit_service = true;

    tokio::select! {
        _ = signal_terminate.recv() => {},
        _ = signal_interrupt.recv() => {},
        _ = shutdown_rx => {
            tracing::info!("Socket closed. Trying to restart.");
            exit_service = false;
        }
        _ = topology_db.start_topology_cli(), if cli.topology_ui => {}
    }
    Ok(exit_service)
}

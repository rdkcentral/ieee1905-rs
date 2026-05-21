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

use clap::{Parser, ValueEnum};
use ieee1905::registration_codec::ServiceType;

#[path = "functional_tests_receiver.rs"]
#[allow(dead_code)]
mod functional_tests_receiver;
#[path = "functional_tests_transmitter.rs"]
#[allow(dead_code)]
mod functional_tests_transmitter;

#[derive(Clone, Debug, ValueEnum)]
enum NodeRole {
    /// Controller role: waits for AP autoconfig search and replies with AP autoconfig response
    Controller,
    /// Agent role: sends AP autoconfig search every 10 seconds
    Agent,
    /// Rogue agent role: sends malformed AP autoconfig search with invalid searched role
    #[value(name = "rogue_agent")]
    RogueAgent,
    /// Fast rogue agent role: sends malformed AP autoconfig search three times per second
    #[value(name = "rogue-agent-fast")]
    RogueAgentFast,
}

#[derive(Parser)]
#[command(version, about, long_about = None, name = "IEEE1905 test node")]
struct Args {
    /// Node role to run
    #[clap(value_enum)]
    role: NodeRole,

    /// Control socket path
    #[clap(short = 'c', long, default_value = "/tmp/al_control_socket")]
    control_path: String,

    /// Data socket path
    #[clap(short = 'd', long, default_value = "/tmp/al_data_socket")]
    data_path: String,

    /// Turn on the topology text UI
    #[arg(long, default_value_t = false)]
    topology_ui: bool,

    /// Ethernet interface to be shown by the topology text UI
    #[arg(long, short, default_value_t = String::from("eth0"))]
    interface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.role {
        NodeRole::Controller => {
            functional_tests_receiver::run_with_config(
                &args.control_path,
                &args.data_path,
                &args.interface,
                args.topology_ui,
                ServiceType::EasyMeshController,
            )
            .await
        }
        NodeRole::Agent => {
            functional_tests_transmitter::run_with_config(
                &args.control_path,
                &args.data_path,
                &args.interface,
                args.topology_ui,
                5,
                100,
                100,
            )
            .await
        }
        NodeRole::RogueAgent => {
            functional_tests_transmitter::run_with_config(
                &args.control_path,
                &args.data_path,
                &args.interface,
                args.topology_ui,
                7,
                100,
                100,
            )
            .await
        }
        NodeRole::RogueAgentFast => {
            functional_tests_transmitter::run_with_config(
                &args.control_path,
                &args.data_path,
                &args.interface,
                args.topology_ui,
                8,
                100,
                100,
            )
            .await
        }
    }
}

use futures::{FutureExt, SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::process::Stdio;
use std::str::FromStr;
use std::sync::Arc;
use structopt::StructOpt;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tun::TunPacket;
use url::Url;

use crate::iptables::{
    create_vpn_config, generate_interface_subnet_and_name, iptables_cleanup,
    iptables_route_to_interface, IpTablesRule,
};
use crate::packet_conv::{packet_ether_to_ip_slice, packet_ip_wrap_to_ether};
use ya_runtime_sdk::error::Error;
use ya_runtime_sdk::server::ContainerEndpoint;
use ya_runtime_sdk::*;

use crate::routing::RoutingTable;

#[derive(StructOpt)]
#[structopt(rename_all = "kebab-case")]
pub struct GatewayCli {
    /// VPN endpoint address
    #[structopt(long)]
    vpn_endpoint: Option<Url>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct GatewayConf {
    pub outbound_interface: String,
    pub apply_iptables_rules: bool,
}

#[derive(Default, RuntimeDef, Clone)]
#[cli(GatewayCli)]
#[conf(GatewayConf)]
pub struct GatewayRuntime {
    pub routing: RoutingTable,
    pub rules_to_remove: Arc<Mutex<Vec<IpTablesRule>>>,
    pub vpn_endpoint: Option<ContainerEndpoint>,
}

impl Runtime for GatewayRuntime {
    fn deploy<'a>(&mut self, ctx: &mut Context<Self>) -> OutputResponse<'a> {
        //logs from here are not yet visible in exe unit logs
        log::info!(
            "Running `Deploy` command. Vpn endpoint: {:?}",
            ctx.cli.runtime.vpn_endpoint
        );

        // SDK will auto-generate the following code:
        //
        // async move {
        //     Ok(Some(serialize::json::json!({
        //         "startMode": "blocking",
        //         "valid": {"Ok": ""},
        //         "vols": []
        //     })))
        // }
        // .boxed_local()

        async move { Ok(None) }.boxed_local()
    }

    fn start<'a>(&mut self, ctx: &mut Context<Self>) -> OutputResponse<'a> {
        //these logs seems to be visible in proper folder
        log::info!("Running `Start` command. Vpn endpoint: {:?}. Gateway configuration {:?}", ctx.cli.runtime.vpn_endpoint, ctx.conf);

        let _emitter = ctx
            .emitter
            .clone()
            .expect("Service not running in Server mode");

        let _workdir = ctx.cli.workdir.clone().expect("Workdir not provided");

        self.vpn_endpoint = match ctx
            .cli
            .runtime
            .vpn_endpoint
            .clone()
            .map(ContainerEndpoint::try_from)
        {
            Some(Ok(endpoint)) => Some(endpoint),
            Some(Err(e)) => return Error::response(format!("Failed to parse VPN endpoint: {e}")),
            None => {
                return Error::response("Start command expects VPN endpoint, but None was found.")
            }
        };

        async move {
            //endpoint.connect(cep).await?;
            Ok(Some(serde_json::json!({})))
        }
        .boxed_local()
    }

    fn stop<'a>(&mut self, _: &mut Context<Self>) -> EmptyResponse<'a> {
        // Gracefully shutdown the service
        log::info!("Running `Stop` command");
        let ip_rules_to_remove_ext = self.rules_to_remove.clone();
        async move {
            // Remove IP rules
            let ip_rules_to_remove = { ip_rules_to_remove_ext.lock().await.clone() };
            log::info!("Cleaning iptables rules: {ip_rules_to_remove:?}");
            iptables_cleanup(ip_rules_to_remove)?;
            Ok(())
        }
        .boxed_local()
    }

    fn run_command<'a>(
        &mut self,
        command: RunProcess,
        mode: RuntimeMode,
        ctx: &mut Context<Self>,
    ) -> ProcessIdResponse<'a> {
        log::info!("Running `Run` command with params: {command:?} mode: {mode:?}");

        if let RuntimeMode::Command = mode {
            return Error::response("Command mode is not supported");
        }

        if command.bin != "test" {
            return Error::response(format!(
                "Only `test` command supported. Provided: command: `{}`, args: `{:?}`",
                command.bin, command.args
            ));
        }

        // Echo the executed command and its arguments
        let started = tokio::process::Command::new("echo")
            .args(["Test: Executing echo command on Provider machine - passed"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .spawn();

        // Wraps command's lifecycle. The handler is executed in background.
        // Result of `started` is handled prior to emitting command lifecycle events.
        futures::future::ready(started).as_command(ctx, |child, mut run_ctx| async move {
            let output = child.wait_with_output().await?;
            run_ctx.stdout(output.stdout).await;
            run_ctx.stderr(output.stderr).await;
            Ok(())
        })
    }

    fn offer<'a>(&mut self, _ctx: &mut Context<Self>) -> OutputResponse<'a> {
        log::info!("Creating Offer template.");
        async move {
            Ok(Some(serde_json::json!({
                "properties": {
                    "golem.runtime.capabilities": ["vpn", "outbound"]
                },
                "constraints": ""
            })))
        }
        .boxed_local()
    }

    /// Join a VPN network
    fn join_network<'a>(
        &mut self,
        create_network: CreateNetwork,
        ctx: &mut Context<Self>,
    ) -> EndpointResponse<'a> {
        log::info!("Running `join_network` with: {create_network:?}");
        if create_network.networks.len() != 1 {
            log::error!("Only one network is supported");
            return Error::response("Only one network is supported");
        }
        let network = match create_network.networks.iter().next() {
            Some(network) => network,
            None => {
                log::error!("No network provided");
                return Error::response("No network provided");
            }
        };

        let yagna_net_ip = match Ipv4Addr::from_str(network.if_addr.as_str()) {
            Ok(ip) => ip,
            Err(err) => {
                log::error!("Error when parsing network ipaddr {err:?}");
                return Error::response(format!("Error when parsing network ipaddr {err:?}"));
            }
        };
        let _yagna_net_mask = match Ipv4Addr::from_str(network.mask.as_str()) {
            Ok(mask) => {
                if mask != Ipv4Addr::new(255, 255, 255, 0) {
                    log::error!("255.255.255.0 mask is supported right now");
                    return Error::response("255.255.255.0 mask is supported right now");
                }
                mask
            }
            Err(err) => {
                log::error!("Error when parsing network mask {err:?}");
                return Error::response(format!("Error when parsing network mask {err:?}"));
            }
        };
        let yagna_net_addr = match Ipv4Addr::from_str(network.addr.as_str()) {
            Ok(addr) => addr,
            Err(err) => {
                log::error!("Error when parsing network addr {err:?}");

                return Error::response(format!("Error when parsing network addr {err:?}"));
            }
        };

        let vpn_subnet_info = match generate_interface_subnet_and_name(yagna_net_ip.octets()[3]) {
            Ok(vpn_subnet_info) => vpn_subnet_info,
            Err(err) => {
                return Error::response(format!(
                    "Error when generating interface subnet and name {err:?}"
                ))
            }
        };

        log::info!("VPN subnet: {vpn_subnet_info:?}");

        let tun_config = create_vpn_config(&vpn_subnet_info);
        let ip_rules_to_remove_ext = self.rules_to_remove.clone();
        // TODO: I'm returning here the same endpoint, that I got from ExeUnit.
        //       In reality I should start listening on the same protocol as ExeUnit
        //       Requested and return my endpoint address here.
        let routing = self.routing.clone();

        let vpn_endpoint = match &self.vpn_endpoint {
            Some(container_endpoint) => match container_endpoint {
                ContainerEndpoint::UdpDatagram(udp_socket_addr) => {
                    log::info!("Using UDP endpoint: {}", udp_socket_addr);
                    udp_socket_addr.clone()
                }
                _ => {
                    log::error!("Only UDP endpoint is supported");
                    return Error::response("Only UDP endpoint is supported");
                }
            },
            None => {
                log::error!("No VPN endpoint provided");
                return Error::response("No VPN endpoint provided");
            }
        };
        let outbound_interface = ctx.conf.outbound_interface.clone();
        let apply_ip_tables_rules = ctx.conf.apply_iptables_rules;
        async move {
            //let tun =
            let socket = Arc::new(UdpSocket::bind(("127.0.0.1", 0)).await.unwrap());
            let endpoint = ContainerEndpoint::UdpDatagram(socket.local_addr().unwrap());

            log::info!("Listening on: {}", socket.local_addr().unwrap());
            let dev = tun::create_as_async(&tun_config).unwrap();

            //Leaving this code inactive for now.
            //TODO: use when rules will be needed
            if apply_ip_tables_rules {
                let ip_rules_to_remove =
                    iptables_route_to_interface(&outbound_interface, &vpn_subnet_info.interface_name).unwrap();
                {
                    //use this method due to runtime issues
                    *ip_rules_to_remove_ext.lock().await = ip_rules_to_remove;
                }
            }

            let (mut tun_write, mut tun_read) = dev.into_framed().split();
            //let r = Arc::new(socket);
            //let s = r.clone();
            let (_udp_socket_write, _rx_forward_to_socket) = mpsc::channel::<Vec<u8>>(1);

            let socket_ = socket.clone();
            tokio::spawn(async move {
                loop {
                    if let Some(Ok(packet)) = tun_read.next().await {
                        //todo: add mac addresses
                        match packet_ip_wrap_to_ether(
                            &packet.get_bytes(),
                            None,
                            None,
                            Some(&vpn_subnet_info.subnet.octets()),
                            Some(&yagna_net_addr.octets()),
                        ) {
                            Ok(ether_packet) => {
                                if let Err(err) =
                                    socket_.send_to(&ether_packet, &vpn_endpoint).await
                                {
                                    log::error!(
                                        "Error sending packet to udp endpoint {}: {:?}",
                                        &vpn_endpoint,
                                        err
                                    );
                                }
                            }
                            Err(e) => {
                                log::error!("Error wrapping packet: {:?}", e);
                            }
                        }
                    }
                }
            });

            tokio::spawn(async move {
                const MAX_PACKET_SIZE: usize = 65535;
                let mut buf_box = Box::new([0; MAX_PACKET_SIZE]); //sufficient to hold jumbo frames (probably around 9000)
                let buf = &mut *buf_box;
                loop {
                    let (len, addr) = socket.recv_from(buf).await.unwrap();
                    log::trace!("{len:?} bytes received from {addr:?}");
                    log::trace!("Packet content {:?}", &buf[..len]);
                    match packet_ether_to_ip_slice(
                        &mut buf[..len],
                        Some(&yagna_net_addr.octets()),
                        Some(&vpn_subnet_info.subnet.octets()),
                    ) {
                        Ok(ip_slice) => {
                            log::trace!("IP packet: {:?}", ip_slice);
                            if let Err(err) =
                                tun_write.send(TunPacket::new(ip_slice.to_vec())).await
                            {
                                log::error!("Error sending packet: {:?}", err);
                            }
                        }
                        Err(e) => {
                            log::error!("Error unwrapping packet: {:?}", e);
                        }
                    }
                }
            });
            routing.update_network(create_network).await?;
            Ok(endpoint)

            //endpoint.connect(cep).await?;
            /*Ok(Some(serde_json::json!({
                "endpoint": new_endpoint,
                "vpn-subnet-info": vpn_subnet_info,
            })))*/
        }
        .boxed_local()
    }
}

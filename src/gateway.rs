use futures::FutureExt;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::process::Stdio;
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use structopt::StructOpt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use url::Url;

use crate::iptables::{
    create_vpn_config, generate_interface_subnet_and_name, iptables_cleanup,
    iptables_route_to_interface, IpTablesRule,
};
use crate::packet_conv::{
    packet_ether_to_ip_slice, packet_ip_wrap_to_ether_in_place, MacAddressCache,
};
use ya_runtime_sdk::error::Error;
use ya_runtime_sdk::server::ContainerEndpoint;
use ya_runtime_sdk::*;

use crate::routing::RoutingTable;
use crate::stats::{InboundStats, InboundStatsAtomic, OutboundStats, OutboundStatsAtomic};

const MAX_PACKET_SIZE: usize = 65535;

#[derive(StructOpt)]
#[structopt(rename_all = "kebab-case")]
pub struct GatewayCli {
    /// VPN endpoint address
    #[structopt(long)]
    vpn_endpoint: Option<Url>,
}

/// Gateway local configuration
/// Default location: ~/.local/share/ya-runtime-gateway/ya-runtime-gateway.json
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayConf {
    pub outbound_interface: Option<String>,
    pub apply_iptables_rules: bool,
    pub allow_packets_to_local: bool,
    pub print_packet_errors: bool,
    pub debug_log_all_packets: bool,
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
        log::info!("Running `Start` command. Vpn endpoint: {:?}. Gateway configuration {:?} Config path {:?}", ctx.cli.runtime.vpn_endpoint, ctx.conf, ctx.conf_path);

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
        let network = match create_network.networks.first() {
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
                log::error!("Error when generating interface subnet and name {err:?}");
                return Error::response(format!(
                    "Error when generating interface subnet and name {err:?}"
                ));
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
                    *udp_socket_addr
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
        let print_packet_errors = ctx.conf.print_packet_errors;
        let debug_log_all_packets = ctx.conf.debug_log_all_packets;
        if print_packet_errors {
            log::warn!("Packet errors will be printed, this may affect performance");
        }
        let allow_packets_to_local = ctx.conf.allow_packets_to_local;
        if allow_packets_to_local {
            log::warn!("Allowing packets to local network");
        } else {
            log::info!("Packets to local network will be dropped");
        }
        let mut emitter = ctx
            .emitter
            .clone()
            .expect("No emitter, Service not running in Server mode");

        let ip_addr = yagna_net_ip.octets();

        let mac_address = [0xA0, 0x13, ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]];
        log::info!(
            "Generate MAC address for node {:?}: {:?}",
            ip_addr,
            mac_address
        );
        let mac_cache_ = MacAddressCache::new();
        let mac_cache = mac_cache_.clone();
        async move {
            emitter
                .counter(RuntimeCounter {
                    name: "join_network".to_string(),
                    value: 1.0,
                })
                .await;
            //let tun =
            let outbound_stats_ = Arc::new(OutboundStatsAtomic::default());
            let inbound_stats_ = Arc::new(InboundStatsAtomic::default());
            let outbound_stats = outbound_stats_.clone();
            let inbound_stats = inbound_stats_.clone();

            let socket = Arc::new(UdpSocket::bind(("127.0.0.1", 0)).await.map_err(|e| {
                log::error!("Error when binding UDP socket: {e:?}");
                Error::from_string(format!("Error when binding UDP socket: {e:?}"))
            })?);
            let endpoint = ContainerEndpoint::UdpDatagram(socket.local_addr().map_err(|e| {
                log::error!("Error when getting UDP socket address: {e:?}");
                Error::from_string(format!("Error when getting UDP socket address: {e:?}"))
            })?);

            log::info!(
                "Listening on: {}",
                socket.local_addr().map_err(|e| {
                    log::error!("Error when getting UDP socket address: {e:?}");
                    Error::from_string(format!("Error when getting UDP socket address: {e:?}"))
                })?
            );
            let dev = tun::create_as_async(&tun_config).map_err(|e| {
                log::error!("Error when creating TUN device: {e:?}");
                Error::from_string(format!("Error when creating TUN device: {e:?}"))
            })?;

            //Leaving this code inactive for now.
            //TODO: use when rules will be needed
            if apply_ip_tables_rules {
                let Some(outbound_interface) = outbound_interface else {
                    log::error!("No outbound interface provided");
                    return Err(Error::from_string("No outbound interface provided"));
                };
                let ip_rules_to_remove = iptables_route_to_interface(
                    &outbound_interface,
                    &vpn_subnet_info.interface_name,
                )
                .map_err(|e| {
                    log::error!("Error when applying iptables rules: {e:?}");
                    Error::from_string(format!("Error when applying iptables rules: {e:?}"))
                })?;
                {
                    //Save rules to auto remove when runtime is stopped
                    *ip_rules_to_remove_ext.lock().await = ip_rules_to_remove;
                }
            }

            let (mut tun_read, mut tun_write) = tokio::io::split(dev);
            let socket_ = socket.clone();
            tokio::spawn(async move {
                let mut buf = Box::new(vec![0u8; MAX_PACKET_SIZE]);
                loop {
                    if let Ok(packet_size) = tun_read.read(&mut buf[14..]).await {
                        //todo: add mac addresses
                        let ether_packet = &mut buf[..14 + packet_size];
                        if debug_log_all_packets {
                            log::info!("Sending packet, before wrap: {}", hex::encode(&ether_packet[14..]));
                        }
                        match packet_ip_wrap_to_ether_in_place(
                            ether_packet,
                            Some(&mac_address),
                            None,
                            Some(&vpn_subnet_info.subnet.octets()),
                            Some(&yagna_net_addr.octets()),
                            Some(mac_cache.clone())
                        ) {
                            //emitter.counter("vpn.packets.out", 1);
                            Ok(()) => {
                                if debug_log_all_packets {
                                    log::info!("Sending packet, after wrap: {}", hex::encode(&ether_packet));
                                }
                                if let Err(err) = socket_.send_to(ether_packet, &vpn_endpoint).await
                                {
                                    log::error!(
                                        "Error sending packet to udp endpoint {}: {:?}",
                                        &vpn_endpoint,
                                        err
                                    );
                                } else {
                                    inbound_stats
                                        .bytes_received
                                        .fetch_add(packet_size as u64, Ordering::Relaxed);
                                    inbound_stats
                                        .packets_received
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            Err(e) => {
                                inbound_stats
                                    .packets_error
                                    .fetch_add(1, Ordering::Relaxed);
                                if print_packet_errors {
                                    log::error!("Error wrapping packet: {:?}", e);
                                }
                            }
                        }
                    }
                }
            });
            let mac_cache = mac_cache_.clone();

            tokio::spawn(async move {
                let mut buf_box = Box::new([0; MAX_PACKET_SIZE]); //sufficient to hold jumbo frames (probably around 9000)
                let buf = &mut *buf_box;
                loop {
                    let (len, addr) = socket.recv_from(buf).await.unwrap();
                    // check if packet is coming from the exe-unit endpoint, otherwise ignore it
                    if addr != vpn_endpoint {
                        if print_packet_errors {
                            log::error!("Received packet from unknown source: {:?}", addr);
                        }
                        continue;
                    }

                    if debug_log_all_packets {
                        log::info!("Received packet, before slice: {}", hex::encode(&buf[..len]));
                    }

                    match packet_ether_to_ip_slice(
                        &mut buf[..len],
                        Some(&yagna_net_addr.octets()),
                        Some(&vpn_subnet_info.subnet.octets()),
                        !allow_packets_to_local,
                        Some(mac_cache.clone())
                    ) {
                        Ok(ip_slice) => {
                            //log::trace!("IP packet: {:?}", ip_slice);
                            if debug_log_all_packets {
                                log::info!("Received packet, after slice: {}", hex::encode(&ip_slice));
                            }

                            if let Err(err) = tun_write.write(ip_slice).await {
                                log::error!("Error sending packet: {:?}", err);
                            } else {
                                outbound_stats
                                    .bytes_sent
                                    .fetch_add(ip_slice.len() as u64, Ordering::Relaxed);
                                outbound_stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(e) => {
                            match e {
                                ya_relay_stack::Error::Forbidden => {
                                    outbound_stats
                                        .packets_local_drop
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                _ => {
                                    outbound_stats
                                        .packets_error
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            if print_packet_errors {
                                log::error!("Error unwrapping packet: {:?}", e);
                            }
                        }
                    }
                }
            });

            let outbound_stats = outbound_stats_;
            let inbound_stats = inbound_stats_;
            tokio::spawn(async move {
                let mut last_outbound_stats = OutboundStats::default();
                let mut last_inbound_stats = InboundStats::default();
                loop {
                    let outbound_stats = outbound_stats.to_outbound_stats();
                    let inbound_stats = inbound_stats.to_inbound_stats();

                    if outbound_stats != last_outbound_stats {
                        let bytes_sent_mib = outbound_stats.bytes_sent as f64 / 1024.0 / 1024.0;
                        log::info!(
                            "Outgoing statistics: bytes: {} MiB: {} packets: {} dropped: {} error: {}",
                            outbound_stats.bytes_sent,
                            bytes_sent_mib,
                            outbound_stats.packets_sent,
                            outbound_stats.packets_local_drop,
                            outbound_stats.packets_error
                        );
                        emitter
                            .counter(RuntimeCounter {
                                name: "golem.usage.network.out-mib".to_string(),
                                value: bytes_sent_mib,
                            })
                            .await;
                        last_outbound_stats = outbound_stats;
                    }
                    if inbound_stats != last_inbound_stats {
                        let bytes_received_mib =
                            inbound_stats.bytes_received as f64 / 1024.0 / 1024.0;
                        log::info!(
                            "Incoming statistics: bytes: {} MiB: {} packets: {} error: {}",
                            inbound_stats.bytes_received,
                            bytes_received_mib,
                            inbound_stats.packets_received,
                            inbound_stats.packets_error
                        );
                        emitter
                            .counter(RuntimeCounter {
                                name: "golem.usage.network.in-mib".to_string(),
                                value: bytes_received_mib,
                            })
                            .await;
                        last_inbound_stats = inbound_stats;
                    }

                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
            });
            routing.update_network(create_network).await?;
            Ok(endpoint)
        }
        .boxed_local()
    }
}

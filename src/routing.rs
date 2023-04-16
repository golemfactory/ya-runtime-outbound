use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;

use ya_client::model::NodeId;
use ya_runtime_sdk::runtime_api::server::NetworkInterface;
use ya_runtime_sdk::{CreateNetwork, Error};

#[derive(Clone, Debug)]
pub struct Network {
    pub network: IpAddr,
    pub node_ip: IpAddr,
    pub nodes: HashMap<IpAddr, NodeId>,
}

#[derive(Default, Clone)]
pub struct RoutingTable {
    pub routing: Arc<RwLock<RoutingTableImpl>>,
}

#[derive(Default, Clone)]
pub struct RoutingTableImpl {
    pub networks: HashMap<IpAddr, Network>,
}

impl RoutingTable {
    #[allow(dead_code)]
    pub async fn update_network(&self, update: CreateNetwork) -> Result<(), Error> {
        match NetworkInterface::from_i32(update.interface) {
            Some(NetworkInterface::Vpn) => (),
            Some(NetworkInterface::Inet) => {
                return Err(Error::from_string("Only VPN network interface supported."))
            }
            _ => return Err(Error::from_string("No network interface provided.")),
        };

        let mut table = self.routing.write().await;

        for network_update in update.networks {
            let network_address =
                IpAddr::from_str(&network_update.addr).map_err(Error::from_string)?;
            let our_address =
                IpAddr::from_str(&network_update.if_addr).map_err(Error::from_string)?;

            table
                .networks
                .entry(network_address)
                .or_insert(Network {
                    network: network_address,
                    node_ip: our_address,
                    nodes: Default::default(),
                })
                .nodes
                .extend(update.hosts.iter().filter_map(|(ip, node_id)| {
                    let ip_result = IpAddr::from_str(ip);
                    let id_result = NodeId::from_str(node_id);
                    match (ip_result, id_result) {
                        (Ok(ip), Ok(id)) => Some((ip, id)),
                        _ => None,
                    }
                }));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ya_runtime_sdk::runtime_api::server::proto::Network as ProtoNetwork;

    fn create_network_helper(nodes: &[(&str, &str)]) -> CreateNetwork {
        CreateNetwork {
            networks: vec![ProtoNetwork {
                addr: "192.168.0.0".to_string(),
                gateway: "192.168.0.1".to_string(),
                mask: "255.255.255.0".to_string(),
                if_addr: "192.168.0.2".to_string(),
            }],
            hosts: nodes
                .iter()
                .map(|(ip, id)| (ip.to_string(), id.to_string()))
                .collect(),
            interface: NetworkInterface::Vpn as i32,
        }
    }

    async fn get_node(table: &RoutingTable, network: &str, node: &str) -> Option<NodeId> {
        table
            .routing
            .read()
            .await
            .networks
            .get(&IpAddr::from_str(network).unwrap())
            .unwrap()
            .nodes
            .get(&IpAddr::from_str(node).unwrap())
            .cloned()
    }

    #[actix_rt::test]
    async fn update_network_with_wrong_interface() {
        let routing = RoutingTable::default();

        let update = CreateNetwork {
            networks: vec![],
            hosts: Default::default(),
            interface: NetworkInterface::Inet as i32,
        };

        assert!(routing.update_network(update).await.is_err());
    }

    #[actix_rt::test]
    async fn update_network_existing_ip() {
        let routing = RoutingTable::default();

        let update = create_network_helper(&[
            ("192.168.0.3", "0xffad3f81e283983b8e9705b2e31d0c138bb2b1b7"),
            ("192.168.0.4", "0xcfad3f81e283983b8e9705b2e31d0c138bb2b1b7"),
        ]);

        routing.update_network(update).await.unwrap();

        let update =
            create_network_helper(&[("192.168.0.4", "0xcfad3f81e283983b8e9705b2e31d0c138bb2b1b7")]);

        routing.update_network(update).await.unwrap();

        assert_eq!(
            get_node(&routing, "192.168.0.0", "192.168.0.4")
                .await
                .unwrap(),
            NodeId::from_str("0xcfad3f81e283983b8e9705b2e31d0c138bb2b1b7").unwrap()
        );

        assert_eq!(
            get_node(&routing, "192.168.0.0", "192.168.0.3")
                .await
                .unwrap(),
            NodeId::from_str("0xffad3f81e283983b8e9705b2e31d0c138bb2b1b7").unwrap()
        );

        assert_eq!(get_node(&routing, "192.168.0.0", "192.168.0.2").await, None);
        assert_eq!(get_node(&routing, "192.168.0.0", "192.168.0.5").await, None);
    }
}

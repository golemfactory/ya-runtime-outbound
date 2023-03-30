mod gateway;
mod iptables;
mod packet_conv;
mod routing;
mod stats;

use gateway::GatewayRuntime;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    ya_runtime_sdk::run::<GatewayRuntime>().await
}

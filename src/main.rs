use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "zorv", version, about = "Zorv tunnel client/server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the server (equivalent to zorvd)
    Server {
        #[arg(short, long, default_value = "zorvd.toml")]
        config: String,
    },
    /// Start the client
    Client {
        #[arg(short, long, default_value = "zorv.toml")]
        config: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Server { config } => {
            let cfg = zorv::common::config::load_server(&config)?;
            zorv::common::logging::init(&cfg.log.level, &cfg.log.output);
            tracing::info!("starting zorvd (server) on tunnel {}", cfg.tunnel_addr);
            zorv::server::Server::new(cfg, config.clone()).run().await?;
        }
        Command::Client { config } => {
            let cfg = zorv::common::config::load_client(&config)?;
            zorv::common::logging::init(&cfg.log.level, &cfg.log.output);
            tracing::info!("starting zorv (client) -> {}", cfg.server_addr);
            let client = zorv::client::Client::new(cfg);
            client.run().await?;
        }
    }
    Ok(())
}

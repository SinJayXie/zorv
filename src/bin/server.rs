use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "zorvd", version, about = "Zorv tunnel server daemon")]
struct Cli {
    /// Path to the config file
    #[arg(short, long, default_value = "zorvd.toml")]
    config: String,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a PBKDF2-HMAC-SHA256 password hash (for use in admin.password)
    HashPassword {
        /// Plain-text password
        password: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if let Some(Command::HashPassword { password }) = cli.command {
        let hash = zorv::server::admin::hash_password(&password);
        println!("{hash}");
        return Ok(());
    }
    let cfg = zorv::common::config::load_server(&cli.config)?;
    zorv::common::logging::init(&cfg.log.level, &cfg.log.output);
    tracing::info!("starting zorvd on tunnel {}", cfg.tunnel_addr);
    zorv::server::Server::new(cfg, cli.config.clone()).run().await
}

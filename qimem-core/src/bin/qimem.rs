use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "qimem")]
#[command(about = "QIMEM-Core local cryptographic engine CLI")]
struct Cli {
    #[arg(long)]
    infra_url: Option<String>,
    #[arg(long)]
    tenant_id: Option<String>,
    #[arg(long)]
    jwt: Option<String>,
    #[arg(long, default_value_t = false)]
    offline: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    PqKeygen,
    PqSession,
    WrapDek,
    UnwrapDek,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Encrypt => println!("encrypt command scaffolded"),
        Commands::Decrypt => println!("decrypt command scaffolded"),
        Commands::Sign => println!("sign command scaffolded"),
        Commands::Verify => println!("verify command scaffolded"),
        Commands::PqKeygen => println!("pq-keygen command scaffolded"),
        Commands::PqSession => println!("pq-session command scaffolded"),
        Commands::WrapDek => println!("wrap-dek command scaffolded"),
        Commands::UnwrapDek => println!("unwrap-dek command scaffolded"),
    }
}

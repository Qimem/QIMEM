use clap::{Parser, Subcommand};
use qimem::qauth::QAuthService;
use serde::Serialize;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    InitRealm {
        id: String,
        name: String,
    },
    CreateRole {
        realm_id: String,
        name: String,
        permissions: Vec<String>,
    },
    CreateClient {
        realm_id: String,
        redirect_uris: Vec<String>,
    },
    CreateUser {
        realm_id: String,
        username: String,
        password: String,
        roles: Vec<String>,
    },
    Login {
        client_id: String,
        client_secret: String,
        realm_id: String,
        username: String,
        password: String,
        #[arg(long)]
        totp_code: Option<String>,
    },
    RotateKeys,
}

fn print_json(value: serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string(&value).unwrap_or_else(|_| "{\"error\":\"serialization\"}".into())
    );
}

fn print_result<T: Serialize>(res: Result<T, qimem::QimemError>) {
    match res {
        Ok(value) => print_json(
            serde_json::to_value(value)
                .unwrap_or_else(|_| serde_json::json!({"error":"serialization"})),
        ),
        Err(err) => print_json(serde_json::json!({"error": err.to_string()})),
    }
}

fn main() {
    let cli = Cli::parse();
    let svc = QAuthService::new();

    match cli.command {
        Commands::InitRealm { id, name } => print_result(svc.create_realm(&id, &name)),
        Commands::CreateRole {
            realm_id,
            name,
            permissions,
        } => print_result(svc.create_role(&realm_id, &name, permissions)),
        Commands::CreateClient {
            realm_id,
            redirect_uris,
        } => print_result(svc.create_client(&realm_id, redirect_uris)),
        Commands::CreateUser {
            realm_id,
            username,
            password,
            roles,
        } => print_result(svc.create_user(&realm_id, &username, &password, roles)),
        Commands::Login {
            client_id,
            client_secret,
            realm_id,
            username,
            password,
            totp_code,
        } => print_result(svc.login(
            &client_id,
            &client_secret,
            &realm_id,
            &username,
            &password,
            totp_code.as_deref(),
        )),
        Commands::RotateKeys => print_result(svc.rotate_signing_key()),
    }
}

use anyhow::Result;
use clap::{Parser, Subcommand};
use cloudflare_disk::config::{doctor, initialize, Profile, Secrets};
use cloudflare_disk::gateway;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version,
    about = "Single-gateway R2 disk; Linux only. Secrets are never command-line values."
)]
struct Cli {
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Create a private profile without starting services or modifying host configuration.
    Init {
        #[arg(long)]
        config: PathBuf,
        /// Owned regular 0600 TOML file; omit for hidden terminal prompts.
        #[arg(long)]
        secrets_file: Option<PathBuf>,
    },
    /// Write an encrypted identity marker to an EMPTY dedicated remote prefix (explicit remote mutation).
    InitializeDestination {
        #[arg(long)]
        config: PathBuf,
    },
    /// Verify the existing encrypted identity marker while the gateway is stopped.
    VerifyDestination {
        #[arg(long)]
        config: PathBuf,
    },
    /// Check installed tools, storage, FUSE, selected interface and port availability.
    Doctor {
        #[arg(long)]
        config: PathBuf,
    },
    /// Serve one encrypted SMB3 share as administrator-created r2disk (TCP 445 privilege required).
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    /// Report authenticated local mount, backend, cache and upload health.
    Status {
        #[arg(long)]
        config: PathBuf,
    },
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Action::Init {
            config,
            secrets_file,
        } => {
            let profile = Profile::load(&config)?;
            let secrets = match secrets_file {
                Some(path) => Secrets::from_protected_file(&path)?,
                None => Secrets {
                    access_key_id: rpassword::prompt_password("R2 access key ID: ")?,
                    secret_access_key: rpassword::prompt_password("R2 secret access key: ")?,
                    smb_password: rpassword::prompt_password("SMB password (12+ bytes): ")?,
                    crypt_password: rpassword::prompt_password(
                        "Crypt password (16+ bytes; back up securely): ",
                    )?,
                    crypt_salt: rpassword::prompt_password(
                        "Crypt salt (16+ bytes; back up securely): ",
                    )?,
                },
            };
            initialize(&profile, &secrets)?;
            println!("Local encrypted profile initialized; back up crypt password, salt and profile together. No remote data changed. Run initialize-destination with the saved profile for a new empty prefix before serve.");
        }
        Action::InitializeDestination { config } => {
            let profile = Profile::load(&config)?;
            cloudflare_disk::config::validate_storage(
                &profile,
                &cloudflare_disk::config::LinuxStorage,
            )?;
            let secrets = Secrets::from_protected_file(&profile.state_dir.join("secrets.toml"))?;
            gateway::initialize_destination(&profile, &secrets)?;
            println!("Encrypted destination identity initialized and verified.");
        }
        Action::Doctor { config } => {
            cloudflare_disk::samba::check_identity()?;
            for message in doctor(&Profile::load(&config)?)? {
                println!("{message}");
            }
        }
        Action::VerifyDestination { config } => {
            let profile = Profile::load(&config)?;
            cloudflare_disk::config::validate_storage(
                &profile,
                &cloudflare_disk::config::LinuxStorage,
            )?;
            let secrets = Secrets::from_protected_file(&profile.state_dir.join("secrets.toml"))?;
            gateway::verify_initialized_destination(&profile, &secrets)?;
            println!("Existing encrypted destination identity verified; no remote data changed.");
        }
        Action::Serve { config } => {
            gateway::serve(Profile::load(&config)?)?;
        }
        Action::Status { config } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&gateway::status(&Profile::load(&config)?)?)?
            );
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

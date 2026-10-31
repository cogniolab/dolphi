use dolphi::{
    EncryptionKey, Owner,
    http::{HttpConfig, router},
};
use std::{io::Write, path::Path, time::Duration};
use zeroize::Zeroizing;

fn secret_file(path: &str, contents: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

fn load_key(path: &str) -> Result<EncryptionKey, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err("key must be a private regular file (0600)".into());
        }
    }
    let bytes = Zeroizing::new(std::fs::read(path)?);
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "key file must contain exactly 32 raw bytes")?;
    Ok(EncryptionKey::from_bytes(key))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        return Err("usage: dolphi-server init DB KEY_FILE OWNER_TOKEN_FILE | owner-token DB KEY_FILE NEW_TOKEN_FILE | serve DB KEY_FILE [PORT] | keygen NEW_KEY_FILE | migration-export[-stream] SOURCE_DB SOURCE_KEY SNAPSHOT BACKUP_KEY | migration-import SNAPSHOT BACKUP_KEY NEW_DB NEW_DB_KEY REPORT".into());
    }
    match args[1].as_str() {
        "keygen" if args.len() == 3 => {
            let mut key = Zeroizing::new([0u8; 32]);
            getrandom::fill(key.as_mut()).map_err(|_| "OS randomness unavailable")?;
            secret_file(&args[2], key.as_ref())?;
            println!("Key saved to a new private file.");
        }
        "migration-export" | "migration-export-stream" if args.len() == 6 => {
            let database_key = load_key(&args[3])?;
            let backup_key = load_key(&args[5])?;
            let report = if args[1] == "migration-export-stream" {
                Owner::migration_export_streaming(
                    Path::new(&args[2]),
                    &database_key,
                    Path::new(&args[4]),
                    &backup_key,
                )
                .await?
            } else {
                Owner::migration_export(
                    Path::new(&args[2]),
                    &database_key,
                    Path::new(&args[4]),
                    &backup_key,
                )
                .await?
            };
            println!("{}", serde_json::to_string(&report)?);
        }
        "migration-import" if args.len() == 7 => {
            if std::fs::symlink_metadata(&args[6]).is_ok() {
                return Err("report destination must be new".into());
            }
            let report_path = Path::new(&args[6]);
            let parent = report_path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let mut report_file = tempfile::NamedTempFile::new_in(parent)?;
            let (owner, report) = Owner::restore_verified(
                Path::new(&args[2]),
                &load_key(&args[3])?,
                Path::new(&args[4]),
                &load_key(&args[5])?,
            )
            .await?;
            drop(owner);
            let saved = (|| -> Result<(), Box<dyn std::error::Error>> {
                serde_json::to_writer_pretty(report_file.as_file_mut(), &report)?;
                report_file.write_all(b"\n")?;
                report_file.as_file().sync_all()?;
                report_file
                    .persist_noclobber(report_path)
                    .map_err(|e| e.error)?;
                #[cfg(unix)]
                std::fs::File::open(parent)?.sync_all()?;
                Ok(())
            })();
            if saved.is_err() {
                return Err("migration database was created and verified, but report publication failed; preserve the destination for inspection".into());
            }
            println!("{}", serde_json::to_string(&report)?);
        }
        "init" if args.len() == 5 => {
            if Path::new(&args[2]).exists()
                || Path::new(&args[3]).exists()
                || Path::new(&args[4]).exists()
            {
                return Err("initialization destinations must be new".into());
            }
            let mut bytes = Zeroizing::new([0; 32]);
            getrandom::fill(bytes.as_mut()).map_err(|_| "OS randomness unavailable")?;
            secret_file(&args[3], bytes.as_ref())?;
            let owner =
                Owner::open_encrypted(&args[2], &EncryptionKey::from_bytes(*bytes), None).await?;
            let token = owner
                .issue_owner_credential(Duration::from_secs(30 * 86400))
                .await?;
            secret_file(&args[4], token.expose_secret().as_bytes())?;
            println!(
                "Initialized encrypted Community database; key and owner token saved to private files."
            );
        }
        "owner-token" if args.len() == 5 => {
            if !Path::new(&args[2]).is_file() {
                return Err("database does not exist".into());
            }
            let owner = Owner::open_encrypted(&args[2], &load_key(&args[3])?, None).await?;
            let token = owner
                .issue_owner_credential(Duration::from_secs(30 * 86400))
                .await?;
            secret_file(&args[4], token.expose_secret().as_bytes())?;
            println!("New owner credential saved; previous credentials are unchanged.");
        }
        "serve" if args.len() == 4 || args.len() == 5 => {
            if !Path::new(&args[2]).is_file() {
                return Err("database does not exist; run init first".into());
            }
            let owner = Owner::open_encrypted(&args[2], &load_key(&args[3])?, None).await?;
            let port: u16 = args.get(4).map_or(Ok(8787), |s| s.parse())?;
            let listener =
                tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
            let address = listener.local_addr()?;
            let app = router(
                owner,
                HttpConfig {
                    authority: address.to_string(),
                    requests_per_minute: 1200,
                },
            );
            println!("Dolphi listening at http://{address} (loopback only)");
            dolphi::http::serve(listener, app).await?;
        }
        _ => return Err("invalid command or arguments".into()),
    }
    Ok(())
}

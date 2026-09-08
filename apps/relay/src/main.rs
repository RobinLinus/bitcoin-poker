//! Standalone process for the BP52 opaque relay.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;

use poker_relay::DeploymentConfig;
use poker_relay::RelayServer;

const USAGE: &str = "usage: poker-relay [listen-address] <deployment-config>";

type StartupArguments = (SocketAddr, PathBuf);

fn parse_arguments(
    arguments: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<Option<StartupArguments>, std::io::Error> {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    if matches!(arguments.as_slice(), [flag] if flag == "--help" || flag == "-h" || flag == "help")
    {
        return Ok(None);
    }
    if arguments
        .first()
        .is_some_and(|argument| argument.to_string_lossy().starts_with('-'))
    {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, USAGE));
    }
    let (listen, deployment_path) = match arguments.as_slice() {
        [deployment_path] => (
            "127.0.0.1:3000".parse().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "default listen address is invalid",
                )
            })?,
            PathBuf::from(deployment_path),
        ),
        [listen, deployment_path] => (
            listen
                .clone()
                .into_string()
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "listen address is not valid UTF-8",
                    )
                })?
                .parse::<SocketAddr>()
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "listen address is invalid",
                    )
                })?,
            PathBuf::from(deployment_path),
        ),
        _ => {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, USAGE));
        }
    };
    Ok(Some((listen, deployment_path)))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some((listen, deployment_path)) = parse_arguments(std::env::args_os().skip(1))?
    else {
        println!("{USAGE}");
        return Ok(());
    };
    let bytes = std::fs::read(deployment_path)?;
    let deployment: DeploymentConfig = serde_json::from_slice(&bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "deployment config is not valid canonical JSON",
        )
    })?;
    let relay = RelayServer::open_with_deployment(&deployment)?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    eprintln!("BP52 relay listening on {listen}");
    axum::serve(listener, relay.router()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{USAGE, parse_arguments};
    use std::{ffi::OsString, path::PathBuf};

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn help_never_resolves_a_database_path() -> Result<(), Box<dyn std::error::Error>> {
        for flag in ["help", "-h", "--help"] {
            assert!(parse_arguments(args(&[flag]))?.is_none());
        }
        Ok(())
    }

    #[test]
    fn explicit_deployment_is_required() -> Result<(), Box<dyn std::error::Error>> {
        match parse_arguments(args(&[])) {
            Err(error) => assert_eq!(error.to_string(), USAGE),
            Ok(_) => return Err("missing deployment unexpectedly parsed".into()),
        }
        match parse_arguments(args(&["--unknown", "deployment.json"])) {
            Err(error) => assert_eq!(error.to_string(), USAGE),
            Ok(_) => return Err("unknown option unexpectedly became a database path".into()),
        }
        Ok(())
    }

    #[test]
    fn parses_default_and_explicit_listen_addresses() -> Result<(), Box<dyn std::error::Error>> {
        let Some(default) = parse_arguments(args(&["deployment.json"]))? else {
            return Err("server arguments unexpectedly requested help".into());
        };
        assert_eq!(default.0.to_string(), "127.0.0.1:3000");
        assert_eq!(default.1, PathBuf::from("deployment.json"));

        let Some(explicit) =
            parse_arguments(args(&["127.0.0.1:4000", "deployment.json"]))?
        else {
            return Err("server arguments unexpectedly requested help".into());
        };
        assert_eq!(explicit.0.to_string(), "127.0.0.1:4000");
        Ok(())
    }
}

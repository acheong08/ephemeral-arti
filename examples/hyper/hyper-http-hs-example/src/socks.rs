use arti_client::DataStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error;
use log::info;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::{io, net};

const AUTH_VERSION: u8 = 0x1;
const IPV4_TYPE: u8 = 0x1;
const IPV6_TYPE: u8 = 0x4;
const DOMAIN_TYPE: u8 = 0x3;
const CONNECT_COMMAND: u8 = 0x1;
const AUTH_METHOD: u8 = 0x2;
const NO_AUTH_METHOD: u8 = 0x0;
const NO_METHOD: u8 = 0xff;
const SOCKS_VERSION: u8 = 0x5;
const SUCCESS_REPLY: u8 = 0x0;

#[derive(Clone)]
pub struct AuthConfig {
    pub users: Vec<(String, String)>,
}

pub async fn handle(
    stream: &mut DataStream,
    auth_config: Option<&AuthConfig>,
) -> error::Result<()> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;

    let ver = buf[0];
    if ver != SOCKS_VERSION {
        return Err(error::Error::InvalidVersion);
    }

    let len = buf[1] as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;

    let method = *buf
        .iter()
        .find(|&&m| {
            m == NO_AUTH_METHOD && auth_config.is_none()
                || m == AUTH_METHOD
                    && (auth_config.is_some() || auth_config.as_ref().unwrap().users.is_empty())
        })
        .unwrap_or(&NO_METHOD);

    let buf = [SOCKS_VERSION, method];
    stream.write_all(&buf).await?;
    stream.flush().await?;

    match method {
        AUTH_METHOD => {
            let res = auth(
                stream,
                Arc::new(match auth_config {
                    Some(c) => c.clone(),
                    None => return Err(error::Error::NoAcceptableMethod),
                }),
            )
            .await;
            let reply = res.is_err() as u8;
            let buf = [AUTH_VERSION, reply];
            stream.write_all(&buf).await?;
            stream.flush().await?;
            res?;
        }
        NO_METHOD => {
            return Err(error::Error::NoAcceptableMethod);
        }
        _ => {}
    }

    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await?;

    let ver = buf[0];
    if ver != SOCKS_VERSION {
        println!("Invalid version");
        return Err(error::Error::InvalidVersion);
    }

    let (mut peer, local_addr) = match socks(stream, buf).await {
        Ok(t) => t,
        Err(e) => {
            let reply = match &e {
                error::Error::AddrUnsupported => 0x8,
                error::Error::CommandUnsupported => 0x7,
                error::Error::Io(e) => {
                    // TODO: https://github.com/rust-lang/rust/issues/86442
                    match e.kind() {
                        ErrorKind::ConnectionRefused => 0x5,
                        _ => 0x1,
                    }
                }
                _ => 0x1,
            };

            let buf = [SOCKS_VERSION, reply, 0, IPV4_TYPE, 0, 0, 0, 0, 0, 0];
            stream.write_all(&buf).await?;
            stream.flush().await?;

            return Err(e);
        }
    };

    let mut buf = Vec::with_capacity(22);
    buf.extend([SOCKS_VERSION, SUCCESS_REPLY, 0]);

    match local_addr.ip() {
        IpAddr::V4(i) => {
            buf.push(IPV4_TYPE);
            buf.extend(i.octets());
        }
        IpAddr::V6(i) => {
            buf.push(IPV6_TYPE);
            buf.extend(i.octets());
        }
    }

    let port = local_addr.port().to_le_bytes();
    buf.extend(port);
    stream.write_all(&buf).await?;
    stream.flush().await?;

    let (sent, received) = io::copy_bidirectional(stream, &mut peer).await?;
    stream.flush().await?;
    info!("sent {sent} bytes and received {received} bytes");

    Ok(())
}

async fn socks(stream: &mut DataStream, buf: [u8; 4]) -> error::Result<(TcpStream, SocketAddr)> {
    let cmd = buf[1];
    if cmd != CONNECT_COMMAND {
        return Err(error::Error::CommandUnsupported);
    }

    let addr_type = buf[3];
    let dest = match addr_type {
        IPV4_TYPE => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;

            let port = stream.read_u16().await?;
            vec![SocketAddr::new(IpAddr::from(octets), port)]
        }
        DOMAIN_TYPE => {
            let len = stream.read_u8().await? as usize;
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;

            let domain = String::from_utf8(buf)?;
            let port = stream.read_u16().await?;

            net::lookup_host(format!("{domain}:{port}"))
                .await?
                .collect()
        }
        IPV6_TYPE => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;

            let port = stream.read_u16().await?;
            vec![SocketAddr::new(IpAddr::from(octets), port)]
        }
        _ => return Err(error::Error::AddrUnsupported),
    };
    let stream = TcpStream::connect(&dest[..]).await?;
    let addr = stream.local_addr()?;
    Ok((stream, addr))
}

async fn auth(stream: &mut DataStream, config: Arc<AuthConfig>) -> error::Result<()> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;

    let ver = buf[0];
    if ver != AUTH_VERSION {
        return Err(error::Error::InvalidVersion);
    }

    let len = buf[1] as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    let username = String::from_utf8(buf)?;

    let len = stream.read_u8().await? as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    let password = String::from_utf8(buf)?;

    let pass = config
        .users
        .iter()
        .find(|(u, _)| u == &username)
        .ok_or(error::Error::UsernameNotFound)?
        .1
        .clone();
    // This is less secure but hashing takes too long
    if pass != password {
        return Err(error::Error::InvalidPassword);
    }
    eprintln!("Authenticated user: {username}");
    Ok(())
}

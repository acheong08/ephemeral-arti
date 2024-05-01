mod error;
mod socks;
use std::sync::Arc;

use anyhow::Result;
use arti_client::{DataStream, TorClient, TorClientConfig};
use futures::{AsyncWriteExt, StreamExt};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use safelog::sensitive;
use tokio_util::sync::CancellationToken;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::StreamRequest;
use tor_proto::stream::IncomingStreamRequest;

use tokio::io::AsyncReadExt;

struct WebHandler {
    shutdown: CancellationToken,
}

impl WebHandler {
    async fn serve(&self, request: Request<Incoming>) -> Result<Response<String>> {
        let path = request.uri().path();

        // TODO: Unauthenticated management. This route is accessible by anyone, and exists solely
        //  to demonstrate how to safely shutdown further incoming requests. You should probably
        //  move this elsewhere to ensure proper checks are in place!
        if path == "/shutdown" {
            self.shutdown.cancel();
        }

        Ok(Response::builder().status(StatusCode::OK).body(format!(
            "{} {}",
            request.method(),
            path
        ))?)
    }
}

#[tokio::main]
async fn main() {
    // Make sure you read doc/OnionService.md to extract your Onion service hostname

    // Arti uses the `tracing` crate for logging. Install a handler for this, to print Arti's logs.
    // (You'll need to set RUST_LOG=info as an environment variable to actually see much; also try
    // =debug for more detailed logging.)
    tracing_subscriber::fmt::init();

    // Initialize web server data, if you need to
    let handler = Arc::new(WebHandler {
        shutdown: CancellationToken::new(),
    });

    // The client config includes things like where to store persistent Tor network state.
    // The defaults provided are the same as the Arti standalone application, and save data
    // to a conventional place depending on operating system (for example, ~/.local/share/arti
    // on Linux platforms)
    let config = TorClientConfig::builder()
        .persistent_state(false)
        .build()
        .unwrap();

    // We now let the Arti client start and bootstrap a connection to the network.
    // (This takes a while to gather the necessary consensus state, etc.)
    let client = TorClient::create_bootstrapped(config).await.unwrap();

    let svc_cfg = OnionServiceConfigBuilder::default()
        .nickname("allium-ampeloprasum".parse().unwrap())
        .build()
        .unwrap();
    let (service, request_stream) = client.launch_onion_service(svc_cfg).unwrap();
    // Show the onion address of the service
    println!(
        "onion service address: {}",
        service.onion_name().unwrap().to_string()
    );

    eprintln!("ready to serve connections");

    let stream_requests = tor_hsservice::handle_rend_requests(request_stream)
        .take_until(handler.shutdown.cancelled());
    tokio::pin!(stream_requests);

    while let Some(stream_request) = stream_requests.next().await {
        // incoming connection
        let handler = handler.clone();

        tokio::spawn(async move {
            let request = stream_request.request().clone();
            let result = handle_stream_request(stream_request, handler).await;

            match result {
                Ok(()) => {}
                Err(err) => {
                    eprintln!("error serving connection {:?}: {}", sensitive(request), err);
                }
            }
        });
    }

    drop(service);
    eprintln!("onion service exited cleanly");
}

async fn handle_stream_request(
    stream_request: StreamRequest,
    handler: Arc<WebHandler>,
) -> Result<()> {
    match stream_request.request() {
        IncomingStreamRequest::Begin(begin) => match begin.port() {
            80 => {
                let onion_service_stream = stream_request.accept(Connected::new_empty()).await?;
                let io = TokioIo::new(onion_service_stream);

                http1::Builder::new()
                    .serve_connection(io, service_fn(|request| handler.serve(request)))
                    .await?;
            }
            1081 => {
                eprintln!("custom SOCKS5 connection");
                let mut onion_service_stream =
                    stream_request.accept(Connected::new_empty()).await?;
                eprintln!("onion service stream accepted");
                socks::handle(&mut onion_service_stream).await?;
                eprintln!("custom SOCKS5 connection finished");
            }
            1082 => {
                eprintln!("ping connection");
                let mut onion_service_stream =
                    stream_request.accept(Connected::new_empty()).await?;
                eprintln!("onion service stream accepted");
                handle_ping(&mut onion_service_stream).await?;
                eprintln!("ping connection finished");
            }
            _ => {
                stream_request.shutdown_circuit()?;
            }
        },
        _ => {
            stream_request.shutdown_circuit()?;
        }
    }

    Ok(())
}

async fn handle_ping(data_stream: &mut DataStream) -> error::Result<()> {
    // String buffer to keep data until newline
    let mut str_buf = String::new();
    // Infinite loop until the connection is closed
    loop {
        // Read a single byte from the client
        let mut buf = [0u8; 1];
        data_stream.read_exact(&mut buf).await?;
        // Store the byte in the string buffer
        str_buf.push(buf[0] as char);
        // If the byte is a newline, print the string buffer and clear it
        if buf[0] == b'\n' {
            println!("Received: {}", str_buf);
            if str_buf == "exit\n" {
                return Ok(());
            }
            data_stream.write_all(str_buf.as_bytes()).await?;
            data_stream.flush().await?;
            str_buf.clear();
        }
    }
}

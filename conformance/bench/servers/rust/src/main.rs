// Rust bench server (salvo): implements the vortex stress/bench endpoint contract
// over HTTP/1.1, HTTP/2 (rustls ALPN), and HTTP/3 (quinn). Semantics match
// stress_server.nim byte-for-byte: deterministic download (byte i = i mod 256),
// SHA-1-validated upload, id-ordered SSE (sseTotal=100/sseBatch=20, Last-Event-ID).
use salvo::conn::rustls::{Keycert, RustlsConfig};
use salvo::prelude::*;
use salvo::sse::{self, SseEvent};
use salvo::websocket::WebSocketUpgrade;
use futures_util::{stream, SinkExt, StreamExt};
use sha1::{Digest, Sha1};
use std::env;

const SSE_TOTAL: usize = 100;
const SSE_BATCH: usize = 20;
const DL_CHUNK: usize = 64 * 1024;

fn env_s(k: &str, d: &str) -> String { env::var(k).unwrap_or_else(|_| d.to_string()) }
fn stream_bytes() -> usize { env_s("STREAM_BYTES", "1073741824").parse().unwrap_or(1 << 30) }

// deterministic payload: byte i = i mod 256
fn gen_chunk(start: usize, n: usize) -> Vec<u8> {
    (0..n).map(|i| ((start + i) & 0xff) as u8).collect()
}

#[handler]
async fn plaintext(res: &mut Response) { res.render(Text::Plain("Hello, World!")); }

#[handler]
async fn json(res: &mut Response) {
    res.render(Text::Json(r#"{"message":"Hello, World!"}"#));
}

#[handler]
async fn echo(req: &mut Request, res: &mut Response) {
    let body = req.payload_with_max_size(usize::MAX).await.cloned().unwrap_or_default();
    res.write_body(body).ok();
}

#[handler]
async fn download(res: &mut Response) {
    let total = stream_bytes();
    let s = stream::unfold(0usize, move |off| async move {
        if off >= total { return None; }
        let n = DL_CHUNK.min(total - off);
        Some((Ok::<_, std::io::Error>(bytes::Bytes::from(gen_chunk(off, n))), off + n))
    });
    res.stream(s);
}

#[handler]
async fn upload(req: &mut Request, res: &mut Response) {
    // buffer the body (bounded by STREAM_BYTES + slack); Rust upload buffers, so
    // its upload RSS is not comparable to the streaming servers -- noted in README.
    let body = req.payload_with_max_size(stream_bytes() + 1024 * 1024).await.cloned().unwrap_or_default();
    let mut h = Sha1::new();
    h.update(&body);
    let got = hex::encode(h.finalize());
    let want = req.header::<String>("x-sha1").unwrap_or_default();
    if got == want {
        res.render("ok");
    } else {
        res.status_code(StatusCode::BAD_REQUEST);
        res.render("mismatch");
    }
}

#[handler]
async fn sse_handler(req: &mut Request, res: &mut Response) {
    let mut i: usize = 0;
    if let Some(last) = req.header::<String>("last-event-id") {
        if let Ok(v) = last.parse::<usize>() { i = v + 1; }
    }
    let mut events = Vec::new();
    let mut sent = 0usize;
    while i < SSE_TOTAL && sent < SSE_BATCH {
        events.push(Ok::<_, std::convert::Infallible>(
            SseEvent::default().id(i.to_string()).text(format!("event {}", i)),
        ));
        i += 1; sent += 1;
    }
    sse::stream(res, stream::iter(events));
}

#[handler]
async fn ws_handler(req: &mut Request, res: &mut Response) -> Result<(), StatusError> {
    WebSocketUpgrade::new()
        .upgrade(req, res, |mut ws| async move {
            while let Some(Ok(msg)) = ws.recv().await {
                if ws.send(msg).await.is_err() { break; }
            }
        })
        .await
}

fn router() -> Router {
    Router::new()
        .push(Router::with_path("plaintext").get(plaintext))
        .push(Router::with_path("json").get(json))
        .push(Router::with_path("echo").goal(echo))
        .push(Router::with_path("download").get(download))
        .push(Router::with_path("upload").post(upload))
        .push(Router::with_path("sse").get(sse_handler))
        .push(Router::with_path("ws").goal(ws_handler))
}

#[tokio::main]
async fn main() {
    let port = env_s("STRESS_PORT", "8080");
    let tls = env_s("STRESS_TLS", "0") == "1";
    let h3 = env_s("STRESS_HTTP3", "0") == "1";
    let addr = format!("0.0.0.0:{}", port);
    let router = router();

    if tls {
        let config = RustlsConfig::new(
            Keycert::new()
                .cert_from_path("/app/cert.pem").unwrap()
                .key_from_path("/app/key.pem").unwrap(),
        );
        if h3 {
            let listener = QuinnListener::new(config.clone().build_quinn_config().unwrap(), addr.clone())
                .join(TcpListener::new(addr.clone()).rustls(config));
            let acceptor = listener.bind().await;
            println!("listening on {}", port);
            Server::new(acceptor).serve(router).await;
        } else {
            let acceptor = TcpListener::new(addr).rustls(config).bind().await;
            println!("listening on {}", port);
            Server::new(acceptor).serve(router).await;
        }
    } else {
        let acceptor = TcpListener::new(addr).bind().await;
        println!("listening on {}", port);
        Server::new(acceptor).serve(router).await;
    }
}

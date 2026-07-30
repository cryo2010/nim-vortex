// Rust interop client for the vortex cross-client test. Uses reqwest (tokio),
// which negotiates HTTP/2 over TLS via ALPN (asserted through resp.version()),
// trusting the shared CA and exercising every method against /echo. The "gzip"
// feature transparently requests and decompresses gzip, so a correct
// round-trip proves the compression path.
//
// Env: INTEROP_URL, INTEROP_RUNTIME (s), INTEROP_CLIENTS, INTEROP_MTLS (0/1).
// Certs: /certs/ca.pem, and for mTLS /certs/client.p12 (password "changeit").

use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::{Certificate, Client, Identity, Method, Version};

const NAME: &str = "rust";
const METHODS: [&str; 7] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

fn fail(reason: String) -> ! {
    eprintln!("INTEROP FAIL {}: {}", NAME, reason);
    std::process::exit(1);
}

fn build_client(mtls: bool) -> Result<Client, Box<dyn std::error::Error>> {
    let ca = std::fs::read("/certs/ca.pem")?;
    let mut builder = Client::builder()
        .add_root_certificate(Certificate::from_pem(&ca)?)
        .gzip(true)
        .timeout(Duration::from_secs(30));
    if mtls {
        // reqwest's native-tls backend takes the client identity as PKCS#12 DER
        // (the same client.p12 run.sh mints for the Java client).
        let p12 = std::fs::read("/certs/client.p12")?;
        builder = builder.identity(Identity::from_pkcs12_der(&p12, "changeit")?);
    }
    Ok(builder.build()?)
}

async fn one(client: &Client, base: &str, method: &str, mtls: bool)
    -> Result<(), String>
{
    let m = Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?;
    let mut req = client
        .request(m, format!("{}/echo", base))
        .header("x-api-key", "interop");
    if matches!(method, "POST" | "PUT" | "PATCH") {
        req = req.header("content-type", "text/plain")
            .body(format!("hello from {}", NAME));
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    if resp.status().as_u16() != 200 {
        return Err(format!("{} status {}", method, resp.status().as_u16()));
    }
    if resp.version() != Version::HTTP_2 {
        return Err(format!("{} not HTTP/2: {:?}", method, resp.version()));
    }
    if method == "HEAD" {
        match resp.headers().get("x-echo-method") {
            Some(v) if v == "HEAD" => return Ok(()),
            _ => return Err("HEAD missing x-echo-method".into()),
        }
    }
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if !body.contains(&format!("method={}", method)) {
        return Err(format!("{} body did not echo method", method));
    }
    if mtls {
        let r = client
            .get(format!("{}/whoami", base))
            .header("x-api-key", "interop")
            .send().await.map_err(|e| e.to_string())?;
        let s = r.text().await.map_err(|e| e.to_string())?;
        if s.trim().is_empty() || s.trim() == "-" {
            return Err("mTLS /whoami did not report a client subject".into());
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    let base = env::var("INTEROP_URL").unwrap_or_else(|_| "https://server:8443".into());
    let runtime: u64 = env::var("INTEROP_RUNTIME").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(5);
    let clients: u64 = env::var("INTEROP_CLIENTS").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(1).max(1);
    let mtls = env::var("INTEROP_MTLS").ok().as_deref() == Some("1");

    let client = build_client(mtls).unwrap_or_else(|e| fail(e.to_string()));
    let deadline = Instant::now() + Duration::from_secs(runtime);
    let count = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    for _ in 0..clients {
        let client = client.clone();
        let base = base.clone();
        let count = count.clone();
        handles.push(tokio::spawn(async move {
            while Instant::now() < deadline {
                for m in METHODS {
                    // On mTLS runs, exercise /whoami once per method cycle.
                    let check_mtls = mtls && m == "GET";
                    one(&client, &base, m, check_mtls).await?;
                    count.fetch_add(1, Ordering::Relaxed);
                }
            }
            Ok::<(), String>(())
        }));
    }
    for h in handles {
        match h.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => fail(e),
            Err(e) => fail(e.to_string()),
        }
    }
    println!(
        "INTEROP OK {}: requests={} (clients={}, runtime={}s, mtls={})",
        NAME, count.load(Ordering::Relaxed), clients, runtime,
        if mtls { 1 } else { 0 }
    );
}

// Java interop client for the vortex cross-client test. Uses java.net.http's
// HttpClient pinned to HTTP_2 (asserted through response.version()), trusting
// the shared CA and exercising every method against /echo. java.net.http does
// not auto-decompress, so it sets Accept-Encoding itself and decodes the
// response (gzip via java.util.zip, brotli via org.brotli.dec on the
// classpath), checking Content-Encoding, to prove the compression path.
//
// Run as a single-file source program: `java -cp <brotli-dec.jar> Interop.java`.
// Env: INTEROP_URL, INTEROP_RUNTIME (s), INTEROP_CLIENTS, INTEROP_MTLS (0/1),
//      INTEROP_ENCODING (gzip|br).
// Certs: /certs/ca.pem, and for mTLS /certs/client.p12 (password "changeit").

import javax.net.ssl.*;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.*;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.GZIPInputStream;

public class Interop {
    static final String NAME = "java";
    static final String ENC =
        System.getenv().getOrDefault("INTEROP_ENCODING", "gzip");
    static final List<String> METHODS =
        List.of("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS");

    static void fail(String reason) {
        System.err.println("INTEROP FAIL " + NAME + ": " + reason);
        System.exit(1);
    }

    static SSLContext sslContext(boolean mtls) throws Exception {
        // Trust: build a keystore holding just the shared CA certificate.
        var cf = CertificateFactory.getInstance("X.509");
        X509Certificate ca;
        try (var in = new java.io.FileInputStream("/certs/ca.pem")) {
            ca = (X509Certificate) cf.generateCertificate(in);
        }
        var trust = KeyStore.getInstance(KeyStore.getDefaultType());
        trust.load(null, null);
        trust.setCertificateEntry("ca", ca);
        var tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trust);

        KeyManager[] kms = null;
        if (mtls) {
            var pass = "changeit".toCharArray();
            var ks = KeyStore.getInstance("PKCS12");
            try (var in = new java.io.FileInputStream("/certs/client.p12")) {
                ks.load(in, pass);
            }
            var kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, pass);
            kms = kmf.getKeyManagers();
        }
        var ctx = SSLContext.getInstance("TLS");
        ctx.init(kms, tmf.getTrustManagers(), null);
        return ctx;
    }

    static byte[] decodeBody(HttpResponse<byte[]> resp) throws Exception {
        var enc = resp.headers().firstValue("content-encoding").orElse("");
        var body = resp.body();
        if (body.length == 0) return body;
        if (enc.equalsIgnoreCase("gzip")) {
            try (var in = new GZIPInputStream(new ByteArrayInputStream(body))) {
                return in.readAllBytes();
            }
        }
        if (enc.equalsIgnoreCase("br")) {
            try (var in = new org.brotli.dec.BrotliInputStream(
                    new ByteArrayInputStream(body))) {
                return in.readAllBytes();
            }
        }
        return body;
    }

    static void one(HttpClient client, String base, String method, boolean mtls)
            throws Exception {
        HttpRequest.BodyPublisher pub =
            (method.equals("POST") || method.equals("PUT") || method.equals("PATCH"))
                ? HttpRequest.BodyPublishers.ofString("hello from " + NAME)
                : HttpRequest.BodyPublishers.noBody();
        var req = HttpRequest.newBuilder(URI.create(base + "/echo"))
            .version(HttpClient.Version.HTTP_2)
            .header("x-api-key", "interop")
            .header("accept-encoding", ENC)
            .header("content-type", "text/plain")
            .method(method, pub)
            .build();
        var resp = client.send(req, HttpResponse.BodyHandlers.ofByteArray());
        if (resp.statusCode() != 200)
            throw new RuntimeException(method + " status " + resp.statusCode());
        if (resp.version() != HttpClient.Version.HTTP_2)
            throw new RuntimeException(method + " not HTTP/2: " + resp.version());
        if (!resp.headers().firstValue("content-encoding").orElse("").equalsIgnoreCase(ENC))
            throw new RuntimeException(method + " not " + ENC + "-encoded: "
                + resp.headers().firstValue("content-encoding").orElse(""));
        if (method.equals("HEAD")) {
            if (!resp.headers().firstValue("x-echo-method").orElse("").equals("HEAD"))
                throw new RuntimeException("HEAD missing x-echo-method");
            return;
        }
        var body = new String(decodeBody(resp));
        if (!body.contains("method=" + method))
            throw new RuntimeException(method + " body did not echo method");

        if (mtls) {
            var wr = HttpRequest.newBuilder(URI.create(base + "/whoami"))
                .version(HttpClient.Version.HTTP_2)
                .header("x-api-key", "interop")
                .header("accept-encoding", ENC)
                .GET().build();
            var wres = client.send(wr, HttpResponse.BodyHandlers.ofByteArray());
            var subject = new String(decodeBody(wres)).trim();
            if (subject.isEmpty() || subject.equals("-"))
                throw new RuntimeException("mTLS /whoami did not report a client subject");
        }
    }

    public static void main(String[] args) throws Exception {
        String base = System.getenv().getOrDefault("INTEROP_URL", "https://server:8443");
        int runtime = Integer.parseInt(System.getenv().getOrDefault("INTEROP_RUNTIME", "5"));
        int clients = Math.max(1,
            Integer.parseInt(System.getenv().getOrDefault("INTEROP_CLIENTS", "1")));
        boolean mtls = "1".equals(System.getenv("INTEROP_MTLS"));

        var client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_2)
            .sslContext(sslContext(mtls))
            .connectTimeout(Duration.ofSeconds(30))
            .build();

        long deadline = System.nanoTime() + runtime * 1_000_000_000L;
        var count = new AtomicLong();
        var pool = Executors.newFixedThreadPool(clients);
        var tasks = new java.util.ArrayList<Callable<Void>>();
        for (int i = 0; i < clients; i++) {
            tasks.add(() -> {
                while (System.nanoTime() < deadline) {
                    for (String m : METHODS) {
                        // Exercise /whoami once per cycle on mTLS runs.
                        one(client, base, m, mtls && m.equals("GET"));
                        count.incrementAndGet();
                    }
                }
                return null;
            });
        }
        try {
            for (var f : pool.invokeAll(tasks)) f.get();
        } catch (ExecutionException e) {
            fail(e.getCause() == null ? e.getMessage() : e.getCause().getMessage());
        } finally {
            pool.shutdownNow();
        }
        System.out.printf(
            "INTEROP OK %s: requests=%d (clients=%d, runtime=%ds, mtls=%d, enc=%s)%n",
            NAME, count.get(), clients, runtime, mtls ? 1 : 0, ENC);
    }
}

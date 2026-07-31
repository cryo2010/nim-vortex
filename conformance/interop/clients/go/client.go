// Go interop client for the vortex cross-client test. Uses the standard
// net/http client, which negotiates HTTP/2 over TLS via ALPN (asserted through
// resp.Proto), trusting the shared CA and exercising every method against
// /echo. It sets Accept-Encoding itself (so Go does not auto-decompress) and
// decodes the response (gzip via stdlib, brotli via andybalholm/brotli),
// checking Content-Encoding, to prove the compression path.
//
// Env: INTEROP_URL, INTEROP_RUNTIME (s), INTEROP_CLIENTS, INTEROP_MTLS (0/1),
//      INTEROP_ENCODING (gzip|br).
// Certs: /certs/ca.pem, and for mTLS /certs/client.pem + /certs/client.key.
package main

import (
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andybalholm/brotli"
)

const name = "go"

var methods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

var enc = env("INTEROP_ENCODING", "gzip")

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func atoi(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

func fail(reason string) {
	fmt.Fprintf(os.Stderr, "INTEROP FAIL %s: %s\n", name, reason)
	os.Exit(1)
}

func newClient(mtls bool) (*http.Client, error) {
	caPem, err := os.ReadFile("/certs/ca.pem")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPem) {
		return nil, fmt.Errorf("could not parse ca.pem")
	}
	tlsCfg := &tls.Config{RootCAs: pool}
	if mtls {
		cert, err := tls.LoadX509KeyPair("/certs/client.pem", "/certs/client.key")
		if err != nil {
			return nil, err
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	// ForceAttemptHTTP2 makes the default transport negotiate h2 over TLS.
	tr := &http.Transport{
		TLSClientConfig:    tlsCfg,
		ForceAttemptHTTP2:  true,
		DisableCompression: true, // we manage Accept-Encoding + decoding ourselves
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, nil
}

func do(client *http.Client, method, url, body string) error {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("x-api-key", "interop")
	req.Header.Set("accept-encoding", enc)
	if body != "" {
		req.Header.Set("content-type", "text/plain")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s status %d", method, resp.StatusCode)
	}
	if resp.ProtoMajor != 2 {
		return fmt.Errorf("%s not HTTP/2: %s", method, resp.Proto)
	}
	echo := !strings.HasSuffix(url, "/whoami")
	if echo && resp.Header.Get("content-encoding") != enc {
		return fmt.Errorf("%s not %s-encoded: %q", method, enc,
			resp.Header.Get("content-encoding"))
	}
	if method == "HEAD" {
		if resp.Header.Get("x-echo-method") != "HEAD" {
			return fmt.Errorf("HEAD missing x-echo-method")
		}
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	var reader io.Reader = resp.Body
	switch resp.Header.Get("content-encoding") {
	case "gzip":
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return fmt.Errorf("%s gunzip: %w", method, err)
		}
		defer gz.Close()
		reader = gz
	case "br":
		reader = brotli.NewReader(resp.Body)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	if strings.HasSuffix(url, "/whoami") {
		s := strings.TrimSpace(string(data))
		if s == "" || s == "-" {
			return fmt.Errorf("mTLS /whoami did not report a client subject")
		}
		return nil
	}
	if !strings.Contains(string(data), "method="+method) {
		return fmt.Errorf("%s body did not echo method", method)
	}
	return nil
}

func main() {
	base := env("INTEROP_URL", "https://server:8443")
	runtime := atoi(os.Getenv("INTEROP_RUNTIME"), 5)
	clients := atoi(os.Getenv("INTEROP_CLIENTS"), 1)
	if clients < 1 {
		clients = 1
	}
	mtls := os.Getenv("INTEROP_MTLS") == "1"

	client, err := newClient(mtls)
	if err != nil {
		fail(err.Error())
	}
	deadline := time.Now().Add(time.Duration(runtime) * time.Second)

	var count int64
	var failure atomic.Value
	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				for _, m := range methods {
					body := ""
					if m == "POST" || m == "PUT" || m == "PATCH" {
						body = "hello from " + name
					}
					if err := do(client, m, base+"/echo", body); err != nil {
						failure.Store(err.Error())
						return
					}
					atomic.AddInt64(&count, 1)
				}
				if mtls {
					if err := do(client, "GET", base+"/whoami", ""); err != nil {
						failure.Store(err.Error())
						return
					}
					atomic.AddInt64(&count, 1)
				}
			}
		}()
	}
	wg.Wait()
	if v := failure.Load(); v != nil {
		fail(v.(string))
	}
	fmt.Printf("INTEROP OK %s: requests=%d (clients=%d, runtime=%ds, mtls=%d, enc=%s)\n",
		name, count, clients, runtime, map[bool]int{true: 1, false: 0}[mtls], enc)
}

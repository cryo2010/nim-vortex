// Go bench server: implements the vortex stress/bench endpoint contract
// (/plaintext, /json, /echo, /sse, /upload, /download, /ws) over HTTP/1.1,
// HTTP/2 (TLS ALPN), and HTTP/3 (quic-go). Semantics match stress_server.nim
// byte-for-byte: deterministic download (byte i = i mod 256), SHA-1-validated
// upload, id-ordered SSE with sseTotal=100/sseBatch=20 and Last-Event-ID resume.
package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"

	"github.com/coder/websocket"
	"github.com/quic-go/quic-go/http3"
)

const (
	sseTotal = 100
	sseBatch = 20
	dlChunk  = 64 * 1024
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// deterministic payload: byte i = i mod 256
func genChunk(start, n int) []byte {
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = byte((start + i) & 0xff)
	}
	return b
}

func streamBytes() int {
	n, _ := strconv.Atoi(env("STREAM_BYTES", "1073741824"))
	return n
}

func handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/plaintext", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message":"Hello, World!"}`))
	})
	echo := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	}
	mux.HandleFunc("/echo", echo)
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		total := streamBytes()
		off := 0
		for off < total {
			n := dlChunk
			if total-off < n {
				n = total - off
			}
			if _, err := w.Write(genChunk(off, n)); err != nil {
				return
			}
			off += n
		}
	})
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		h := sha1.New()
		io.Copy(h, r.Body)
		got := hex.EncodeToString(h.Sum(nil))
		if got == r.Header.Get("x-sha1") {
			w.Write([]byte("ok"))
		} else {
			http.Error(w, "mismatch", http.StatusBadRequest)
		}
	})
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		i := 0
		if last := r.Header.Get("Last-Event-ID"); last != "" {
			if v, err := strconv.Atoi(last); err == nil {
				i = v + 1
			}
		}
		for sent := 0; i < sseTotal && sent < sseBatch; i, sent = i+1, sent+1 {
			fmt.Fprintf(w, "id: %d\ndata: event %d\n\n", i, i)
			if fl != nil {
				fl.Flush()
			}
		}
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer c.CloseNow()
		for {
			typ, data, err := c.Read(r.Context())
			if err != nil {
				return
			}
			if err := c.Write(r.Context(), typ, data); err != nil {
				return
			}
		}
	})
	return mux
}

func main() {
	port := env("STRESS_PORT", "8080")
	tls := env("STRESS_TLS", "0") == "1"
	h3 := env("STRESS_HTTP3", "0") == "1"
	cert, key := env("STRESS_CERT", "/app/cert.pem"), env("STRESS_KEY", "/app/key.pem")
	h := handler()
	addr := ":" + port

	if h3 {
		go func() {
			s := &http3.Server{Addr: addr, Handler: h}
			s.ListenAndServeTLS(cert, key) // UDP :port
		}()
	}
	fmt.Println("listening on", port)
	if tls {
		// net/http negotiates HTTP/2 via ALPN over TLS automatically.
		if err := http.ListenAndServeTLS(addr, cert, key, h); err != nil {
			panic(err)
		}
	} else {
		if err := http.ListenAndServe(addr, h); err != nil {
			panic(err)
		}
	}
}

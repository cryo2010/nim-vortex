// Node.js interop client for the vortex cross-client test. Uses the built-in
// http2 module (so every request is genuinely HTTP/2) over TLS, trusting the
// shared CA, exercising every method against /echo, and decoding the compressed
// responses itself (gzip or brotli) to prove the compression path end-to-end.
//
// Env: INTEROP_URL, INTEROP_RUNTIME (s), INTEROP_CLIENTS, INTEROP_MTLS (0/1),
//      INTEROP_ENCODING (gzip|br).
// Certs: /certs/ca.pem, and for mTLS /certs/client.pem + /certs/client.key.

'use strict';
const http2 = require('http2');
const zlib = require('zlib');
const fs = require('fs');

const URL = process.env.INTEROP_URL || 'https://server:8443';
const RUNTIME = parseInt(process.env.INTEROP_RUNTIME || '5', 10);
const CLIENTS = Math.max(1, parseInt(process.env.INTEROP_CLIENTS || '1', 10));
const MTLS = process.env.INTEROP_MTLS === '1';
const ENC = process.env.INTEROP_ENCODING || 'gzip';
const NAME = 'node';
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

const tls = { ca: fs.readFileSync('/certs/ca.pem') };
if (MTLS) {
  tls.cert = fs.readFileSync('/certs/client.pem');
  tls.key = fs.readFileSync('/certs/client.key');
}

function fail(reason) {
  console.error(`INTEROP FAIL ${NAME}: ${reason}`);
  process.exit(1);
}

function decode(buf, encoding) {
  if (!buf.length) return buf;
  if (encoding === 'gzip') return zlib.gunzipSync(buf);
  if (encoding === 'br') return zlib.brotliDecompressSync(buf);
  return buf;
}

// One request on an established session. Resolves with {status, headers, body}.
function request(session, method, path, body) {
  return new Promise((resolve, reject) => {
    const headers = {
      ':method': method,
      ':path': path,
      'x-api-key': 'interop',
      'accept-encoding': ENC,
    };
    if (body) headers['content-type'] = 'text/plain';
    const req = session.request(headers);
    const chunks = [];
    let resHeaders = null;
    req.on('response', (h) => { resHeaders = h; });
    req.on('data', (c) => chunks.push(c));
    req.on('error', reject);
    req.on('end', () => {
      let buf;
      try { buf = decode(Buffer.concat(chunks), resHeaders['content-encoding']); }
      catch (e) { return reject(new Error('decode failed: ' + e.message)); }
      resolve({
        status: resHeaders[':status'],
        headers: resHeaders,
        body: buf.toString('utf8'),
      });
    });
    if (body) req.end(body); else req.end();
  });
}

async function worker(deadline, counter) {
  const session = await connect();
  try {
    while (Date.now() < deadline) {
      for (const m of METHODS) {
        const body = (m === 'POST' || m === 'PUT' || m === 'PATCH')
          ? `hello from ${NAME}` : null;
        const r = await request(session, m, '/echo', body);
        if (r.status !== 200) throw new Error(`${m} status ${r.status}`);
        if (r.headers['content-encoding'] !== ENC)
          throw new Error(`${m} not ${ENC}-encoded (got ${r.headers['content-encoding']})`);
        if (m === 'HEAD') {
          if (r.headers['x-echo-method'] !== 'HEAD')
            throw new Error('HEAD missing x-echo-method');
        } else if (!r.body.includes(`method=${m}`)) {
          throw new Error(`${m} body did not echo method`);
        }
        counter.n++;
      }
      if (MTLS) {
        const r = await request(session, 'GET', '/whoami', null);
        if (r.status !== 200 || r.body.trim() === '' || r.body.trim() === '-')
          throw new Error('mTLS /whoami did not report a client subject');
        counter.n++;
      }
    }
  } finally {
    session.close();
  }
}

function connect() {
  return new Promise((resolve, reject) => {
    const s = http2.connect(URL, tls);
    s.on('error', reject);
    s.on('connect', () => resolve(s));
  });
}

(async () => {
  const deadline = Date.now() + RUNTIME * 1000;
  const counter = { n: 0 };
  try {
    await Promise.all(
      Array.from({ length: CLIENTS }, () => worker(deadline, counter)));
  } catch (e) {
    fail(e.message);
  }
  console.log(`INTEROP OK ${NAME}: requests=${counter.n} ` +
    `(clients=${CLIENTS}, runtime=${RUNTIME}s, mtls=${MTLS ? 1 : 0}, enc=${ENC})`);
})();

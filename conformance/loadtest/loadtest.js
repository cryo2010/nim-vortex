// k6 load script for the vortex load harness (conformance/loadtest/run.sh).
//
// One script, two load models, chosen by MODE:
//   throughput  constant-vus: VUS virtual users loop flat-out for DURATION,
//               saturating the server to find its ceiling.
//   rate        constant-arrival-rate: hold RATE req/s for DURATION and measure
//               latency/errors under that fixed load.
//
// The request is deliberately minimal (one GET, one check, bodies discarded) so
// k6 spends its CPU generating load, not parsing responses. Metrics stream to
// Prometheus (run.sh wires -o experimental-prometheus-rw) and render in Grafana.
import http from 'k6/http';
import { check } from 'k6';

const target = __ENV.TARGET_URL || 'http://server:8080';
const endpoint = __ENV.ENDPOINT || '/plaintext';
const url = target + endpoint;

const mode = __ENV.MODE || 'throughput';
const duration = __ENV.DURATION || '30s';
const vus = parseInt(__ENV.VUS || '50', 10);
const rate = parseInt(__ENV.RATE || '5000', 10);

let scenario;
if (mode === 'rate') {
  scenario = {
    executor: 'constant-arrival-rate',
    rate: rate,
    timeUnit: '1s',
    duration: duration,
    // Enough VUs to sustain the rate even if latency rises; k6 warns and emits
    // dropped_iterations if it still can't keep up (watch that Grafana panel).
    preAllocatedVUs: Math.max(50, Math.ceil(rate / 20)),
    maxVUs: Math.max(200, rate),
  };
} else {
  scenario = {
    executor: 'constant-vus',
    vus: vus,
    duration: duration,
  };
}

export const options = {
  scenarios: { load: scenario },
  discardResponseBodies: true,   // measure the server, not JSON/body parsing
  insecureSkipTLSVerify: true,   // self-signed cert on the TLS backends
  summaryTrendStats: ['avg', 'p(95)', 'p(99)', 'max'],
};

export default function () {
  const res = http.get(url);
  check(res, { 'status is 200': (r) => r.status === 200 });
}

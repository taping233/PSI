# Plain32 Protocol 3 / Method 2 PSI Simulation

This directory keeps two paper-aligned protocol simulations over one
TG-friendly prime. The arithmetic roles still run inside one executable, while
the message layer can either use fast ledger accounting plus the Zhihu linear
transport estimator, or a real local TCP/TLS RPC transport.

- `protocol3`: the paper's Protocol 3. The querying party has its own set,
  reconstructs one randomized intersection encoding
  `R = sum_i omega_i * p_i`, and tests only its own elements as roots of `R`.
- `protocol3-method2`: the paper's Protocol 3 share/reconstruction framework
  used twice as required by Fig. 4 plus Section 6.3 Method 2. The input-free
  third-party evaluator receives two independent encodings `R1` and `R2`,
  computes `gcd(R1, R2)`, and extracts all field roots with Tangent Graeffe.
  The result is checked against the delegated parties' intersection, without
  filtering by a query input set. The older CLI name `third-party-method2` is
  still accepted as a compatibility alias.

Elements are embedded directly as 32-bit field elements. No hash tag is used.
The Method 2 path intentionally keeps the previous no-hash design, runs two
independent Protocol 3 RIE rounds, and takes `gcd(R1, R2)` to reduce
spurious-root risk.

## Protocol model

The executable separates Client, Cloud, Query, and deterministic Dealer roles
with explicit message accounting, while remaining a single process.

Each set polynomial and random polynomial is additively shared between a client
and the cloud. Polynomial products use the coefficient-level Beaver protocol:
every scalar convolution term consumes an independent deterministic test triple.
Only the evaluator/query role reconstructs the final RIE polynomial. In
`protocol3-method2`, that role models the paper's third-party querying party
with no private input set.

All Beaver triples are generated and cached before input-dependent processing
starts. The cache shape depends only on the public `--exp`, participant count,
mode, and round. Online multiplication only consumes each cached triple once.
`RIE_OFFLINE triple_generate_time` is reported separately and is excluded from
`online_time` and `total_time`.

This is a correctness and cost simulation. It still does not implement the
paper's FHE-based distributed triple generation. Common-key setup uses real
RSA-OAEP-SHA256 public-key encryption/decryption to distribute the AES key in
the benchmark harness. Step 8 common-key result-share delivery uses real
OpenSSL AES-256-GCM encryption and authenticated decryption, with deterministic
benchmark nonce derivation.

By default, protocol messages are accounted without kernel network I/O and the
`RIE_TRANSPORT` line estimates communication time from the saved Zhihu
communication-volume model. Add `--transport tcp-tls` or `--real-network` to
open a loopback TCP socket, perform a real OpenSSL TLS handshake, and send every
protocol message as a length-prefixed streaming RPC frame with a 1-byte ACK.
The long-lived connection matches the article's recommendation for MPC-style
high-frequency interaction. Each frame carries a SPDZ-style HMAC-SHA256
integrity tag. This is a frame-level malicious-tamper check for the benchmark
transport, not a full SPDZ arithmetic MAC proof.

## Build

```bash
cmake -S . -B build-rie -DCMAKE_BUILD_TYPE=Release
cmake --build build-rie --parallel
```

The build links FLINT and NTL. NTL is the default GCD backend for the
`protocol3-method2` path because it is faster for the current `exp=20`
no-bucket benchmark. FLINT remains available for comparison with `--gcd flint`.

Sanitizer build:

```bash
cmake -S . -B build-rie-san \
  -DCMAKE_BUILD_TYPE=Debug \
  -DENABLE_SANITIZERS=ON
cmake --build build-rie-san --parallel
```

## Run

```bash
./build-rie/psi_direct_fft_no_bucket \
  --mode protocol3 --clients 2 --exp 8

./build-rie/psi_direct_fft_no_bucket \
  --mode protocol3-method2 --clients 3 --exp 9 --scenario half

./build-rie/psi_direct_fft_no_bucket \
  --mode protocol3-method2 --clients 2 --exp 5 --scenario half \
  --transport tcp-tls
```

GCD backend options:

```bash
./build-rie/psi_direct_fft_no_bucket \
  --mode protocol3-method2 --clients 2 --exp 15 --scenario half --gcd ntl

./build-rie/psi_direct_fft_no_bucket \
  --mode protocol3-method2 --clients 2 --exp 15 --scenario half --gcd flint
```

Add `--validate` for the heavier oracle and query-included checks. Validation
allocates its own offline Beaver caches and is disabled by default so that large
protocol runs such as `--exp 20` stay within small cgroup memory limits.

Add `--intersection-rate 0.0..1.0` to override the scenario's default common
element count. This is useful for algorithm-performance experiments where the
GCD degree and root-extraction cost should vary independently from the input
size.

Add `--trace` to print the paper-aligned protocol skeleton before execution:

```bash
./build-rie/psi_direct_fft_no_bucket \
  --mode protocol3-method2 --clients 2 --exp 5 --scenario half --trace
```

The run output includes:

- `RIE_RESULT`: correctness, degree, extraction, and timing summary.
- `RIE_OFFLINE`: preprocessing / Beaver cache cost.
- `RIE_METRICS`: arithmetic timing and total field-element messages.
- `RIE_PROFILE`: finer FFT/Beaver timing for polynomial multiplication.
- `RIE_FRAMEWORK`: paper-structure ledger separating input shares, Beaver
  openings, secure-channel result shares, common-key encrypted result shares,
  and reconstructed RIE polynomials.
- `RIE_NETWORK`: real or disabled network transport summary, including
  length-prefixed RPC bytes, TLS handshake time, RSA-OAEP key-exchange bytes,
  ACK count, and frame MAC checks.
- `RIE_MEMORY`: current RSS and peak RSS from `/proc/self/status`.

`RIE_RESULT` and `RIE_METRICS` also report Step 8 crypto fields:
`common_key_cipher=aes-256-gcm`, `common_key_exchange=rsa-oaep-sha256`,
`common_key_encrypt_time`, `common_key_decrypt_time`,
`common_key_encrypted_bytes`, `common_key_encryptions`,
`pke_key_exchange_time`, `tls_handshake_time`, `network_time`,
`spdz_mac_checks`, and `spdz_mac_failures`. PKE, TLS handshake, and measured
network wall time are included in `online_time` when `--transport tcp-tls` is
used. Frame MAC time is reported separately because it is already inside the
network wall time.

`RIE_TRANSPORT` reports a configurable transport model over the protocol
message ledger. The ledger converts field-element counts to bytes, uses the
measured AES-GCM ciphertext bytes for Step 8 payloads, and adds a fixed
per-message overhead before estimating transport time.

The default model is `--transport-model zhihu-linear --transport-profile wan`,
aligned to the saved Zhihu communication-time article's long-connection WAN
fit:

```text
transport_time = 0.538 + 0.116 * communication_mb   # WAN, x > 40 MB
transport_time = 0.024 + 0.004 * communication_mb   # LAN, x > 10 MB
```

Use `--transport-profile lan` for the LAN fit. The linear model treats the
protocol as a long-lived connection, so transport time depends on total
communication volume instead of round count. For the older parametric model,
use `--transport-model latency-bandwidth`, which estimates:

```text
transport_time = messages * latency_ms / 1000
               + total_bytes * 8 / (bandwidth_mbps * 1e6)
```

The model can be customized with `--transport-bandwidth-mbps`,
`--transport-latency-ms`, `--transport-message-overhead-bytes`,
`--transport-linear-intercept`, `--transport-linear-slope-per-mb`, and
`--transport-linear-valid-min-mb`. Existing arithmetic timings are left
unchanged; the output adds `online_with_transport_time` and
`end_to_end_with_transport_time` for the combined compute-plus-transport view.

Supported scenarios:

```text
half empty full single duplicates bounds
```

The current implementation accepts `exp <= 20`. Large runs require protocol-only
mode unless the container has enough memory for validation caches. Offline
triple caches require `6 * N * fft_n * sizeof(uint64_t)` bytes per RIE round,
where `fft_n` is the next power of two at least `2 * (n + 1) - 1`.

In the FFT-domain Beaver path, the offline cache shape is public and depends on
`--exp`, participant count, mode, and round. The implementation generates and
frees one round cache at a time. For `protocol3-method2 --clients 2 --exp 20`,
one protocol round cache is about 384 MiB, and the two protocol rounds together
consume about 768 MiB over the full run, but not simultaneously.


## Real Multi-Process Deployment And Dynamic Updates

`tools/dpsi_deploy.py` provides a deployable Method 2 path with separate long-
running cloud and query/evaluator processes. Clients update their own party
state over real HTTP(S) sockets. The cloud persists only cloud shares; the query
service persists only evaluator shares. The Python tool uses the compiled
`build-rie/dpsi_poly_backend` C++ helper by default for set-polynomial
construction, `omega_i p_i` multiplication, NTL GCD, and FLINT linear-root
extraction; Python only handles networking, persistence, and JSON framing.

Build the deployment polynomial backend and start a local deployment:

```bash
cmake --build build-rie --target dpsi_poly_backend --parallel

python3 tools/dpsi_deploy.py cloud   --host 127.0.0.1 --port 18765   --state deploy/cloud.json --token dev-token

python3 tools/dpsi_deploy.py query   --host 127.0.0.1 --port 18766   --state deploy/query.json   --cloud-url http://127.0.0.1:18765 --token dev-token
```

Upload or replace party state. Re-running `client update` for the same party is
the dynamic-update operation; it replaces that party's persisted shares without
restarting the cloud or query service.

```bash
python3 tools/dpsi_deploy.py client update   --party 1 --values '1 2 3 4' --degree-bound 4   --cloud-url http://127.0.0.1:18765   --query-url http://127.0.0.1:18766 --token dev-token

python3 tools/dpsi_deploy.py client update   --party 2 --values '3 4 5 6' --degree-bound 4   --cloud-url http://127.0.0.1:18765   --query-url http://127.0.0.1:18766 --token dev-token

python3 tools/dpsi_deploy.py result   --query-url http://127.0.0.1:18766 --token dev-token
```

Delete a party with `client delete`. Use `--dataset-file` instead of `--values`
for newline/comma/space separated integer datasets. `--degree-bound` is public
padding metadata; keep it at or above the largest party set size and stable
across updates when you do not want update size changes to alter the public
share length. Servers can be wrapped with Python TLS by passing `--tls-cert` and
`--tls-key`; clients accept test certificates with `--insecure-tls`. Use
`--poly-backend` or `DPSI_POLY_BACKEND` to point at a non-default compiled
backend. The old pure-Python polynomial path is retained only as a debug fallback
behind `DPSI_DEPLOY_PY_POLY=1`.

This deployment path deliberately does not use the C benchmark's trusted-dealer
Beaver cache. Each client computes `omega_i(x) * p_i(x)` locally and additively
splits the result between cloud and query services. That gives a real
multi-process dynamic RIE/Method 2 deployment, but it is not the paper's full
FHE-generated Beaver preprocessing or full SPDZ malicious-security construction.

## Performance notes

For `exp <= 15`, the program caps OpenMP/FLINT worker threads at 32 by default.
On the current 208-vCPU container this is faster and more stable for the
`exp=15` benchmark than using every visible CPU.

The `protocol3` query check uses FLINT fast multipoint evaluation. This keeps
the original "query party tests its elements against R(x)" behavior while
avoiding the previous O(n * degree) Horner loop.

Current verified `exp=15` examples on this container:

```bash
./build-rie/psi_direct_fft_no_bucket --mode protocol3-method2 --clients 2 --exp 15 --scenario half
./build-rie/psi_direct_fft_no_bucket --mode protocol3 --clients 2 --exp 15 --scenario half
```

The `protocol3-method2` third-party path remains the paper Method 2 path:
`roots(gcd(R1, R2))`. A direct `roots(R1) intersect roots(R2)` experiment was
not retained because the current Tangent Graeffe root finder corrupts memory on
large RIE polynomials.

For `clients=2 --exp 20 --scenario half`, the NTL GCD backend reduced the
observed GCD phase from about 62.2 seconds with FLINT to about 21.8 seconds,
cutting end-to-end time from about 78.4 seconds to about 38.0 seconds on the
current container.

## Benchmarking

Use `tools/run_bench.py` for repeatable algorithm-performance sweeps. It runs
the executable with timeouts, parses all `RIE_*` lines, and writes both CSV and
JSONL.

Focused `exp=15` run:

```bash
python3 tools/run_bench.py \
  --build \
  --mode protocol3-method2 \
  --clients 2 \
  --exps 15 \
  --scenarios half \
  --repeats 3 \
  --timeout 120 \
  --omp-threads 32 \
  --proc-bind close \
  --places cores \
  --transport simulated \
  --csv bench_exp15.csv \
  --jsonl bench_exp15.jsonl
```

Broader sweep:

```bash
python3 tools/run_bench.py \
  --mode protocol3-method2 \
  --clients 2-20 \
  --exps 10-17 \
  --scenarios half,empty,full \
  --intersection-rates 0.01,0.1,0.5 \
  --repeats 3 \
  --timeout 300 \
  --transport simulated \
  --csv bench_sweep.csv \
  --jsonl bench_sweep.jsonl
```

Rows with timeout, nonzero exit, or missing `RIE_RESULT` are still recorded with
`runner_status`, `runner_wall_time`, stdout/stderr tails, and the command
parameters. This is intended for large experiments where some points may OOM or
exceed the timeout.

See `docs/PAPER_ALIGNMENT.md` for the explicit mapping between the executable
framework and the paper's Protocol 3 and Fig. 4 plus Section 6.3 Method 2,
including the intentionally retained no-hash and optimized arithmetic choices.

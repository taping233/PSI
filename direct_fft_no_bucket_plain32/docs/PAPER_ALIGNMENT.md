# Paper Alignment Notes

This project now has two paths. The C executable is the high-performance
single-process benchmark for the paper's delegated multi-party PSI flow. The
Python deployment tool (`tools/dpsi_deploy.py`) runs separate cloud, query, and
client processes over real HTTP(S) sockets and persists dynamic party updates;
its set-polynomial construction, `omega_i p_i` multiplication, Method 2 GCD,
and linear-root extraction are delegated to the compiled C++/NTL/FLINT backend
`dpsi_poly_backend`.
The benchmark message layer still supports both the saved Zhihu long-connection
transport estimator and an optional real loopback TCP/TLS RPC transport for
measured communication cost.

## Roles

| Paper role | Code role | Current implementation |
| --- | --- | --- |
| Delegating parties `Pi` | `ClientRole` | Own generated datasets, build set polynomials `pi(x)`, create additive shares. |
| Cloud server `C` | `CloudRole` | Receives cloud shares, performs the cloud side of Beaver multiplication, aggregates shares. |
| Query/evaluator party | `QueryRole` | In `protocol3`, owns the query set and tests it against the reconstructed RIE polynomial. In `protocol3-method2`, has no input set and reconstructs the two Protocol 3 RIE polynomials for GCD/root extraction. |
| Preprocessing dealer | `DealerRole` | Deterministic test-only dealer for Beaver triples. This stands in for the paper's preprocessing/FHE triple generation. |

## Protocol 3 Mapping

| Paper step | Executable behavior |
| --- | --- |
| Step 1: encode elements | Direct 32-bit field embedding, no hash tag. |
| Step 2: set polynomial | `build_set_polynomial()` builds `pi(x)=prod(x-a)`. |
| Step 3: share `pi` | `share_poly_padded()` creates additive cloud/user shares. |
| Step 4: share `omega_i` | `random_polynomial()` plus `share_poly_padded()` creates random mask shares. |
| Step 5: cloud computes share of `sum omega_i pi` | `beaver_poly_multiply()` returns the cloud product share and `run_rie_round()` aggregates it. |
| Step 6: party computes its share | Same Beaver multiplication returns the user product share. |
| Step 7: cloud sends result share | Counted as `CHANNEL_SECURE_CHANNEL` in `RIE_FRAMEWORK`; under `--transport tcp-tls`, also sent over an OpenSSL TLS RPC frame. |
| Step 8: parties send encrypted result shares | Encrypted with AES-256-GCM, counted as `CHANNEL_COMMON_KEY_ENCRYPTED`, and under `--transport tcp-tls` sent over the same TLS RPC stream. |
| Step 9: evaluator reconstructs `r(x)` | `run_rie_round()` adds cloud and user sums and increments `reconstructed_polynomials`. |

## Protocol 3 Method 2 Querying

`protocol3-method2` is the preferred paper-aligned optimized path. It follows
the paper's Fig. 4 plus Section 6.3 Method 2 while retaining the existing
engineering decisions: direct 32-bit field embedding, no hash tag, two
independent RIE rounds, FFT-domain Beaver multiplication, NTL/FLINT GCD
backends, and TG/FLINT root extraction.

1. Run the delegated PSI Protocol 3 share framework twice with independent
   randomness.
2. The third-party evaluator reconstructs `R1(x)` and `R2(x)` from the cloud
   share plus all encrypted/user-side result shares.
3. The evaluator computes `I(x)=gcd(R1(x),R2(x))`.
4. The evaluator extracts all roots of `I(x)` as the delegated-party
   intersection.

The legacy CLI name `third-party-method2` is accepted as an alias for
`protocol3-method2`.

The benchmark validation fields `delegated_expected`, `root_count_match`, and
`double_match` are simulation-only correctness checks. A real third-party
deployment would need an additional proof, commitment, or expected-count input
if the third party must independently detect wrong output size.


## Real Deployment Tool

`tools/dpsi_deploy.py` implements a deployable Method 2 variant with persistent
state:

| Paper role | Deployment process |
| --- | --- |
| Delegating party `Pi` | `client update` invokes `dpsi_poly_backend share` to build `p_i(x)`, sample two `omega_i`, compute two `omega_i p_i` polynomials, and sends additive shares over real sockets. |
| Cloud server `C` | `cloud` stores only cloud shares per party/round and returns aggregate cloud shares. |
| Third-party query/evaluator | `query` stores only evaluator shares, fetches cloud aggregates, reconstructs `R1/R2`, and invokes `dpsi_poly_backend roots` for NTL GCD plus FLINT linear-root extraction. |

Dynamic update support is implemented as replacement of a party's persisted
round shares. `client delete` removes a party from both cloud and query state.
The cloud and query services do not need to restart for additions, replacements,
or deletions.

This is real multi-process deployment plumbing with the heavy polynomial work
running in compiled NTL/FLINT code, but it intentionally changes the local
computation split: clients compute `omega_i p_i` before additive sharing.
Therefore it does not exercise the paper's FHE-based Beaver triple generation or
cloud-side Beaver multiplication. It is best read as a deployable RIE/Method 2
state-management path, while the C executable remains the paper-step benchmark
for Beaver/FFT accounting.

## Security Model Implemented

Implemented as executable simulation:

- Additive secret sharing of `pi` and `omega_i`.
- Offline Beaver triple cache with one-time consumption checks.
- FFT-domain Beaver multiplication for polynomial products.
- Real RSA-OAEP-SHA256 public-key encryption/decryption for common-key
  distribution in the benchmark harness.
- Optional real loopback TCP socket plus OpenSSL TLS transport for protocol
  message frames. The frame format follows the saved communication-time page's
  long-connection model: length prefix, streamed payload, and 1-byte ACK.
- Real local AES-256-GCM encryption and authenticated decryption for Step 8
  common-key result-share payloads. Key/nonce material is deterministic for
  reproducible benchmarks and does not implement production key management.
- SPDZ-style HMAC-SHA256 frame MAC checks on TLS RPC payloads. These detect
  benchmark-transport tampering but are not a full SPDZ arithmetic MAC proof.
- Separate accounting for share uploads, Beaver openings, secure-channel result
  shares, and common-key encrypted result shares.
- A configurable transport model over the message ledger, emitted as
  `RIE_TRANSPORT`; the default `zhihu-linear` WAN profile uses the saved Zhihu
  long-connection fit `y=0.538+0.116*x` for `x` in MB, with a LAN profile
  `y=0.024+0.004*x`. This models communication cost without replacing the
  local arithmetic timings.
- Explicit output fields for the retained deviations: `hash_tag=no`,
  `rie_rounds`, `third_party_query`, `transport_runtime`,
  `spdz_mac_checks`, and `spdz_mac_failures`.
- Semi-honest control flow and deterministic reproducibility.

Still simulated / not implemented:

- The paper's FHE-based distributed Beaver triple generation. The deployment
  tool currently avoids this by having each client compute `omega_i p_i` locally
  before splitting the result.
- Production PKI / certificate lifecycle. The TLS path uses an ephemeral
  in-memory certificate trusted by the local client for benchmark runs.
- Full malicious-security SPDZ arithmetic MAC semantics over every polynomial
  operation. The implemented MAC is a frame-level HMAC integrity check.
- Hash-tag encoding and hash-table/binning optimizations.
- Production-grade deployment authentication/authorization. The deployment tool
  has a bearer-token guard and optional TLS wrapping, but no PKI lifecycle or
  per-party identity management.

These gaps are intentional in the current benchmark framework: the goal is to
align the requested communication/security plumbing with the protocol structure
while keeping the fast local arithmetic path available for large sweeps.

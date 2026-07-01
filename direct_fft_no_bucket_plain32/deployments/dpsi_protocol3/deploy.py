#!/usr/bin/env python3
"""Deployable D-PSI Protocol 3 prototype with dynamic updates.

This tool is intentionally separate from the high-performance single-process C
benchmark. It runs real long-lived processes for the cloud, query evaluator, and
clients over HTTP(S), persists per-party shares, and supports replacing or
deleting a party without restarting the deployment.

Protocol shape implemented here:
- each client builds p_i(x)=prod(x-a) locally;
- for each RIE round it samples omega_i and q_i=omega_i*p_i;
- q_i is additively split into a cloud share and evaluator share;
- the cloud stores only cloud shares, the query service stores only evaluator
  shares;
- querying aggregates both sides, reconstructs R1/R2, computes gcd(R1,R2), and
  extracts degree-1 roots.

This is a real multi-process deployment path for RIE Method 2 and dynamic state.
It does not claim to implement the paper's FHE triple generation or full SPDZ
malicious arithmetic MACs.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import http.server
import json
import os
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

FIELD_PRIME = 180143985094819841
TOKEN_HEADER = "X-DPSI-Token"


def now_ms() -> int:
    return int(time.time() * 1000)


def die(message: str, code: int = 2) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(code)



def default_poly_backend() -> str:
    env = os.environ.get("DPSI_POLY_BACKEND", "")
    if env:
        return env
    return str(Path(__file__).resolve().parents[2] / "build-rie" / "dpsi_poly_backend")


def use_python_poly_fallback() -> bool:
    return os.environ.get("DPSI_DEPLOY_PY_POLY", "") in {"1", "yes", "true"}


def require_poly_backend(path: str) -> str:
    backend = path or default_poly_backend()
    if not Path(backend).exists():
        if use_python_poly_fallback():
            return ""
        die(f"C/NTL/FLINT polynomial backend not found: {backend}; build target dpsi_poly_backend or set DPSI_POLY_BACKEND")
    return backend


def backend_share(values: List[int], rounds: int, degree_bound: int, backend_path: str) -> Dict[str, Any]:
    backend = require_poly_backend(backend_path)
    if not backend:
        return {}
    payload = f"{rounds} {degree_bound} {len(values)} " + " ".join(str(v) for v in values) + "\n"
    proc = subprocess.run(
        [backend, "share"],
        input=payload,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        die(f"dpsi_poly_backend share failed: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def backend_roots(lhs: List[int], rhs: List[int], backend_path: str) -> Dict[str, Any]:
    backend = require_poly_backend(backend_path)
    if not backend:
        return {}
    payload = (
        f"{len(lhs)} " + " ".join(str(v) for v in lhs) + " " +
        f"{len(rhs)} " + " ".join(str(v) for v in rhs) + "\n"
    )
    proc = subprocess.run(
        [backend, "roots"],
        input=payload,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        die(f"dpsi_poly_backend roots failed: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def backend_eval(poly: List[int], values: List[int], backend_path: str) -> Dict[str, Any]:
    backend = require_poly_backend(backend_path)
    if not backend:
        return {}
    payload = (
        f"{len(poly)} " + " ".join(str(v) for v in poly) + " " +
        f"{len(values)} " + " ".join(str(v) for v in values) + "\n"
    )
    proc = subprocess.run(
        [backend, "eval"],
        input=payload,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        die(f"dpsi_poly_backend eval failed: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def mod_inv(value: int) -> int:
    if value % FIELD_PRIME == 0:
        raise ZeroDivisionError("inverse of zero")
    return pow(value % FIELD_PRIME, FIELD_PRIME - 2, FIELD_PRIME)


def trim(poly: List[int]) -> List[int]:
    poly = [x % FIELD_PRIME for x in poly]
    while len(poly) > 1 and poly[-1] == 0:
        poly.pop()
    return poly or [0]


def degree(poly: List[int]) -> int:
    return len(trim(poly)) - 1


def monic(poly: List[int]) -> List[int]:
    poly = trim(poly)
    if len(poly) == 1 and poly[0] == 0:
        return poly
    inv = mod_inv(poly[-1])
    return [(x * inv) % FIELD_PRIME for x in poly]


def poly_add(a: List[int], b: List[int]) -> List[int]:
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        out[i] = ((a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)) % FIELD_PRIME
    return trim(out)


def poly_sub(a: List[int], b: List[int]) -> List[int]:
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        out[i] = ((a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0)) % FIELD_PRIME
    return trim(out)


def poly_mul(a: List[int], b: List[int]) -> List[int]:
    a = trim(a)
    b = trim(b)
    if a == [0] or b == [0]:
        return [0]
    out = [0] * (len(a) + len(b) - 1)
    for i, av in enumerate(a):
        if av:
            for j, bv in enumerate(b):
                if bv:
                    out[i + j] = (out[i + j] + av * bv) % FIELD_PRIME
    return trim(out)


def poly_divmod(a: List[int], b: List[int]) -> Tuple[List[int], List[int]]:
    a = trim(a[:])
    b = trim(b)
    if b == [0]:
        raise ZeroDivisionError("polynomial division by zero")
    if degree(a) < degree(b):
        return [0], a
    q = [0] * (degree(a) - degree(b) + 1)
    inv_lc = mod_inv(b[-1])
    while degree(a) >= degree(b) and a != [0]:
        shift = degree(a) - degree(b)
        coeff = a[-1] * inv_lc % FIELD_PRIME
        q[shift] = coeff
        for i, bv in enumerate(b):
            a[i + shift] = (a[i + shift] - coeff * bv) % FIELD_PRIME
        a = trim(a)
    return trim(q), trim(a)


def poly_mod(a: List[int], modulus: List[int]) -> List[int]:
    return poly_divmod(a, modulus)[1]


def poly_divexact(a: List[int], b: List[int]) -> List[int]:
    q, r = poly_divmod(a, b)
    if r != [0]:
        raise ValueError("non-exact polynomial division")
    return q


def poly_gcd(a: List[int], b: List[int]) -> List[int]:
    a = trim(a)
    b = trim(b)
    while b != [0]:
        a, b = b, poly_mod(a, b)
    return monic(a)


def poly_powmod(base: List[int], exp: int, modulus: List[int]) -> List[int]:
    result = [1]
    base = poly_mod(base, modulus)
    while exp:
        if exp & 1:
            result = poly_mod(poly_mul(result, base), modulus)
        exp >>= 1
        if exp:
            base = poly_mod(poly_mul(base, base), modulus)
    return result


def build_set_poly(values: List[int]) -> List[int]:
    poly = [1]
    for value in sorted(set(values)):
        if value < 0 or value > 0xFFFFFFFF:
            die(f"dataset element outside 32-bit range: {value}")
        poly = poly_mul(poly, [(-value) % FIELD_PRIME, 1])
    return poly


def random_poly(deg: int) -> List[int]:
    coeffs = [secrets.randbelow(FIELD_PRIME) for _ in range(deg + 1)]
    if coeffs[-1] == 0:
        coeffs[-1] = 1
    return trim(coeffs)


def random_share(poly: List[int], public_len: int) -> Tuple[List[int], List[int]]:
    padded = poly[:] + [0] * max(0, public_len - len(poly))
    padded = padded[:public_len]
    cloud = [secrets.randbelow(FIELD_PRIME) for _ in range(public_len)]
    evaluator = [(padded[i] - cloud[i]) % FIELD_PRIME for i in range(public_len)]
    return trim(cloud), trim(evaluator)


def deterministic_split_seed(party: str, round_id: int, values: List[int]) -> str:
    h = hashlib.sha256()
    h.update(party.encode())
    h.update(str(round_id).encode())
    for value in sorted(values):
        h.update(str(value).encode())
        h.update(b"\0")
    return h.hexdigest()


def linear_roots(poly: List[int]) -> List[int]:
    poly = monic(poly)
    if degree(poly) <= 0:
        return []
    x_poly = [0, 1]
    linear_part = poly_gcd(poly, poly_sub(poly_powmod(x_poly, FIELD_PRIME, poly), x_poly))
    return sorted(_split_linear_factors(monic(linear_part), 1))


def _split_linear_factors(poly: List[int], salt: int) -> List[int]:
    poly = monic(poly)
    deg = degree(poly)
    if deg <= 0:
        return []
    if deg == 1:
        return [(-poly[0] * mod_inv(poly[1])) % FIELD_PRIME]
    exp = (FIELD_PRIME - 1) // 2
    for attempt in range(1, 128):
        seed = hashlib.sha256(f"{salt}:{attempt}:{poly}".encode()).digest()
        coeffs = []
        counter = 0
        while len(coeffs) < deg:
            block = hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
            for off in range(0, len(block), 8):
                coeffs.append(int.from_bytes(block[off:off + 8], "big") % FIELD_PRIME)
                if len(coeffs) == deg:
                    break
            counter += 1
        h = trim(coeffs)
        if degree(h) <= 0:
            continue
        candidate = poly_gcd(poly, poly_sub(poly_powmod(h, exp, poly), [1]))
        cdeg = degree(candidate)
        if 0 < cdeg < deg:
            other = poly_divexact(poly, candidate)
            return _split_linear_factors(candidate, salt * 131 + attempt) + _split_linear_factors(other, salt * 257 + attempt)
    raise RuntimeError(f"failed to split linear factor product of degree {deg}")


def parse_values(text: str) -> List[int]:
    cleaned = text.replace(",", " ").replace("\n", " ").replace("\t", " ")
    values = [int(part, 0) for part in cleaned.split() if part.strip()]
    unique = sorted(set(values))
    for value in unique:
        if value < 0 or value > 0xFFFFFFFF:
            die(f"dataset element outside 32-bit range: {value}")
    return unique


def load_dataset(args: argparse.Namespace) -> List[int]:
    if args.values:
        values = parse_values(args.values)
    elif args.dataset_file:
        values = parse_values(Path(args.dataset_file).read_text())
    else:
        die("client update requires --values or --dataset-file")
    if not values:
        die("empty dynamic dataset is not supported in this deployment prototype")
    return values


def make_party_payload(party: str, values: List[int], rounds: int, degree_bound: int, backend_path: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
    if len(values) > degree_bound:
        die(f"dataset has {len(values)} values, above --degree-bound {degree_bound}")
    generated = backend_share(values, rounds, degree_bound, backend_path)
    if generated:
        cloud_rounds = generated["cloud"]
        eval_rounds = generated["query"]
    else:
        p = build_set_poly(values)
        cloud_rounds = []
        eval_rounds = []
        public_len = 2 * degree_bound + 1
        for round_id in range(1, rounds + 1):
            omega = random_poly(degree_bound)
            q = poly_mul(p, omega)
            cloud, evaluator = random_share(q, public_len)
            cloud_rounds.append({"round": round_id, "share": cloud})
            eval_rounds.append({"round": round_id, "share": evaluator})
    meta = {
        "party": party,
        "field_prime": FIELD_PRIME,
        "rounds": rounds,
        "degree_bound": degree_bound,
        "set_size": len(values),
        "version": deterministic_split_seed(party, rounds, values),
        "updated_at_ms": now_ms(),
    }
    cloud_payload = dict(meta, role="cloud", shares=cloud_rounds)
    eval_payload = dict(meta, role="query", shares=eval_rounds)
    return cloud_payload, eval_payload


def load_state(path: Path, default_role: str) -> Dict[str, Any]:
    if path.exists():
        return json.loads(path.read_text())
    return {"schema": 1, "role": default_role, "field_prime": FIELD_PRIME, "parties": {}, "query_set": []}


def save_state(path: Path, state: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")))
    tmp.replace(path)


def aggregate_parties(parties: Dict[str, Any], rounds: int | None = None) -> Dict[str, Any]:
    if not parties:
        return {"field_prime": FIELD_PRIME, "party_count": 0, "parties": [], "rounds": []}
    party_ids = sorted(parties.keys(), key=lambda x: (len(x), x))
    expected_rounds = rounds or max(int(parties[p].get("rounds", 0)) for p in party_ids)
    aggregates = []
    for round_id in range(1, expected_rounds + 1):
        agg = [0]
        for party in party_ids:
            by_round = {int(item["round"]): item["share"] for item in parties[party]["shares"]}
            if round_id not in by_round:
                die(f"party {party} missing round {round_id}", 500)
            agg = poly_add(agg, by_round[round_id])
        aggregates.append({"round": round_id, "share": agg})
    return {
        "field_prime": FIELD_PRIME,
        "party_count": len(party_ids),
        "parties": party_ids,
        "rounds": aggregates,
        "degree_bound": max(int(parties[p].get("degree_bound", 0)) for p in party_ids),
        "versions": {p: parties[p].get("version", "") for p in party_ids},
    }


def http_json(method: str, url: str, payload: Dict[str, Any] | None, token: str, insecure_tls: bool = False) -> Dict[str, Any]:
    data = None if payload is None else json.dumps(payload).encode()
    headers = {"Accept": "application/json", TOKEN_HEADER: token}
    if data is not None:
        headers["Content-Type"] = "application/json"
    ctx = None
    if insecure_tls and url.startswith("https://"):
        ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            body = resp.read().decode()
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        die(f"HTTP {e.code} from {url}: {detail}")
    except urllib.error.URLError as e:
        die(f"request failed for {url}: {e}")


class JsonHandler(http.server.BaseHTTPRequestHandler):
    server_version = "DPSIProtocol3Deploy/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        if getattr(self.server, "quiet", False):
            return
        super().log_message(fmt, *args)

    def _authorized(self) -> bool:
        token = getattr(self.server, "token", "")
        if not token:
            return True
        got = self.headers.get(TOKEN_HEADER, "")
        return hmac.compare_digest(got, token)

    def _send(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode())

    def _party_from_path(self, prefix: str) -> str | None:
        parsed = urllib.parse.urlparse(self.path)
        parts = [urllib.parse.unquote(p) for p in parsed.path.split("/") if p]
        if len(parts) == 2 and parts[0] == prefix:
            return parts[1]
        return None

    def do_GET(self) -> None:
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/health":
            self._send(200, {"ok": True, "role": self.server.role, "time_ms": now_ms()})
            return
        if parsed.path == "/state":
            state = load_state(self.server.state_path, self.server.role)
            self._send(200, state)
            return
        if self.server.role == "cloud" and parsed.path == "/aggregate":
            state = load_state(self.server.state_path, "cloud")
            rounds = int(query.get("rounds", ["0"])[0]) or None
            self._send(200, aggregate_parties(state.get("parties", {}), rounds))
            return
        if self.server.role == "query" and parsed.path == "/result":
            self._send(200, self._compute_query_result(query))
            return
        self._send(404, {"error": "not found"})

    def _compute_query_result(self, query: Dict[str, List[str]]) -> Dict[str, Any]:
        state = load_state(self.server.state_path, "query")
        local = aggregate_parties(state.get("parties", {}), 1)
        cloud_url = self.server.cloud_url.rstrip("/") + "/aggregate?rounds=1"
        cloud = http_json("GET", cloud_url, None, self.server.token, self.server.insecure_tls)
        if local["parties"] != cloud.get("parties"):
            raise RuntimeError(f"party mismatch cloud={cloud.get('parties')} query={local['parties']}")
        query_set = state.get("query_set", [])
        if not query_set:
            raise RuntimeError("query set is empty; run query-set update first")
        rie = poly_add(cloud["rounds"][0]["share"], local["rounds"][0]["share"])
        solved = backend_eval(rie, query_set, self.server.poly_backend)
        matches = solved.get("matches", []) if solved else []
        return {
            "ok": True,
            "mode": "dpsi-protocol3",
            "field_prime": FIELD_PRIME,
            "party_count": local["party_count"],
            "parties": local["parties"],
            "query_set_size": len(query_set),
            "intersection_count": len(matches),
            "intersection": matches,
            "versions": local.get("versions", {}),
            "cloud_versions": cloud.get("versions", {}),
            "query_version": state.get("query_version", ""),
            "updated_at_ms": now_ms(),
        }

    def do_POST(self) -> None:
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        parsed = urllib.parse.urlparse(self.path)
        if self.server.role == "query" and parsed.path == "/query-set":
            payload = self._read_json()
            values = sorted(set(int(v) for v in payload.get("values", [])))
            for value in values:
                if value < 0 or value > 0xFFFFFFFF:
                    self._send(400, {"error": "query value outside 32-bit range"})
                    return
            state = load_state(self.server.state_path, "query")
            state["query_set"] = values
            state["query_version"] = deterministic_split_seed("query", 1, values)
            state["query_updated_at_ms"] = now_ms()
            save_state(self.server.state_path, state)
            self._send(200, {"ok": True, "query_set_size": len(values), "query_version": state["query_version"]})
            return
        party = self._party_from_path("party")
        if not party:
            self._send(404, {"error": "not found"})
            return
        payload = self._read_json()
        if str(payload.get("party")) != party:
            self._send(400, {"error": "party id mismatch"})
            return
        if int(payload.get("field_prime", 0)) != FIELD_PRIME:
            self._send(400, {"error": "field prime mismatch"})
            return
        role = payload.get("role")
        if role != self.server.role:
            self._send(400, {"error": f"payload role {role!r} does not match server role {self.server.role!r}"})
            return
        state = load_state(self.server.state_path, self.server.role)
        state.setdefault("parties", {})[party] = payload
        save_state(self.server.state_path, state)
        self._send(200, {"ok": True, "party": party, "role": self.server.role, "party_count": len(state["parties"])})

    def do_DELETE(self) -> None:
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        party = self._party_from_path("party")
        if not party:
            self._send(404, {"error": "not found"})
            return
        state = load_state(self.server.state_path, self.server.role)
        existed = party in state.get("parties", {})
        state.setdefault("parties", {}).pop(party, None)
        save_state(self.server.state_path, state)
        self._send(200, {"ok": True, "party": party, "deleted": existed, "party_count": len(state["parties"])})


def serve(role: str, args: argparse.Namespace) -> None:
    address = (args.host, args.port)
    server = http.server.ThreadingHTTPServer(address, JsonHandler)
    server.role = role
    server.state_path = Path(args.state)
    server.token = args.token
    server.quiet = args.quiet
    server.cloud_url = getattr(args, "cloud_url", "")
    server.insecure_tls = getattr(args, "insecure_tls", False)
    server.poly_backend = getattr(args, "poly_backend", "")
    if args.tls_cert or args.tls_key:
        if not args.tls_cert or not args.tls_key:
            die("both --tls-cert and --tls-key are required for HTTPS")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.tls_cert, args.tls_key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    scheme = "https" if args.tls_cert else "http"
    print(f"DPSI_{role.upper()} listening {scheme}://{args.host}:{args.port} state={args.state}", flush=True)
    server.serve_forever()


def client_update(args: argparse.Namespace) -> None:
    values = load_dataset(args)
    degree_bound = args.degree_bound or len(values)
    cloud_payload, eval_payload = make_party_payload(str(args.party), values, args.rounds, degree_bound, args.poly_backend)
    cloud_url = args.cloud_url.rstrip("/") + f"/party/{urllib.parse.quote(str(args.party))}"
    query_url = args.query_url.rstrip("/") + f"/party/{urllib.parse.quote(str(args.party))}"
    cloud_resp = http_json("POST", cloud_url, cloud_payload, args.token, args.insecure_tls)
    query_resp = http_json("POST", query_url, eval_payload, args.token, args.insecure_tls)
    print(json.dumps({"ok": True, "party": str(args.party), "set_size": len(values), "degree_bound": degree_bound, "cloud": cloud_resp, "query": query_resp}, sort_keys=True))


def client_delete(args: argparse.Namespace) -> None:
    cloud_url = args.cloud_url.rstrip("/") + f"/party/{urllib.parse.quote(str(args.party))}"
    query_url = args.query_url.rstrip("/") + f"/party/{urllib.parse.quote(str(args.party))}"
    cloud_resp = http_json("DELETE", cloud_url, None, args.token, args.insecure_tls)
    query_resp = http_json("DELETE", query_url, None, args.token, args.insecure_tls)
    print(json.dumps({"ok": True, "party": str(args.party), "cloud": cloud_resp, "query": query_resp}, sort_keys=True))


def query_set_update(args: argparse.Namespace) -> None:
    values = load_dataset(args)
    url = args.query_url.rstrip("/") + "/query-set"
    resp = http_json("POST", url, {"values": values}, args.token, args.insecure_tls)
    print(json.dumps({"ok": True, "query_set_size": len(values), "query": resp}, sort_keys=True))


def query_result(args: argparse.Namespace) -> None:
    url = args.query_url.rstrip("/") + "/result"
    print(json.dumps(http_json("GET", url, None, args.token, args.insecure_tls), sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Real-process D-PSI Protocol 3 deployment and dynamic updates")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def server_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--host", default="127.0.0.1")
        p.add_argument("--port", type=int, required=True)
        p.add_argument("--state", required=True)
        p.add_argument("--token", default=os.environ.get("DPSI_TOKEN", "dev-token"))
        p.add_argument("--tls-cert", default="")
        p.add_argument("--tls-key", default="")
        p.add_argument("--quiet", action="store_true")

    cloud = sub.add_parser("cloud")
    server_common(cloud)
    cloud.set_defaults(func=lambda a: serve("cloud", a))

    query = sub.add_parser("query")
    server_common(query)
    query.add_argument("--cloud-url", required=True)
    query.add_argument("--poly-backend", default=default_poly_backend())
    query.add_argument("--insecure-tls", action="store_true")
    query.set_defaults(func=lambda a: serve("query", a))

    client = sub.add_parser("client")
    client_sub = client.add_subparsers(dest="client_cmd", required=True)
    upd = client_sub.add_parser("update")
    upd.add_argument("--party", required=True)
    upd.add_argument("--values", default="")
    upd.add_argument("--dataset-file", default="")
    upd.add_argument("--degree-bound", type=int, default=0)
    upd.add_argument("--rounds", type=int, default=1)
    upd.add_argument("--cloud-url", required=True)
    upd.add_argument("--query-url", required=True)
    upd.add_argument("--poly-backend", default=default_poly_backend())
    upd.add_argument("--token", default=os.environ.get("DPSI_TOKEN", "dev-token"))
    upd.add_argument("--insecure-tls", action="store_true")
    upd.set_defaults(func=client_update)

    dele = client_sub.add_parser("delete")
    dele.add_argument("--party", required=True)
    dele.add_argument("--cloud-url", required=True)
    dele.add_argument("--query-url", required=True)
    dele.add_argument("--token", default=os.environ.get("DPSI_TOKEN", "dev-token"))
    dele.add_argument("--insecure-tls", action="store_true")
    dele.set_defaults(func=client_delete)

    query_set = sub.add_parser("query-set")
    query_set_sub = query_set.add_subparsers(dest="query_set_cmd", required=True)
    q_upd = query_set_sub.add_parser("update")
    q_upd.add_argument("--values", default="")
    q_upd.add_argument("--dataset-file", default="")
    q_upd.add_argument("--query-url", required=True)
    q_upd.add_argument("--token", default=os.environ.get("DPSI_TOKEN", "dev-token"))
    q_upd.add_argument("--insecure-tls", action="store_true")
    q_upd.set_defaults(func=query_set_update)

    qr = sub.add_parser("result")
    qr.add_argument("--query-url", required=True)
    qr.add_argument("--token", default=os.environ.get("DPSI_TOKEN", "dev-token"))
    qr.add_argument("--insecure-tls", action="store_true")
    qr.set_defaults(func=query_result)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    try:
        args.func(args)
        return 0
    except RuntimeError as e:
        die(str(e), 1)


if __name__ == "__main__":
    raise SystemExit(main())

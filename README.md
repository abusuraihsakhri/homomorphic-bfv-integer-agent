# Homomorphic BFV Integer Agent

An educational, pure-Python implementation of **BFV-style encrypted integer polynomial arithmetic**. The core engine supports key generation, encryption/decryption, homomorphic addition, multiplication with gadget-decomposed relinearization, and noise diagnostics. A separate synthetic telemetry API demonstrates an agent audit workflow.

**Security notice:** This is a research and teaching implementation, not a hardened encryption library. The preset ring dimensions are small, parameter recommendations are heuristic, Python arithmetic is not constant-time, and the code has not been independently security assessed. **Do not use this code to protect real secrets, medical records, or patient data.** The audit API is not a validated clinical or standards-compliance system.

## Browser demonstration

The `web/` directory contains a browser UI that runs the **same Python encryption engine** locally using [Pyodide](https://pyodide.org/). It supports integer vectors, encryption/decryption, addition, and negacyclic polynomial multiplication correctness checks. GitHub Actions includes a Pages publishing workflow; a live site requires Pages to be enabled for the repository.

For local preview (requires a network connection to load Pyodide assets):

```bash
mkdir -p /tmp/bfv-site
cp web/index.html web/app.js web/style.css /tmp/bfv-site/
cp bfv_integer_agent/engine.py /tmp/bfv-site/bfv_engine.py
python -m http.server 8080 --directory /tmp/bfv-site
```

Open <http://localhost:8080/>. Browser assets load from jsDelivr. The application does not submit input vectors or keys to an application server; do not enter sensitive data.

## Installation and CLI

Requires Python 3.9 or newer. The BFV core uses the Python standard library.

```bash
git clone https://github.com/abusuraihsakhri/homomorphic-bfv-integer-agent.git
cd homomorphic-bfv-integer-agent
python -m pip install -e .
homomorphic-bfv-integer-agent demo --preset toy
homomorphic-bfv-integer-agent params
```

Generate keys and execute a round trip:

```bash
homomorphic-bfv-integer-agent keygen --preset toy --output bfv_keys.json
homomorphic-bfv-integer-agent encrypt "3,1,4,1,5" --keys bfv_keys.json --output ct.json
homomorphic-bfv-integer-agent decrypt --keys bfv_keys.json --ciphertext ct.json
```

Generate two ciphertexts with the same keys to use `add --ct1 ... --ct2 ...` or `mul --ct1 ... --ct2 ...`. Multiplication is **negacyclic polynomial convolution modulo t** in the ring \(\mathbb{Z}_t[x]/(x^N+1)\), not element-wise vector multiplication. Old serialized keys remain usable for decrypt/add, but **must be regenerated for multiplication** because the relinearization-key format changed.

Key generation creates owner-only secret-key files on Unix-like systems and refuses to overwrite existing files. The global `--seed` option permits reproducible demonstrations; **do not treat seeded keys as secure**.

## Synthetic audit API

The separate synthetic-audit CLI is `homomorphic-bfv-audit`. For the FastAPI service:

```bash
python -m pip install -e ".[server]"
python -m uvicorn agents.api:app --host 127.0.0.1 --port 8000
```

API documentation: <http://127.0.0.1:8000/docs>. Routes include `/health`, `/metrics`, `/api/audit`, `/api/chat`, and `/api/audit/logs`. The audit API uses arbitrary, **synthetic numerical thresholds**: it does not inspect BFV ciphertext integrity, establish conformance, or make medical decisions. Chat uses a **local placeholder**; remote model providers are not implemented.

Audit entries are signed with HMAC-SHA256 and verified against the expected signature and predecessor. **Logs are process-local and not durable.** Set `AUDIT_SECRET_KEY` to a strong random value for a configured installation. The pattern-based identifier filter is incomplete and **does not establish HIPAA compliance**.

## Docker

Docker runs the synthetic API, not the browser demo. Docker Compose binds to loopback:

```bash
export AUDIT_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
docker compose up --build
```

Do not expose audit routes to untrusted networks without authentication, rate limits, and a deployment security review.

## Tests and development

```bash
python -m pip install -e ".[server,test]"
python -m pip check
python -m compileall -q agents bfv_integer_agent cli.py enrichment.py simulator.py
python -m pytest -q
node --check web/app.js
```

CI runs Python 3.10–3.12 with correctness and audit-chain tests. The browser requires WebAssembly, JavaScript, and CDN access; first load can be slow. Modules in `enrichment.py` are generic demonstrators, **not** certified cryptographic validators.

## Project layout

- `bfv_integer_agent/engine.py` — reference BFV-style polynomial engine
- `cli.py` — encryption CLI
- `bfv_integer_agent/cli.py` — synthetic audit CLI
- `agents/` — audit workers, logging and FastAPI
- `web/` — browser UI running Python through Pyodide
- `tests/` — unit and regression tests

## License

[MIT](LICENSE).

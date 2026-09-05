# Homomorphic BFV Integer Agent

> **Domain:** Post-Quantum Cryptography & Zero-Knowledge Architecture
> **Reference Guidelines & Standards:** `NIST FIPS 203/204/205, NIST SP 800-90B & ISO/IEC Standards`

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB.svg?logo=python&logoColor=white)
![Audit Trail](https://img.shields.io/badge/Audit-HMAC--SHA256_Tamper--Evident-brightgreen.svg)
![Zero-PHI Guard](https://img.shields.io/badge/Guard-Zero--PHI_Outbound-blue.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)

</div>

---

## 📖 What It Does

**Homomorphic BFV Integer Agent** is an educational and computational platform implementing BFV / BGV exact integer homomorphic encryption, relinearization & encrypted SQL queries.

This project provides:
- **BFV Homomorphic Encryption Engine**: Full implementation of the BFV scheme for exact integer arithmetic on encrypted data
- **Multi-Agent Analysis System**: Distributed component workers for task evaluation and consensus
- **PHI Protection**: Zero-PHI outbound interceptor for HIPAA compliance
- **Cryptographic Audit Trail**: Tamper-evident HMAC-SHA256 chained logging

---

## ⚙️ Key Capabilities & Algorithmic Modules

### Homomorphic Encryption Engine
- **Polynomial Arithmetic**: Negacyclic ring operations in Z_q[x]/(x^N + 1)
- **Key Generation**: Secret key, public key, and relinearization key generation
- **Encryption/Decryption**: Integer vector encoding with delta scaling
- **Homomorphic Operations**: Addition and multiplication with noise budget tracking
- **Parameter Selection**: Preset and recommended parameter sets

### Security & Analysis
- **Zero-PHI Outbound Interceptor**: AST and regex inspection blocking SSNs, MRNs, phone numbers, and patient identifiers
- **Tamper-Evident HMAC-SHA256 Audit Trail**: Chained, cryptographically signed logs for every evaluation
- **Multi-Agent Consensus**: Specialized workers for QC invariant checking, safety escalation, and protocol conformance

---

## 💻 Installation

```bash
# Clone the repository
git clone https://github.com/abusuraihsakhri/homomorphic-bfv-integer-agent.git
cd homomorphic-bfv-integer-agent

# Install dependencies (Python 3.9+ required)
pip install -e .

# Optional: Install web server dependencies
pip install fastapi uvicorn pydantic pytest
```

---

## 💻 CLI Quickstart & Usage

### 1. Run the Full Demo
```bash
python cli.py demo --preset toy
```

### 2. Key Generation
```bash
python cli.py keygen --preset toy -o bfv_keys.json
```

### 3. Encrypt / Decrypt
```bash
python cli.py encrypt "3,1,4,1,5" --keys bfv_keys.json -o ciphertext.json
python cli.py decrypt --keys bfv_keys.json --ciphertext ciphertext.json
```

### 4. Homomorphic Operations
```bash
# Add two ciphertexts
python cli.py add --keys bfv_keys.json --ct1 ct1.json --ct2 ct2.json -o sum.json

# Multiply two ciphertexts
python cli.py mul --keys bfv_keys.json --ct1 ct1.json --ct2 ct2.json -o product.json
```

### 5. Parameter Information
```bash
# Show preset parameters
python cli.py params

# Get recommended parameters for your use case
python cli.py params --recommend --plaintext-bits 8 --num-muls 2
```

### Command Reference
| Command | Description |
|:--------|:------------|
| `keygen` | Generate BFV key pair and evaluation keys |
| `encrypt` | Encrypt integer message(s) |
| `decrypt` | Decrypt a ciphertext |
| `add` | Homomorphic addition of two ciphertexts |
| `mul` | Homomorphic multiplication of two ciphertexts |
| `demo` | Run a full end-to-end BFV demo |
| `params` | Show or recommend BFV parameters |

---

## 🔐 Security Configuration

### Audit Trail Key
Set the `AUDIT_SECRET_KEY` environment variable for persistent audit integrity:

```bash
# Linux/macOS
export AUDIT_SECRET_KEY="your-secure-random-key"

# Windows
set AUDIT_SECRET_KEY=your-secure-random-key
```

> **Note**: If not set, a random session key is generated (with a warning). This is suitable for development but not for production.

---

## 🧪 Testing & Verification

Run the automated test suite:

```bash
pytest -v
```

Run with coverage:

```bash
pytest -v --cov=bfv_integer_agent --cov=agents --cov=enrichment
```

Execute high-throughput batch simulation benchmarks:

```bash
python simulator.py 100
```

---

## 🐳 Container Deployment

```bash
docker build -t homomorphic-bfv-integer-agent .
docker run -p 8000:8000 -e AUDIT_SECRET_KEY=your-secure-key homomorphic-bfv-integer-agent
```

---

## 📁 Project Structure

```
homomorphic-bfv-integer-agent/
├── bfv_integer_agent/        # Core BFV encryption engine
│   ├── engine.py             # BFV scheme implementation
│   ├── agents.py             # Multi-agent coordination
│   ├── cli.py                # CLI for agent operations
│   ├── models.py             # Data models
│   └── server.py             # FastAPI REST server
├── agents/                   # Analysis agent system
│   ├── base.py               # PHI guard and audit trail
│   ├── models.py             # Agent data models
│   ├── supervisor.py         # Supervisor orchestrator
│   ├── workers.py            # Specialized worker agents
│   └── llm_factory.py        # LLM integration
├── tests/                    # Test suite
├── web/                      # Web interface
├── cli.py                    # Main CLI entry point
├── enrichment.py             # Enrichment feature modules
├── simulator.py              # Batch simulation
└── pyproject.toml            # Project configuration
```

---

## ⚠️ Known Limitations

- **BFV Multiplication**: Homomorphic multiplication with toy/small parameters may fail due to insufficient noise budget. Use `BFVParams.recommend()` for production use cases.
- **Educational Use**: This implementation is for educational purposes and not recommended for production cryptographic applications without thorough security review.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

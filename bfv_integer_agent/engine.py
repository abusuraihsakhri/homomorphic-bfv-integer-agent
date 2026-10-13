"""
BFV (Brakerski-Fan-Vercauteren) Homomorphic Encryption Engine.

Implements exact integer arithmetic over encrypted data using the BFV scheme
over the polynomial ring R_q = Z_q[x] / (x^N + 1).

Key operations:
  - Key generation (secret key, public key, relinearization key)
  - Encryption / Decryption of integer vectors
  - Homomorphic addition and multiplication
  - Noise budget tracking
  - Parameter selection guidance
"""
import math
import random
import json
from typing import List, Tuple, Optional, Dict, Any


# ---------------------------------------------------------------------------
# Polynomial arithmetic in Z_q[x] / (x^N + 1)  (negacyclic ring)
# ---------------------------------------------------------------------------

class Poly:
    """Polynomial in the negacyclic ring Z_q[x]/(x^N + 1)."""

    __slots__ = ("coeffs", "q", "N")

    def __init__(self, coeffs: List[int], q: int, N: int):
        self.q = q
        self.N = N
        if N <= 0 or q <= 1:
            raise ValueError("Invalid polynomial dimension or modulus")
        if len(coeffs) > N:
            raise ValueError("Too many coefficients for ring dimension")
        c = list(coeffs)
        while len(c) < N:
            c.append(0)
        self.coeffs = [x % q for x in c]

    # -- arithmetic ----------------------------------------------------------

    def __add__(self, other: "Poly") -> "Poly":
        assert self.q == other.q and self.N == other.N
        return Poly([(a + b) % self.q for a, b in zip(self.coeffs, other.coeffs)],
                    self.q, self.N)

    def __sub__(self, other: "Poly") -> "Poly":
        assert self.q == other.q and self.N == other.N
        return Poly([(a - b) % self.q for a, b in zip(self.coeffs, other.coeffs)],
                    self.q, self.N)

    def __mul__(self, other: "Poly") -> "Poly":
        """Negacyclic convolution: multiply mod (x^N + 1)."""
        assert self.q == other.q and self.N == other.N
        N, q = self.N, self.q
        result = [0] * N
        for i in range(N):
            ai = self.coeffs[i]
            if ai == 0:
                continue
            for j in range(N):
                bj = other.coeffs[j]
                if bj == 0:
                    continue
                k = i + j
                prod = (ai * bj) % q
                if k < N:
                    result[k] = (result[k] + prod) % q
                else:
                    # x^N ≡ -1  →  negate and wrap
                    result[k - N] = (result[k - N] - prod) % q
        return Poly(result, q, N)

    def scalar_mul(self, scalar: int) -> "Poly":
        return Poly([(c * scalar) % self.q for c in self.coeffs], self.q, self.N)

    def mod_down(self, new_q: int) -> "Poly":
        """Scale coefficients from q to new_q (rounding)."""
        q = self.q
        new_coeffs = [int(c * new_q / q + 0.5) % new_q for c in self.coeffs]
        return Poly(new_coeffs, new_q, self.N)

    def scale(self, numerator: int, denominator: int) -> "Poly":
        """Scale coefficients by numerator/denominator, keeping modulus q.
        Used in BFV multiplication to scale by t/q."""
        new_coeffs = [int(c * numerator / denominator + 0.5) for c in self.coeffs]
        return Poly(new_coeffs, self.q, self.N)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Poly):
            return NotImplemented
        return self.coeffs == other.coeffs and self.q == other.q and self.N == other.N

    def __repr__(self) -> str:
        return f"Poly(N={self.N}, q={self.q}, coeffs={self.coeffs[:8]}{'...' if self.N > 8 else ''})"

    def infinity_norm(self) -> int:
        """Return the infinity norm (max absolute value centered)."""
        half = self.q // 2
        return max(min(c, self.q - c) for c in self.coeffs)

    def to_json(self) -> Dict[str, Any]:
        return {"coeffs": self.coeffs, "q": self.q, "N": self.N}

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "Poly":
        return cls(data["coeffs"], data["q"], data["N"])


# ---------------------------------------------------------------------------
# Error / key sampling
# ---------------------------------------------------------------------------

def sample_ternary(N: int, q: int, hamming_weight: Optional[int] = None,
                   rng: Optional[random.Random] = None) -> Poly:
    """Sample a ternary polynomial with coefficients in {-1, 0, 1}."""
    if rng is None:
        rng = random
    if hamming_weight is None:
        hamming_weight = max(1, N // 3)
    coeffs = [0] * N
    positions = rng.sample(range(N), min(hamming_weight, N))
    for p in positions:
        coeffs[p] = rng.choice([-1, 1])
    return Poly(coeffs, q, N)


def sample_error(N: int, q: int, eta: int = 1,
                 rng: Optional[random.Random] = None) -> Poly:
    """Sample from centered binomial distribution with parameter eta."""
    if rng is None:
        rng = random
    coeffs = []
    for _ in range(N):
        a = sum(rng.randint(0, 1) for _ in range(eta))
        b = sum(rng.randint(0, 1) for _ in range(eta))
        coeffs.append(a - b)
    return Poly(coeffs, q, N)


def sample_uniform(N: int, q: int, rng: Optional[random.Random] = None) -> Poly:
    """Sample a uniformly random polynomial in R_q."""
    if rng is None:
        rng = random
    return Poly([rng.randint(0, q - 1) for _ in range(N)], q, N)


# ---------------------------------------------------------------------------
# BFV Parameters
# ---------------------------------------------------------------------------

class BFVParams:
    """
    BFV scheme parameters.

    Attributes:
        N:   Ring dimension (power of 2).  Security ~ N bits.
        q:   Ciphertext modulus.  Larger q → more noise budget but less security.
        t:   Plaintext modulus.   Messages live in Z_t.
        eta: Error distribution parameter (centered binomial).
    """

    # Pre-defined parameter sets (educational / toy sizes)
    # Educational, non-security-rated presets with room for multiplication.
    TOY = {"N": 16, "q": 2**20, "t": 16, "eta": 1}
    SMALL = {"N": 64, "q": 2**30, "t": 256, "eta": 1}
    MEDIUM = {"N": 256, "q": 2**40, "t": 1024, "eta": 2}

    def __init__(self, N: int, q: int, t: int, eta: int = 1):
        if N < 2 or N & (N - 1) != 0:
            raise ValueError(f"N must be a power of 2, got {N}")
        if q <= t:
            raise ValueError(f"q ({q}) must be > t ({t})")
        if t < 2:
            raise ValueError(f"t ({t}) must be >= 2")
        if eta < 1:
            raise ValueError("eta must be >= 1")
        self.N = N
        self.q = q
        self.t = t
        self.eta = eta
        self.delta = q // t
        self.noise_bits = math.log2(q / t)

    def __repr__(self) -> str:
        return (f"BFVParams(N={self.N}, q={self.q}, t={self.t}, "
                f"eta={self.eta}, delta={self.delta}, "
                f"noise_budget≈{self.noise_bits:.1f} bits)")

    @classmethod
    def from_preset(cls, name: str) -> "BFVParams":
        presets = {"toy": cls.TOY, "small": cls.SMALL, "medium": cls.MEDIUM}
        if name.lower() not in presets:
            raise ValueError(f"Unknown preset '{name}'. Choose from {list(presets.keys())}")
        return cls(**presets[name.lower()])

    @classmethod
    def recommend(cls, plaintext_bits: int, num_adds: int = 0,
                  num_muls: int = 1) -> "BFVParams":
        """Recommend parameters based on desired operations."""
        if not (1 <= plaintext_bits <= 16 and 0 <= num_adds <= 100 and 0 <= num_muls <= 4):
            raise ValueError("Unsupported educational parameter request")
        # Each multiplication consumes ~log2(t) + log2(N)/2 noise bits
        # Each addition consumes ~1 noise bit
        t = 1 << plaintext_bits
        # Pick N (ring dimension) - powers of 2
        N = 128
        # Estimate noise budget needed
        # Initial noise budget ~ log2(q/t)
        # Each mul costs ~ log2(t) + log2(N)/2 bits
        noise_per_mul = plaintext_bits + math.log2(N) / 2
        needed_noise = num_muls * noise_per_mul + num_adds + 10
        # q/t must provide enough noise budget
        # q/t = 2^needed_noise, so q = t * 2^needed_noise
        q = t * (2 ** int(math.ceil(needed_noise)))
        # Round q up to nearest power of 2 for efficiency
        q = 1 << int(math.ceil(math.log2(q)))
        return cls(N=N, q=q, t=t, eta=1)


# ---------------------------------------------------------------------------
# Ciphertext
# ---------------------------------------------------------------------------

class BFVCiphertext:
    """
    BFV ciphertext: a pair (c0, c1) in R_q^2.

    After multiplication (before relinearization) there may be a third
    component c2; the ``degree`` field tracks this.
    """

    __slots__ = ("c0", "c1", "c2", "degree", "noise_budget", "params")

    def __init__(self, c0: Poly, c1: Poly, params: BFVParams,
                 c2: Optional[Poly] = None, noise_budget: float = 0.0):
        self.c0 = c0
        self.c1 = c1
        self.c2 = c2
        self.degree = 2 if c2 is not None else 1
        self.noise_budget = noise_budget
        self.params = params

    def to_json(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "c0": self.c0.to_json(), "c1": self.c1.to_json(),
            "degree": self.degree, "noise_budget": self.noise_budget,
        }
        if self.c2 is not None:
            d["c2"] = self.c2.to_json()
        return d

    @classmethod
    def from_json(cls, data: Dict[str, Any], params: BFVParams) -> "BFVCiphertext":
        c0 = Poly.from_json(data["c0"])
        c1 = Poly.from_json(data["c1"])
        c2 = Poly.from_json(data["c2"]) if "c2" in data else None
        if any(poly.q != params.q or poly.N != params.N for poly in [c0, c1] + ([c2] if c2 else [])):
            raise ValueError("Ciphertext parameters do not match selected keys")
        ct = cls(c0, c1, params, c2=c2, noise_budget=data.get("noise_budget", 0))
        return ct


# ---------------------------------------------------------------------------
# BFV Scheme
# ---------------------------------------------------------------------------

class BFVScheme:
    """
    BFV Homomorphic Encryption Scheme.

    Usage::

        params = BFVParams.from_preset("small")
        scheme = BFVScheme(params)
        sk, pk, rlk = scheme.keygen()

        ct = scheme.encrypt([42, 7, 13], pk)
        msg = scheme.decrypt(ct, sk)          # → [42, 7, 13]

        ct_sum = scheme.add(ct, ct)
        ct_prod = scheme.mul(ct, ct, rlk)
    """

    def __init__(self, params: BFVParams, seed: Optional[int] = None):
        self.params = params
        # Seeded randomness is reproducible, not cryptographically secure.
        self._rng = random.SystemRandom() if seed is None else random.Random(seed)

    # -- key generation ------------------------------------------------------

    def keygen(self) -> Tuple[Poly, Tuple[Poly, Poly], Tuple[Poly, Poly]]:
        """
        Generate (sk, pk, rlk).

        Returns:
            sk:  Secret key (ternary polynomial).
            pk:  Public key tuple (pk0, pk1).
            rlk: Relinearization key tuple (rlk0, rlk1).
        """
        p = self.params
        N, q = p.N, p.q
        rng = self._rng

        # Secret key: ternary polynomial
        sk = sample_ternary(N, q, rng=rng)

        # Public key: pk = (-(a*sk + e), a)
        a = sample_uniform(N, q, rng=rng)
        e = sample_error(N, q, p.eta, rng=rng)
        pk0 = (a * sk + e).scalar_mul(q - 1)  # -(a*sk + e) mod q
        pk = (pk0, a)

        # Relinearization key: encrypt sk^2 under pk, scaled by delta
        rlk = self._gen_relin_key(sk, pk)

        return sk, pk, rlk

    def _gen_relin_key(self, sk: Poly,
                       pk: Tuple[Poly, Poly]) -> Tuple[List[Poly], List[Poly]]:
        """Encrypt gadget multiples of sk² for degree-2 to degree-1 switching."""
        p = self.params
        base = 256
        digits = (p.q.bit_length() + 7) // 8
        sk_sq = sk * sk
        left: List[Poly] = []
        right: List[Poly] = []
        for j in range(digits):
            a = sample_uniform(p.N, p.q, rng=self._rng)
            e = sample_error(p.N, p.q, p.eta, rng=self._rng)
            left.append(sk_sq.scalar_mul(base ** j) - (a * sk) - e)
            right.append(a)
        return left, right

    # -- encryption ----------------------------------------------------------

    def encrypt(self, message: List[int],
                pk: Tuple[Poly, Poly]) -> BFVCiphertext:
        """
        Encrypt a list of integer messages (each mod t).

        The message is encoded as a polynomial m(x) whose coefficients
        are the message values mod t, then scaled by delta = floor(q/t).
        """
        p = self.params
        N, q, t, delta = p.N, p.q, p.t, p.delta

        rng = self._rng

        # Encode message
        if len(message) > N:
            raise ValueError(f"Message length {len(message)} exceeds ring dimension {N}")
        m_coeffs = [int(m) % t for m in message]
        m_poly = Poly(m_coeffs, q, N)
        m_scaled = m_poly.scalar_mul(delta)

        # Randomness
        u = sample_ternary(N, q, rng=rng)
        e1 = sample_error(N, q, p.eta, rng=rng)
        e2 = sample_error(N, q, p.eta, rng=rng)

        # c0 = pk0*u + e1 + delta*m
        c0 = pk[0] * u + e1 + m_scaled
        # c1 = pk1*u + e2
        c1 = pk[1] * u + e2

        # Initial noise budget estimate
        noise_budget = p.noise_bits - math.log2(max(1, p.eta)) - 2

        return BFVCiphertext(c0, c1, p, noise_budget=noise_budget)

    # -- decryption ----------------------------------------------------------

    def decrypt(self, ct: BFVCiphertext, sk: Poly) -> List[int]:
        """
        Decrypt a ciphertext.

        For degree-1:  v = c0 + c1*s         → m = round(v * t / q) mod t
        For degree-2:  v = c0 + c1*s + c2*s^2 → m = round(v * t / q^2) mod t
        """
        p = self.params
        N, q, t = p.N, p.q, p.t

        self._check_ciphertext(ct)
        if sk.N != N or sk.q != q:
            raise ValueError("Secret key parameters do not match scheme")
        if ct.degree == 1:
            v = ct.c0 + ct.c1 * sk
            divisor = q
        else:
            sk_sq = sk * sk
            v = ct.c0 + ct.c1 * sk + ct.c2 * sk_sq
            divisor = q

        message = []
        for coeff in v.coeffs:
            # Center the coefficient
            centered = coeff if coeff <= q // 2 else coeff - q
            m_val = round(centered * t / divisor) % t
            message.append(int(m_val))
        return message

    # -- homomorphic addition ------------------------------------------------

    def add(self, ct1: BFVCiphertext, ct2: BFVCiphertext) -> BFVCiphertext:
        """Homomorphic addition of two ciphertexts."""
        p = self.params
        self._check_ciphertext(ct1)
        self._check_ciphertext(ct2)
        if ct1.degree == 1 and ct2.degree == 1:
            c0 = ct1.c0 + ct2.c0
            c1 = ct1.c1 + ct2.c1
            noise = min(ct1.noise_budget, ct2.noise_budget) - 1
            return BFVCiphertext(c0, c1, p, noise_budget=noise)
        else:
            # General case (degree-2 + degree-2 or mixed)
            c0 = ct1.c0 + ct2.c0
            c1 = ct1.c1 + ct2.c1
            c2 = None
            if ct1.degree == 2 and ct2.degree == 2:
                c2 = ct1.c2 + ct2.c2
            elif ct1.degree == 2:
                c2 = ct1.c2
            elif ct2.degree == 2:
                c2 = ct2.c2
            noise = min(ct1.noise_budget, ct2.noise_budget) - 1
            return BFVCiphertext(c0, c1, p, c2=c2, noise_budget=noise)

    def add_plain(self, ct: BFVCiphertext, message: List[int]) -> BFVCiphertext:
        """Add a plaintext polynomial to a ciphertext."""
        p = self.params
        m_poly = Poly([m % p.t for m in message], p.q, p.N)
        m_scaled = m_poly.scalar_mul(p.delta)
        self._check_ciphertext(ct)
        c0 = ct.c0 + m_scaled
        return BFVCiphertext(c0, ct.c1, p, noise_budget=ct.noise_budget)

    # -- homomorphic multiplication ------------------------------------------

    def mul(self, ct1: BFVCiphertext, ct2: BFVCiphertext,
            rlk: Tuple[List[Poly], List[Poly]]) -> BFVCiphertext:
        """Scale integer tensor products, then relinearize using gadget digits.

        Multiplying already reduced mod-q products loses information.
        This is a reference teaching implementation, not production BFV.
        """
        p = self.params
        self._check_ciphertext(ct1)
        self._check_ciphertext(ct2)
        if ct1.degree != 1 or ct2.degree != 1:
            raise ValueError("Only degree-one inputs are supported")
        if (len(rlk) != 2 or not isinstance(rlk[0], list)
                or not isinstance(rlk[1], list) or len(rlk[0]) != len(rlk[1])
                or len(rlk[0]) != (p.q.bit_length() + 7) // 8):
            raise ValueError("Incompatible legacy relinearization key; regenerate keys")

        def centered(poly: Poly) -> List[int]:
            return [x if x <= p.q // 2 else x - p.q for x in poly.coeffs]

        def convolution(a: List[int], b: List[int]) -> List[int]:
            result = [0] * p.N
            for i, ai in enumerate(a):
                for j, bj in enumerate(b):
                    k = i + j
                    result[k % p.N] += ai * bj if k < p.N else -ai * bj
            return result

        def scaled(values: List[int]) -> Poly:
            def rounded(value: int) -> int:
                numerator = abs(value) * p.t
                v = (numerator + p.q // 2) // p.q
                return v if value >= 0 else -v
            return Poly([rounded(value) for value in values], p.q, p.N)

        a0, a1 = centered(ct1.c0), centered(ct1.c1)
        b0, b1 = centered(ct2.c0), centered(ct2.c1)
        d0 = scaled(convolution(a0, b0))
        d1 = scaled([u + v for u, v in zip(convolution(a0, b1), convolution(a1, b0))])
        d2 = scaled(convolution(a1, b1))
        c0, c1 = d0, d1
        base = 256
        for j, (key0, key1) in enumerate(zip(rlk[0], rlk[1])):
            if key0.N != p.N or key0.q != p.q or key1.N != p.N or key1.q != p.q:
                raise ValueError("Relinearization key parameters do not match scheme")
            digit_poly = Poly([(v // (base ** j)) % base for v in d2.coeffs], p.q, p.N)
            c0 = c0 + digit_poly * key0
            c1 = c1 + digit_poly * key1

        noise = min(ct1.noise_budget, ct2.noise_budget) - math.log2(p.t) - math.log2(p.N) / 2
        return BFVCiphertext(c0, c1, p, noise_budget=noise)

    def _check_ciphertext(self, ct: BFVCiphertext) -> None:
        if (ct.c0.q != self.params.q or ct.c1.q != self.params.q
                or ct.c0.N != self.params.N or ct.c1.N != self.params.N
                or ct.params.N != self.params.N or ct.params.q != self.params.q
                or ct.params.t != self.params.t):
            raise ValueError("Ciphertext parameters do not match scheme")

    def mul_plain(self, ct: BFVCiphertext, message: List[int]) -> BFVCiphertext:
        """Multiply ciphertext by a plaintext polynomial."""
        p = self.params
        self._check_ciphertext(ct)
        m_poly = Poly([m % p.t for m in message], p.q, p.N)
        c0 = ct.c0 * m_poly
        c1 = ct.c1 * m_poly
        noise = ct.noise_budget - math.log2(p.t) / 2
        return BFVCiphertext(c0, c1, p, noise_budget=noise)

    # -- utilities -----------------------------------------------------------

    def noise_budget(self, ct: BFVCiphertext, sk: Poly) -> float:
        """
        Measure the actual noise budget of a ciphertext.

        Computes v = c0 + c1*s (mod q) and measures how far the
        coefficients are from the nearest valid plaintext value.
        """
        p = self.params
        N, q, t, delta = p.N, p.q, p.t, p.delta

        self._check_ciphertext(ct)
        v = ct.c0 + ct.c1 * sk
        max_noise = 0
        for coeff in v.coeffs:
            # The "clean" value should be delta * m for some m in Z_t
            centered = coeff if coeff <= q // 2 else coeff - q
            # Distance to nearest multiple of delta
            m_est = round(centered / delta)
            residual = abs(centered - m_est * delta)
            if residual > max_noise:
                max_noise = residual

        if max_noise == 0:
            return float("inf")
        return math.log2(delta) - math.log2(max_noise)

    def serialize_keys(self, sk: Poly, pk: Tuple[Poly, Poly],
                       rlk: Tuple[Poly, Poly]) -> str:
        """Serialize keys to JSON string."""
        data = {
            "sk": sk.to_json(),
            "pk": [pk[0].to_json(), pk[1].to_json()],
            "rlk": [[p.to_json() for p in rlk[0]], [p.to_json() for p in rlk[1]]],
            "params": {"N": self.params.N, "q": self.params.q,
                       "t": self.params.t, "eta": self.params.eta},
        }
        return json.dumps(data)

    @classmethod
    def deserialize_keys(cls, json_str: str) -> Tuple[Poly, Tuple[Poly, Poly],
                                                       Tuple[Poly, Poly],
                                                       BFVParams]:
        """Deserialize keys from JSON string."""
        data = json.loads(json_str)
        params = BFVParams(**data["params"])
        sk = Poly.from_json(data["sk"])
        pk = (Poly.from_json(data["pk"][0]), Poly.from_json(data["pk"][1]))
        if isinstance(data["rlk"][0], list):
            rlk = ([Poly.from_json(p) for p in data["rlk"][0]],
                   [Poly.from_json(p) for p in data["rlk"][1]])
        else:
            # Legacy keys remain readable for decrypt/add, not multiplication.
            rlk = (Poly.from_json(data["rlk"][0]), Poly.from_json(data["rlk"][1]))
        return sk, pk, rlk, params


# ---------------------------------------------------------------------------
# High-level demo helper
# ---------------------------------------------------------------------------

def demo(preset: str = "toy", seed: int = 42) -> Dict[str, Any]:
    """Run a full BFV demo and return results dict."""
    params = BFVParams.from_preset(preset)
    scheme = BFVScheme(params, seed=seed)

    sk, pk, rlk = scheme.keygen()

    # Encrypt two messages
    m1 = [3, 1, 4, 1, 5] + [0] * (params.N - 5)
    m2 = [2, 7, 1, 8, 2] + [0] * (params.N - 5)

    ct1 = scheme.encrypt(m1, pk)
    ct2 = scheme.encrypt(m2, pk)

    # Decrypt
    dec1 = scheme.decrypt(ct1, sk)
    dec2 = scheme.decrypt(ct2, sk)

    # Add
    ct_sum = scheme.add(ct1, ct2)
    dec_sum = scheme.decrypt(ct_sum, sk)

    # Multiply (first 2 slots only, rest zero)
    ct_prod = scheme.mul(ct1, ct2, rlk)
    dec_prod = scheme.decrypt(ct_prod, sk)

    # Measure noise
    nb1 = scheme.noise_budget(ct1, sk)
    nb_sum = scheme.noise_budget(ct_sum, sk)
    nb_prod = scheme.noise_budget(ct_prod, sk)

    return {
        "params": repr(params),
        "m1": m1[:5],
        "m2": m2[:5],
        "dec_m1": dec1[:5],
        "dec_m2": dec2[:5],
        "add_expected": [(a + b) % params.t for a, b in zip(m1[:5], m2[:5])],
        "add_decrypted": dec_sum[:5],
        "mul_expected": (Poly(m1, params.t, params.N) * Poly(m2, params.t, params.N)).coeffs[:5],
        "mul_decrypted": dec_prod[:5],
        "noise_budget_ct1": round(nb1, 2),
        "noise_budget_sum": round(nb_sum, 2),
        "noise_budget_prod": round(nb_prod, 2),
    }


# ---------------------------------------------------------------------------
# Frontier Domain Engine - Analytical evaluation functions
# ---------------------------------------------------------------------------

class FrontierDomainEngine:
    """Domain-specific analytical engine for evaluating task parameters.

    Provides threshold-based evaluation of primary metrics, secondary kinetics,
    and specification conformance for the BFV/BGV agent system.
    """

    PRIMARY_THRESHOLD = 25.0
    SECONDARY_THRESHOLD = 12.0
    DISCORDANCE_KEYWORDS = ["DISCORDANT", "ANOMALY", "MUTANT", "VIOLATION", "FAIL", "REJECT"]

    @classmethod
    def evaluate_primary_parameter(cls, primary_metric: float) -> Optional[Dict[str, Any]]:
        """Evaluate primary metric against threshold.

        Returns:
            Alert dict with keys: summary, details, remediation
            None if metric is within acceptable bounds.
        """
        if primary_metric > cls.PRIMARY_THRESHOLD:
            return {
                "summary": "Primary Metric Threshold Exceeded",
                "details": (
                    f"Primary measurement ({primary_metric:.2f}) exceeds upper reference "
                    f"limit ({cls.PRIMARY_THRESHOLD:.2f}) under BFV / BGV Homomorphic Cryptography standards."
                ),
                "remediation": "Initiate recalibration workflow and review secondary parameters.",
            }
        return None

    @classmethod
    def evaluate_secondary_kinetics(cls, secondary_metric: float, is_critical_flag: bool) -> Optional[Dict[str, Any]]:
        """Evaluate secondary metric and critical flag.

        Returns:
            Alert dict with keys: summary, details, remediation
            None if metric is within acceptable bounds.
        """
        if is_critical_flag or secondary_metric > cls.SECONDARY_THRESHOLD:
            return {
                "summary": "Critical Safety Interlock Triggered",
                "details": (
                    f"CriticalFlag={is_critical_flag} with secondary index {secondary_metric:.2f}."
                ),
                "remediation": "Execute immediate closed-loop escalation and notify attending supervisor.",
            }
        return None

    @classmethod
    def audit_specification_conformance(cls, status_descriptor: str, attributes: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Audit status descriptor for specification conformance.

        Returns:
            Alert dict with keys: summary, details, remediation
            None if descriptor indicates conformance.
        """
        desc_upper = str(status_descriptor).upper()
        if any(keyword in desc_upper for keyword in cls.DISCORDANCE_KEYWORDS):
            return {
                "summary": "Protocol Conformance Discordance Detected",
                "details": (
                    f"Descriptor '{status_descriptor}' indicates discordance with "
                    f"BFV / BGV Homomorphic Cryptography standards."
                ),
                "remediation": "Re-evaluate input specimen or rerun secondary confirmation assay.",
            }
        return None

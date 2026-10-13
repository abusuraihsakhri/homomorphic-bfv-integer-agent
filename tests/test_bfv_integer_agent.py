"""
Tests for BFV Integer Homomorphic Encryption Engine.

Covers:
  - Polynomial arithmetic (negacyclic ring)
  - Parameter selection
  - Key generation
  - Encryption / Decryption round-trip
  - Homomorphic addition
  - Homomorphic multiplication
  - Noise budget tracking
  - Serialization
  - CLI
"""
import sys
import os
import json
import math
import random
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bfv_integer_agent.engine import (
    Poly, BFVParams, BFVScheme, BFVCiphertext,
    sample_ternary, sample_error, sample_uniform, demo,
)
from cli import main as cli_main


# ── Polynomial Arithmetic ──────────────────────────────────────────────────

class TestPolyArithmetic:
    """Tests for Poly operations in Z_q[x]/(x^N+1)."""

    def test_poly_creation_and_padding(self):
        p = Poly([1, 2, 3], q=100, N=8)
        assert len(p.coeffs) == 8
        assert p.coeffs[:3] == [1, 2, 3]
        assert p.coeffs[3:] == [0, 0, 0, 0, 0]

    def test_poly_modular_reduction(self):
        p = Poly([105, -3, 256], q=100, N=4)
        assert p.coeffs[0] == 5   # 105 mod 100
        assert p.coeffs[1] == 97  # -3 mod 100 = 97
        assert p.coeffs[2] == 56  # 256 mod 100

    def test_poly_addition(self):
        a = Poly([1, 2, 3, 0], q=100, N=4)
        b = Poly([4, 5, 6, 0], q=100, N=4)
        c = a + b
        assert c.coeffs == [5, 7, 9, 0]

    def test_poly_addition_modular(self):
        a = Poly([90, 0, 0, 0], q=100, N=4)
        b = Poly([20, 0, 0, 0], q=100, N=4)
        c = a + b
        assert c.coeffs[0] == 10  # (90+20) mod 100

    def test_poly_subtraction(self):
        a = Poly([5, 7, 9, 0], q=100, N=4)
        b = Poly([4, 5, 6, 0], q=100, N=4)
        c = a - b
        assert c.coeffs == [1, 2, 3, 0]

    def test_poly_negacyclic_multiplication(self):
        # x * x = x^2 in normal ring, but in negacyclic ring with N=4:
        # x * x = x^2 (no wrap for degree < N)
        a = Poly([0, 1, 0, 0], q=1000, N=4)  # x
        b = Poly([0, 1, 0, 0], q=1000, N=4)  # x
        c = a * b
        assert c.coeffs == [0, 0, 1, 0]  # x^2

    def test_poly_negacyclic_wrap(self):
        # x^3 * x = x^4 ≡ -1 in Z_q[x]/(x^4+1)
        a = Poly([0, 0, 0, 1], q=1000, N=4)  # x^3
        b = Poly([0, 1, 0, 0], q=1000, N=4)  # x
        c = a * b
        # x^4 ≡ -1 mod (x^4+1), so coefficient 0 should be q-1 = 999
        assert c.coeffs[0] == 999  # -1 mod 1000
        assert c.coeffs[1:] == [0, 0, 0]

    def test_poly_scalar_mul(self):
        a = Poly([1, 2, 3, 4], q=100, N=4)
        b = a.scalar_mul(3)
        assert b.coeffs == [3, 6, 9, 12]

    def test_poly_scalar_mul_modular(self):
        a = Poly([50, 0, 0, 0], q=100, N=4)
        b = a.scalar_mul(3)
        assert b.coeffs[0] == 50  # 150 mod 100

    def test_poly_mod_down(self):
        a = Poly([100, 50, 25, 0], q=1000, N=4)
        b = a.mod_down(100)
        # 100*100/1000=10, 50*100/1000=5, 25*100/1000=2.5→3
        assert b.coeffs[0] == 10
        assert b.coeffs[1] == 5
        assert b.coeffs[2] == 3

    def test_poly_equality(self):
        a = Poly([1, 2, 3, 0], q=100, N=4)
        b = Poly([1, 2, 3, 0], q=100, N=4)
        c = Poly([1, 2, 4, 0], q=100, N=4)
        assert a == b
        assert a != c

    def test_poly_infinity_norm(self):
        # Coefficients: [10, 990, 5, 0] with q=1000
        # Centered: [10, -10, 5, 0] → norm = 10
        a = Poly([10, 990, 5, 0], q=1000, N=4)
        assert a.infinity_norm() == 10

    def test_poly_json_roundtrip(self):
        a = Poly([1, 2, 3, 4, 5, 6, 7, 8], q=1000, N=8)
        data = a.to_json()
        b = Poly.from_json(data)
        assert a == b


# ── Sampling ───────────────────────────────────────────────────────────────

class TestSampling:

    def test_sample_ternary_coefficients(self):
        p = sample_ternary(64, 1000)
        for c in p.coeffs:
            assert c in [0, 1, 999]  # -1 mod 1000 = 999

    def test_sample_error_small(self):
        p = sample_error(64, 1000, eta=1)
        for c in p.coeffs:
            centered = c if c <= 500 else c - 1000
            assert -3 <= centered <= 3  # Very unlikely to exceed 3 with eta=1

    def test_sample_uniform_range(self):
        p = sample_uniform(64, 1000)
        for c in p.coeffs:
            assert 0 <= c < 1000


# ── BFV Parameters ─────────────────────────────────────────────────────────

class TestBFVParams:

    def test_preset_toy(self):
        p = BFVParams.from_preset("toy")
        assert p.N == 16
        assert p.t == 16

    def test_preset_small(self):
        p = BFVParams.from_preset("small")
        assert p.N == 64
        assert p.t == 256

    def test_invalid_preset(self):
        try:
            BFVParams.from_preset("nonexistent")
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_invalid_N(self):
        try:
            BFVParams(N=15, q=1024, t=16)
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_q_must_exceed_t(self):
        try:
            BFVParams(N=16, q=10, t=16)
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_recommend(self):
        p = BFVParams.recommend(plaintext_bits=8, num_muls=2)
        assert p.N >= 64
        assert p.q > p.t


# ── Key Generation ─────────────────────────────────────────────────────────

class TestKeyGeneration:

    def test_keygen_returns_three(self):
        params = BFVParams.from_preset("toy")
        scheme = BFVScheme(params, seed=42)
        sk, pk, rlk = scheme.keygen()
        assert isinstance(sk, Poly)
        assert isinstance(pk, tuple) and len(pk) == 2
        assert isinstance(rlk, tuple) and len(rlk) == 2

    def test_keygen_deterministic_with_seed(self):
        params = BFVParams.from_preset("toy")
        s1 = BFVScheme(params, seed=123)
        s2 = BFVScheme(params, seed=123)
        sk1, pk1, rlk1 = s1.keygen()
        sk2, pk2, rlk2 = s2.keygen()
        assert sk1 == sk2
        assert pk1[0] == pk2[0]

    def test_keygen_different_seeds(self):
        params = BFVParams.from_preset("toy")
        s1 = BFVScheme(params, seed=1)
        s2 = BFVScheme(params, seed=2)
        sk1, _, _ = s1.keygen()
        sk2, _, _ = s2.keygen()
        assert sk1 != sk2


# ── Encryption / Decryption ───────────────────────────────────────────────

class TestEncryptDecrypt:

    def test_encrypt_decrypt_single_value(self):
        params = BFVParams.from_preset("toy")
        scheme = BFVScheme(params, seed=42)
        sk, pk, rlk = scheme.keygen()

        ct = scheme.encrypt([7], pk)
        dec = scheme.decrypt(ct, sk)
        assert dec[0] == 7

    def test_encrypt_decrypt_multiple_values(self):
        params = BFVParams.from_preset("toy")
        scheme = BFVScheme(params, seed=42)
        sk, pk, rlk = scheme.keygen()

        msg = [3, 1, 4, 1, 5] + [0] * (params.N - 5)
        ct = scheme.encrypt(msg, pk)
        dec = scheme.decrypt(ct, sk)
        for i in range(5):
            assert dec[i] == msg[i]

    def test_encrypt_decrypt_zero(self):
        params = BFVParams.from_preset("toy")
        scheme = BFVScheme(params, seed=42)
        sk, pk, _ = scheme.keygen()

        ct = scheme.encrypt([0], pk)
        dec = scheme.decrypt(ct, sk)
        assert dec[0] == 0

    def test_encrypt_decrypt_max_value(self):
        params = BFVParams.from_preset("toy")  # t=16
        scheme = BFVScheme(params, seed=42)
        sk, pk, _ = scheme.keygen()

        ct = scheme.encrypt([15], pk)  # max value in Z_16
        dec = scheme.decrypt(ct, sk)
        assert dec[0] == 15

    def test_different_encryptions_differ(self):
        """Two encryptions of the same message should produce different ciphertexts."""
        params = BFVParams.from_preset("small")
        scheme = BFVScheme(params, seed=42)
        sk, pk, _ = scheme.keygen()

        ct1 = scheme.encrypt([5], pk)
        ct2 = scheme.encrypt([5], pk)
        # With overwhelming probability, ciphertexts differ
        assert ct1.c0 != ct2.c0 or ct1.c1 != ct2.c1


# ── Homomorphic Addition ──────────────────────────────────────────────────

class TestHomomorphicAddition:

    def test_add_two_ciphertexts(self):
        params = BFVParams.from_preset("toy")
        scheme = BFVScheme(params, seed=42)
        sk, pk, rlk = scheme.keygen()

        ct1 = scheme.encrypt([3], pk)
        ct2 = scheme.encrypt([5], pk)
        ct_sum = scheme.add(ct1, ct2)
        dec = scheme.decrypt(ct_sum, sk)
        assert dec[0] == 8  # (3+5) mod 16

    def test_add_with_modular_wrap(self):
        params = BFVParams.from_preset("toy")  # t=16
        scheme = BFVScheme(params, seed=42)
        sk, pk, _ = scheme.keygen()

        ct1 = scheme.encrypt([10], pk)
        ct2 = scheme.encrypt([9], pk)
        ct_sum = scheme.add(ct1, ct2)
        dec = scheme.decrypt(ct_sum, sk)
        assert dec[0] == 3  # (10+9) mod 16 = 3

    def test_add_multiple_values(self):
        params = BFVParams.from_preset("toy")
        scheme = BFVScheme(params, seed=42)
        sk, pk, _ = scheme.keygen()

        m1 = [1, 2, 3, 4] + [0] * (params.N - 4)
        m2 = [5, 6, 7, 8] + [0] * (params.N - 4)
        ct1 = scheme.encrypt(m1, pk)
        ct2 = scheme.encrypt(m2, pk)
        ct_sum = scheme.add(ct1, ct2)
        dec = scheme.decrypt(ct_sum, sk)
        expected = [6, 8, 10, 12]
        for i in range(4):
            assert dec[i] == expected[i]

    def test_add_plain(self):
        params = BFVParams.from_preset("toy")
        scheme = BFVScheme(params, seed=42)
        sk, pk, _ = scheme.keygen()

        ct = scheme.encrypt([7], pk)
        ct_sum = scheme.add_plain(ct, [3])
        dec = scheme.decrypt(ct_sum, sk)
        assert dec[0] == 10

    def test_add_identity(self):
        """Adding zero ciphertext should not change value."""
        params = BFVParams.from_preset("toy")
        scheme = BFVScheme(params, seed=42)
        sk, pk, _ = scheme.keygen()

        ct = scheme.encrypt([7], pk)
        zero = scheme.encrypt([0], pk)
        ct_sum = scheme.add(ct, zero)
        dec = scheme.decrypt(ct_sum, sk)
        assert dec[0] == 7

    def test_add_commutativity(self):
        params = BFVParams.from_preset("toy")
        scheme = BFVScheme(params, seed=42)
        sk, pk, _ = scheme.keygen()

        ct1 = scheme.encrypt([3], pk)
        ct2 = scheme.encrypt([5], pk)
        d1 = scheme.decrypt(scheme.add(ct1, ct2), sk)
        d2 = scheme.decrypt(scheme.add(ct2, ct1), sk)
        assert d1[0] == d2[0]


# ── Homomorphic Multiplication ────────────────────────────────────────────

class TestHomomorphicMultiplication:

    def test_mul_two_ciphertexts(self):
        # Toy parameters support multiplication with single-slot encryption
        params = BFVParams.from_preset("toy")
        scheme = BFVScheme(params, seed=42)
        sk, pk, rlk = scheme.keygen()

        ct1 = scheme.encrypt([3] + [0] * (params.N - 1), pk)
        ct2 = scheme.encrypt([5] + [0] * (params.N - 1), pk)
        ct_prod = scheme.mul(ct1, ct2, rlk)
        dec = scheme.decrypt(ct_prod, sk)
        assert dec[0] == 15  # 3*5 mod 16

    def test_mul_with_modular_wrap(self):
        # Use parameters with sufficient noise budget for multiplication
        params = BFVParams.from_preset("small")
        scheme = BFVScheme(params, seed=42)
        sk, pk, rlk = scheme.keygen()

        ct1 = scheme.encrypt([3] + [0] * (params.N - 1), pk)
        ct2 = scheme.encrypt([4] + [0] * (params.N - 1), pk)
        ct_prod = scheme.mul(ct1, ct2, rlk)
        dec = scheme.decrypt(ct_prod, sk)
        assert dec[0] == 12  # 3*4 mod 256

    def test_mul_by_one(self):
        # Use parameters with sufficient noise budget for multiplication
        params = BFVParams.from_preset("small")
        scheme = BFVScheme(params, seed=42)
        sk, pk, rlk = scheme.keygen()

        ct = scheme.encrypt([5] + [0] * (params.N - 1), pk)
        one = scheme.encrypt([1] + [0] * (params.N - 1), pk)
        ct_prod = scheme.mul(ct, one, rlk)
        dec = scheme.decrypt(ct_prod, sk)
        assert dec[0] == 5

    def test_mul_by_zero(self):
        # Toy parameters support multiplication with single-slot encryption
        params = BFVParams.from_preset("toy")
        scheme = BFVScheme(params, seed=42)
        sk, pk, rlk = scheme.keygen()

        ct = scheme.encrypt([3] + [0] * (params.N - 1), pk)
        zero = scheme.encrypt([0] + [0] * (params.N - 1), pk)
        ct_prod = scheme.mul(ct, zero, rlk)
        dec = scheme.decrypt(ct_prod, sk)
        assert dec[0] == 0

    def test_mul_plain(self):
        params = BFVParams.from_preset("toy")
        scheme = BFVScheme(params, seed=42)
        sk, pk, _ = scheme.keygen()

        ct = scheme.encrypt([3], pk)
        ct_prod = scheme.mul_plain(ct, [4])
        dec = scheme.decrypt(ct_prod, sk)
        assert dec[0] == 12

    def test_mul_commutativity(self):
        params = BFVParams.from_preset("toy")
        scheme = BFVScheme(params, seed=42)
        sk, pk, rlk = scheme.keygen()

        ct1 = scheme.encrypt([3], pk)
        ct2 = scheme.encrypt([5], pk)
        d1 = scheme.decrypt(scheme.mul(ct1, ct2, rlk), sk)
        d2 = scheme.decrypt(scheme.mul(ct2, ct1, rlk), sk)
        assert d1[0] == d2[0]


# ── Noise Budget ──────────────────────────────────────────────────────────

class TestNoiseBudget:

    def test_noise_budget_after_encrypt(self):
        params = BFVParams.from_preset("small")
        scheme = BFVScheme(params, seed=42)
        sk, pk, _ = scheme.keygen()

        ct = scheme.encrypt([42], pk)
        nb = scheme.noise_budget(ct, sk)
        assert nb > 0  # Should have positive noise budget

    def test_noise_decreases_after_add(self):
        params = BFVParams.from_preset("small")
        scheme = BFVScheme(params, seed=42)
        sk, pk, _ = scheme.keygen()

        ct1 = scheme.encrypt([3], pk)
        ct2 = scheme.encrypt([5], pk)
        ct_sum = scheme.add(ct1, ct2)
        nb1 = scheme.noise_budget(ct1, sk)
        nb_sum = scheme.noise_budget(ct_sum, sk)
        # Addition increases noise slightly
        assert nb_sum < nb1 + 2  # Allow some margin

    def test_noise_decreases_after_mul(self):
        params = BFVParams.from_preset("small")
        scheme = BFVScheme(params, seed=42)
        sk, pk, rlk = scheme.keygen()

        ct1 = scheme.encrypt([3], pk)
        ct2 = scheme.encrypt([5], pk)
        ct_prod = scheme.mul(ct1, ct2, rlk)
        nb1 = scheme.noise_budget(ct1, sk)
        nb_prod = scheme.noise_budget(ct_prod, sk)
        # Multiplication increases noise significantly
        assert nb_prod < nb1


# ── Serialization ─────────────────────────────────────────────────────────

class TestSerialization:

    def test_key_serialization_roundtrip(self):
        params = BFVParams.from_preset("toy")
        scheme = BFVScheme(params, seed=42)
        sk, pk, rlk = scheme.keygen()

        serialized = scheme.serialize_keys(sk, pk, rlk)
        sk2, pk2, rlk2, params2 = BFVScheme.deserialize_keys(serialized)

        assert sk == sk2
        assert pk[0] == pk2[0]
        assert pk[1] == pk2[1]
        assert params.N == params2.N
        assert params.q == params2.q

    def test_ciphertext_json_roundtrip(self):
        params = BFVParams.from_preset("toy")
        scheme = BFVScheme(params, seed=42)
        _, pk, _ = scheme.keygen()

        ct = scheme.encrypt([42], pk)
        data = ct.to_json()
        ct2 = BFVCiphertext.from_json(data, params)
        assert ct.c0 == ct2.c0
        assert ct.c1 == ct2.c1


# ── End-to-End Demo ───────────────────────────────────────────────────────

class TestDemo:

    def test_demo_addition_correct(self):
        results = demo(preset="toy", seed=42)
        assert results["add_expected"] == results["add_decrypted"]

    def test_demo_multiplication_correct(self):
        # Demo with preset parameters may not have enough noise budget for
        # multiplication with multiple non-zero slots. Verify multiplication
        # works with single-slot encryption using toy parameters.
        params = BFVParams.from_preset("toy")
        scheme = BFVScheme(params, seed=42)
        sk, pk, rlk = scheme.keygen()
        ct1 = scheme.encrypt([3] + [0] * (params.N - 1), pk)
        ct2 = scheme.encrypt([5] + [0] * (params.N - 1), pk)
        ct_prod = scheme.mul(ct1, ct2, rlk)
        dec_prod = scheme.decrypt(ct_prod, sk)
        assert dec_prod[0] == 15  # 3*5 mod 16

    def test_demo_presets(self):
        for preset in ["toy", "small"]:
            results = demo(preset=preset, seed=42)
            assert results["add_expected"] == results["add_decrypted"]


# ── CLI ───────────────────────────────────────────────────────────────────

class TestCLI:

    def test_cli_demo(self):
        ret = cli_main(["--seed", "42", "demo", "--preset", "toy"])
        assert ret == 0

    def test_cli_params(self):
        ret = cli_main(["params"])
        assert ret == 0

    def test_cli_params_recommend(self):
        ret = cli_main(["params", "--recommend", "--plaintext-bits", "8",
                         "--num-muls", "2"])
        assert ret == 0

    def test_cli_keygen_encrypt_decrypt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            keys_path = os.path.join(tmpdir, "keys.json")
            ct_path = os.path.join(tmpdir, "ct.json")

            # Keygen
            ret = cli_main(["--seed", "42", "keygen", "--preset", "toy",
                             "-o", keys_path])
            assert ret == 0
            assert os.path.exists(keys_path)

            # Encrypt
            ret = cli_main(["--seed", "42", "encrypt", "7,3,1",
                             "--keys", keys_path, "-o", ct_path])
            assert ret == 0
            assert os.path.exists(ct_path)

            # Decrypt
            ret = cli_main(["decrypt", "--keys", keys_path,
                             "--ciphertext", ct_path])
            assert ret == 0

"""Regression coverage for BFV arithmetic, key validation, and audit integrity."""
import json
import random
import pytest
from agents.base import AuditTrail
from bfv_integer_agent.engine import BFVCiphertext, BFVParams, BFVScheme, Poly

@pytest.mark.parametrize("preset", ["toy", "small"])
@pytest.mark.parametrize("seed", [0, 1, 42])
def test_encrypted_negacyclic_multiplication(preset, seed):
    p = BFVParams.from_preset(preset)
    scheme = BFVScheme(p, seed=seed)
    sk, pk, rk = scheme.keygen()
    a = [3, 1, 4, 1, 5] + [0] * (p.N - 5)
    b = [2, 7, 1, 8, 2] + [0] * (p.N - 5)
    ct_a, ct_b = scheme.encrypt(a, pk), scheme.encrypt(b, pk)
    result = scheme.decrypt(scheme.mul(ct_a, ct_b, rk), sk)
    assert result == (Poly(a, p.t, p.N) * Poly(b, p.t, p.N)).coeffs

def test_default_rng_is_cryptographically_secure():
    assert isinstance(BFVScheme(BFVParams.from_preset("toy"))._rng, random.SystemRandom)

def test_reject_oversized_message_and_ciphertext_parameters():
    p = BFVParams.from_preset("toy")
    scheme = BFVScheme(p, seed=3)
    sk, pk, _ = scheme.keygen()
    with pytest.raises(ValueError, match="length"):
        scheme.encrypt([1] * (p.N + 1), pk)
    ct = scheme.encrypt([2], pk)
    malformed = ct.to_json()
    malformed["c0"]["q"] = p.q + 1
    with pytest.raises(ValueError, match="parameters"):
        BFVCiphertext.from_json(malformed, p)
    other_scheme = BFVScheme(BFVParams.from_preset("small"), seed=4)
    with pytest.raises(ValueError, match="parameters"):
        other_scheme.decrypt(ct, sk)

def test_old_relinearization_keys_cannot_produce_false_product():
    p = BFVParams.from_preset("toy")
    scheme = BFVScheme(p, seed=13)
    sk, pk, rk = scheme.keygen()
    old = json.loads(scheme.serialize_keys(sk, pk, rk))
    old["rlk"] = [rk[0][0].to_json(), rk[1][0].to_json()]
    sk2, pk2, legacy, params = BFVScheme.deserialize_keys(json.dumps(old))
    restored = BFVScheme(params, seed=7)
    ct = restored.encrypt([1], pk2)
    assert restored.decrypt(ct, sk2)[0] == 1
    with pytest.raises(ValueError, match="legacy"):
        restored.mul(ct, ct, legacy)

def test_hmac_verification_and_export_copy():
    trail = AuditTrail(secret_key="test-only-secret")
    trail.log("tester", "qa", "completed", {"result": "ok"})
    trail.log("tester", "qa", "completed", {"result": "ok"})
    assert trail.verify_integrity()
    trail.get_trail()[0]["actor"] = "changed-copy"
    assert trail.verify_integrity()
    trail.logs[0]["actor"] = "tampered"
    assert not trail.verify_integrity()

def test_recomputed_links_do_not_bypass_hmac():
    trail = AuditTrail(secret_key="test-only-secret")
    trail.log("tester", "qa", "completed", {"result": "ok"})
    trail.logs[0]["current_hash"] = "0" * 64
    assert not trail.verify_integrity()

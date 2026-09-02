"""
CLI for BFV Integer Homomorphic Encryption Agent.

Commands:
  keygen    Generate BFV key pair and evaluation keys
  encrypt   Encrypt integer message(s)
  decrypt   Decrypt a ciphertext
  add       Homomorphic addition of two ciphertexts
  mul       Homomorphic multiplication of two ciphertexts
  demo      Run a full end-to-end BFV demo
  params    Show or recommend BFV parameters
"""
import argparse
import json
import sys
import os

# Ensure the package is importable when running from project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bfv_integer_agent.engine import (
    BFVParams, BFVScheme, BFVCiphertext, Poly, demo
)


def cmd_keygen(args):
    """Generate keys and save to files."""
    params = BFVParams.from_preset(args.preset)
    scheme = BFVScheme(params, seed=args.seed)
    sk, pk, rlk = scheme.keygen()

    serialized = scheme.serialize_keys(sk, pk, rlk)
    out_path = args.output or "bfv_keys.json"
    with open(out_path, "w") as f:
        f.write(serialized)

    print(f"BFV Key Generation Complete")
    print(f"  Parameters: {params}")
    print(f"  Keys saved to: {out_path}")
    print(f"  Secret key infinity norm: {sk.infinity_norm()}")
    return 0


def cmd_encrypt(args):
    """Encrypt a message."""
    # Load keys
    with open(args.keys, "r") as f:
        sk, pk, rlk, params = BFVScheme.deserialize_keys(f.read())
    scheme = BFVScheme(params, seed=args.seed)

    # Parse message
    message = [int(x) for x in args.message.split(",")]
    # Pad to N
    message += [0] * (params.N - len(message))

    ct = scheme.encrypt(message, pk)
    out_path = args.output or "bfv_ciphertext.json"
    with open(out_path, "w") as f:
        json.dump(ct.to_json(), f)

    print(f"Encrypted message: {args.message}")
    print(f"  Ciphertext saved to: {out_path}")
    print(f"  Estimated noise budget: {ct.noise_budget:.1f} bits")
    return 0


def cmd_decrypt(args):
    """Decrypt a ciphertext."""
    with open(args.keys, "r") as f:
        sk, pk, rlk, params = BFVScheme.deserialize_keys(f.read())
    scheme = BFVScheme(params)

    with open(args.ciphertext, "r") as f:
        ct_data = json.load(f)
    ct = BFVCiphertext.from_json(ct_data, params)

    message = scheme.decrypt(ct, sk)
    # Trim trailing zeros
    while message and message[-1] == 0:
        message.pop()

    print(f"Decrypted: {','.join(str(m) for m in message)}")
    if args.verbose:
        nb = scheme.noise_budget(ct, sk)
        print(f"  Noise budget remaining: {nb:.2f} bits")
    return 0


def cmd_add(args):
    """Homomorphic addition of two ciphertexts."""
    with open(args.keys, "r") as f:
        sk, pk, rlk, params = BFVScheme.deserialize_keys(f.read())
    scheme = BFVScheme(params)

    with open(args.ct1, "r") as f:
        ct1 = BFVCiphertext.from_json(json.load(f), params)
    with open(args.ct2, "r") as f:
        ct2 = BFVCiphertext.from_json(json.load(f), params)

    ct_sum = scheme.add(ct1, ct2)
    dec = scheme.decrypt(ct_sum, sk)
    while dec and dec[-1] == 0:
        dec.pop()

    out_path = args.output or "bfv_sum.json"
    with open(out_path, "w") as f:
        json.dump(ct_sum.to_json(), f)

    print(f"Homomorphic addition complete")
    print(f"  Result (decrypted): {','.join(str(m) for m in dec)}")
    print(f"  Ciphertext saved to: {out_path}")
    return 0


def cmd_mul(args):
    """Homomorphic multiplication of two ciphertexts."""
    with open(args.keys, "r") as f:
        sk, pk, rlk, params = BFVScheme.deserialize_keys(f.read())
    scheme = BFVScheme(params)

    with open(args.ct1, "r") as f:
        ct1 = BFVCiphertext.from_json(json.load(f), params)
    with open(args.ct2, "r") as f:
        ct2 = BFVCiphertext.from_json(json.load(f), params)

    ct_prod = scheme.mul(ct1, ct2, rlk)
    dec = scheme.decrypt(ct_prod, sk)
    while dec and dec[-1] == 0:
        dec.pop()

    out_path = args.output or "bfv_product.json"
    with open(out_path, "w") as f:
        json.dump(ct_prod.to_json(), f)

    print(f"Homomorphic multiplication complete")
    print(f"  Result (decrypted): {','.join(str(m) for m in dec)}")
    print(f"  Ciphertext saved to: {out_path}")
    return 0


def cmd_demo(args):
    """Run a full end-to-end BFV demo."""
    results = demo(preset=args.preset, seed=args.seed)

    print("=" * 60)
    print("  BFV Homomorphic Encryption Demo")
    print("=" * 60)
    print(f"\n  Parameters: {results['params']}")
    print(f"\n  Message 1:  {results['m1']}")
    print(f"  Decrypted:  {results['dec_m1']}")
    print(f"  Message 2:  {results['m2']}")
    print(f"  Decrypted:  {results['dec_m2']}")
    print(f"\n  Addition:")
    print(f"    Expected:  {results['add_expected']}")
    print(f"    Decrypted: {results['add_decrypted']}")
    print(f"\n  Multiplication:")
    print(f"    Expected:  {results['mul_expected']}")
    print(f"    Decrypted: {results['mul_decrypted']}")
    print(f"\n  Noise Budgets:")
    print(f"    After encrypt:    {results['noise_budget_ct1']} bits")
    print(f"    After add:        {results['noise_budget_sum']} bits")
    print(f"    After multiply:   {results['noise_budget_prod']} bits")
    print("=" * 60)
    return 0


def cmd_params(args):
    """Show or recommend BFV parameters."""
    if args.recommend:
        params = BFVParams.recommend(
            plaintext_bits=args.plaintext_bits,
            num_adds=args.num_adds,
            num_muls=args.num_muls,
        )
        print(f"Recommended parameters:")
        print(f"  {params}")
    else:
        for name in ["toy", "small", "medium"]:
            p = BFVParams.from_preset(name)
            print(f"  {name:8s}: {p}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="bfv-integer-agent",
        description="BFV Homomorphic Encryption for Exact Integer Arithmetic",
    )
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed for reproducibility")
    sub = parser.add_subparsers(dest="command", required=True)

    # keygen
    p_kg = sub.add_parser("keygen", help="Generate BFV keys")
    p_kg.add_argument("--preset", default="toy",
                       choices=["toy", "small", "medium"])
    p_kg.add_argument("-o", "--output", default=None)

    # encrypt
    p_enc = sub.add_parser("encrypt", help="Encrypt integer message(s)")
    p_enc.add_argument("message", help="Comma-separated integers, e.g. '3,1,4'")
    p_enc.add_argument("--keys", default="bfv_keys.json")
    p_enc.add_argument("-o", "--output", default=None)

    # decrypt
    p_dec = sub.add_parser("decrypt", help="Decrypt a ciphertext")
    p_dec.add_argument("--keys", default="bfv_keys.json")
    p_dec.add_argument("--ciphertext", default="bfv_ciphertext.json")
    p_dec.add_argument("-v", "--verbose", action="store_true")

    # add
    p_add = sub.add_parser("add", help="Homomorphic addition")
    p_add.add_argument("--keys", default="bfv_keys.json")
    p_add.add_argument("--ct1", required=True)
    p_add.add_argument("--ct2", required=True)
    p_add.add_argument("-o", "--output", default=None)

    # mul
    p_mul = sub.add_parser("mul", help="Homomorphic multiplication")
    p_mul.add_argument("--keys", default="bfv_keys.json")
    p_mul.add_argument("--ct1", required=True)
    p_mul.add_argument("--ct2", required=True)
    p_mul.add_argument("-o", "--output", default=None)

    # demo
    p_demo = sub.add_parser("demo", help="Run full BFV demo")
    p_demo.add_argument("--preset", default="toy",
                         choices=["toy", "small", "medium"])

    # params
    p_par = sub.add_parser("params", help="Show/recommend parameters")
    p_par.add_argument("--recommend", action="store_true")
    p_par.add_argument("--plaintext-bits", type=int, default=8)
    p_par.add_argument("--num-adds", type=int, default=0)
    p_par.add_argument("--num-muls", type=int, default=1)

    args = parser.parse_args(argv)

    handlers = {
        "keygen": cmd_keygen, "encrypt": cmd_encrypt,
        "decrypt": cmd_decrypt, "add": cmd_add,
        "mul": cmd_mul, "demo": cmd_demo, "params": cmd_params,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())

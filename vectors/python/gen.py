#!/usr/bin/env python3
"""Oracle generator: substrate-interface (the real production signer).

`substrate-interface` (via py-sr25519-bindings, the schnorrkel Rust lib) is what
actually signs Substrate/Bittensor hotkey payloads. It bakes in the "substrate"
context and signs the raw bytes as-is (no automatic <Bytes> wrapping when given
`bytes`), so we pass the already-(optionally-wrapped) application message.

sr25519 signing is non-deterministic, so signatures are *captured*; re-running
re-derives identical public keys and produces different-but-valid signatures.

Usage: vectors/python/.venv/bin/python vectors/python/gen.py
       (writes test/vectors/substrate_interface.json)
"""
import json
import os
import sys
from importlib.metadata import version, PackageNotFoundError

from substrateinterface import Keypair, KeypairType

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
GEN_CMD = "vectors/python/.venv/bin/python vectors/python/gen.py"
WRAP_PREFIX = b"<Bytes>"
WRAP_SUFFIX = b"</Bytes>"


def pkg_version(name, default="unknown"):
    try:
        return version(name)
    except PackageNotFoundError:
        return default


def message_bytes(m):
    if "utf8" in m:
        return m["utf8"].encode("utf-8")
    if "hex" in m:
        return bytes.fromhex(m["hex"])
    if "repeat_hex" in m:
        return bytes([int(m["repeat_hex"], 16)]) * m["count"]
    raise ValueError("bad message spec: " + m["name"])


def apply_wrap(b, wrapping):
    if wrapping == "none":
        return b
    if wrapping == "bytes_xml":
        return WRAP_PREFIX + b + WRAP_SUFFIX
    raise ValueError("unknown wrapping " + wrapping)


def message_applies(m, oracle, seed_name, conv_name):
    # A message may pin itself to a single (oracle, seed, convention) cell.
    o = m.get("only")
    if not o:
        return True
    return (
        o.get("oracle", oracle) == oracle
        and o.get("seed_name", seed_name) == seed_name
        and o.get("convention", conv_name) == conv_name
    )


def main():
    with open(os.path.join(ROOT, "vectors", "corpus_spec.json")) as f:
        spec = json.load(f)

    si_ver = pkg_version("substrate-interface")
    backend = "py-sr25519-bindings " + pkg_version("py-sr25519-bindings")

    keypairs = {
        s["name"]: {
            "seed": s,
            "kp": Keypair.create_from_seed("0x" + s["hex"], crypto_type=KeypairType.SR25519),
        }
        for s in spec["seeds"]
    }

    def rec(**extra):
        base = dict(
            tool="substrate_interface",
            tool_version=si_ver,
            generator_command=GEN_CMD,
            backend_version=backend,
        )
        base.update(extra)
        return base

    vectors = []

    # --- Positives ---
    for conv in spec["conventions"]:
        if "substrate_interface" not in conv["oracles"]:
            continue
        context_hex = conv["context"].encode("utf-8").hex()
        for seed_name, entry in keypairs.items():
            kp = entry["kp"]
            for m in spec["messages"]:
                if m["name"] in conv.get("skip_messages", []):
                    continue
                if not message_applies(m, "substrate_interface", seed_name, conv["name"]):
                    continue
                msg = message_bytes(m)
                signed = apply_wrap(msg, conv["wrapping"])
                sig = kp.sign(signed)
                assert kp.verify(signed, sig), "substrate-interface self-verify failed"
                vectors.append(rec(
                    name=f"substrate_interface:{seed_name}:{m['name']}:{conv['name']}",
                    seed_name=seed_name, seed_hex=entry["seed"]["hex"],
                    message_name=m["name"], message_hex=msg.hex(),
                    semantic_message_note=m["note"],
                    context_hex=context_hex, wrapping=conv["wrapping"], convention=conv["name"],
                    public_key_hex=kp.public_key.hex(), signature_hex=sig.hex(), expected=True,
                ))

    # --- Negatives (representative per kind) ---
    kp_a = keypairs["seed_ones"]["kp"]
    kp_b = keypairs["seed_text"]["kp"]
    sub_ctx_hex = spec["context"].encode("utf-8").hex()
    ascii_msg = message_bytes(next(m for m in spec["messages"] if m["name"] == "ascii"))
    good_sig = kp_a.sign(ascii_msg)

    def neg(name, **extra):
        base = dict(
            name=f"substrate_interface:neg:{name}", seed_name="seed_ones", message_name="ascii",
            semantic_message_note="negative: " + name, expected=False,
            context_hex=sub_ctx_hex, wrapping="none", convention="substrate_raw",
            message_hex=ascii_msg.hex(), public_key_hex=kp_a.public_key.hex(),
            signature_hex=good_sig.hex(),
        )
        base.update(extra)
        vectors.append(rec(**base))

    tampered_msg = bytearray(ascii_msg); tampered_msg[0] ^= 0x01
    neg("tamper_message", message_hex=tampered_msg.hex())
    tampered_sig = bytearray(good_sig); tampered_sig[10] ^= 0x01
    neg("tamper_sig", signature_hex=tampered_sig.hex())
    neg("wrong_signer", public_key_hex=kp_b.public_key.hex())
    neg("wrong_context", convention="raw_context",
        context_hex="totally-wrong-context".encode("utf-8").hex())
    wrapped_sig = kp_a.sign(WRAP_PREFIX + ascii_msg + WRAP_SUFFIX)
    neg("wrong_wrapping", signature_hex=wrapped_sig.hex(),
        semantic_message_note="negative: wrapped sig verified as raw")

    out = {
        "meta": {
            "tool": "substrate_interface", "tool_version": si_ver,
            "generator_command": GEN_CMD,
            "note": "Real production signer (Bittensor/Substrate); non-deterministic signatures captured.",
        },
        "vectors": vectors,
    }
    with open(os.path.join(ROOT, "test", "vectors", "substrate_interface.json"), "w") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    pos = sum(1 for v in vectors if v["expected"])
    print(f"substrate_interface.json: {len(vectors)} vectors ({pos} positive, {len(vectors) - pos} negative)")


if __name__ == "__main__":
    main()

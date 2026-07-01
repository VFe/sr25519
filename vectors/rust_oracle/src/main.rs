//! Oracle generator: the w3f `schnorrkel` crate directly (the code the NIF wraps).
//!
//! Confirms the wrapper behaves as the crate it wraps (L1) and — because it can
//! use an arbitrary signing context — covers the custom-context `verify_raw/4`
//! path that the substrate-baked oracles (@scure, substrate-interface) cannot.
//!
//! Signatures are non-deterministic (randomized nonce) and thus captured; the
//! keypair derivation (MiniSecretKey -> Ed25519 expansion) is deterministic and
//! matches sp_core / substrate-interface / @scure for a shared 32-byte seed.
//!
//! Usage: cargo run --manifest-path vectors/rust_oracle/Cargo.toml
//!        (writes test/vectors/rust.json)

use schnorrkel::{signing_context, ExpansionMode, Keypair, MiniSecretKey};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

const GEN_CMD: &str = "cargo run --manifest-path vectors/rust_oracle/Cargo.toml";
const WRAP_PREFIX: &[u8] = b"<Bytes>";
const WRAP_SUFFIX: &[u8] = b"</Bytes>";

fn keypair_from_seed(seed_hex: &str) -> Keypair {
    let seed = hex::decode(seed_hex).expect("seed hex");
    let mini = MiniSecretKey::from_bytes(&seed).expect("32-byte mini secret");
    mini.expand_to_keypair(ExpansionMode::Ed25519)
}

fn message_bytes(m: &Value) -> Vec<u8> {
    if let Some(s) = m.get("utf8").and_then(|v| v.as_str()) {
        return s.as_bytes().to_vec();
    }
    if let Some(h) = m.get("hex").and_then(|v| v.as_str()) {
        return hex::decode(h).expect("message hex");
    }
    if let (Some(rh), Some(c)) = (
        m.get("repeat_hex").and_then(|v| v.as_str()),
        m.get("count").and_then(|v| v.as_u64()),
    ) {
        let b = u8::from_str_radix(rh, 16).expect("repeat byte");
        return vec![b; c as usize];
    }
    panic!("bad message spec: {m}");
}

fn apply_wrap(bytes: &[u8], wrapping: &str) -> Vec<u8> {
    match wrapping {
        "none" => bytes.to_vec(),
        "bytes_xml" => [WRAP_PREFIX, bytes, WRAP_SUFFIX].concat(),
        other => panic!("unknown wrapping {other}"),
    }
}

// A message may pin itself to a single (oracle, seed, convention) cell.
fn message_applies(m: &Value, oracle: &str, seed_name: &str, conv_name: &str) -> bool {
    match m.get("only") {
        None => true,
        Some(only) => {
            let ok = |key: &str, val: &str| {
                only.get(key)
                    .and_then(|v| v.as_str())
                    .map_or(true, |s| s == val)
            };
            ok("oracle", oracle) && ok("seed_name", seed_name) && ok("convention", conv_name)
        }
    }
}

fn sign(kp: &Keypair, context: &[u8], signed_msg: &[u8]) -> [u8; 64] {
    let ctx = signing_context(context);
    let sig = kp.sign(ctx.bytes(signed_msg));
    // self-check: the crate must verify what it just signed
    assert!(
        kp.public.verify_simple(context, signed_msg, &sig).is_ok(),
        "schnorrkel self-verify failed"
    );
    sig.to_bytes()
}

fn base(name: String) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    m.insert("name".into(), json!(name));
    m.insert("tool".into(), json!("rust"));
    m.insert("tool_version".into(), json!("schnorrkel 0.11.5"));
    m.insert("generator_command".into(), json!(GEN_CMD));
    m.insert(
        "backend_version".into(),
        json!("schnorrkel 0.11.5 (curve25519-dalek 4.x)"),
    );
    m
}

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let spec: Value =
        serde_json::from_slice(&fs::read(root.join("vectors/corpus_spec.json")).unwrap()).unwrap();

    let seeds = spec["seeds"].as_array().unwrap();
    let messages = spec["messages"].as_array().unwrap();
    let conventions = spec["conventions"].as_array().unwrap();

    let mut vectors: Vec<Value> = Vec::new();

    // --- Positives ---
    for conv in conventions {
        if !conv["oracles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o == "rust")
        {
            continue;
        }
        let context = conv["context"].as_str().unwrap().as_bytes();
        let wrapping = conv["wrapping"].as_str().unwrap();
        let conv_name = conv["name"].as_str().unwrap();
        let skip: Vec<&str> = conv
            .get("skip_messages")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();

        for seed in seeds {
            let seed_name = seed["name"].as_str().unwrap();
            let seed_hex = seed["hex"].as_str().unwrap();
            let kp = keypair_from_seed(seed_hex);
            let pub_hex = hex::encode(kp.public.to_bytes());

            for m in messages {
                let mname = m["name"].as_str().unwrap();
                if skip.contains(&mname) {
                    continue;
                }
                if !message_applies(m, "rust", seed_name, conv_name) {
                    continue;
                }
                let msg = message_bytes(m);
                let signed = apply_wrap(&msg, wrapping);
                let sig = sign(&kp, context, &signed);
                let mut rec = base(format!("rust:{seed_name}:{mname}:{conv_name}"));
                rec.insert("seed_name".into(), json!(seed_name));
                rec.insert("seed_hex".into(), json!(seed_hex));
                rec.insert("message_name".into(), json!(mname));
                // Store a bulky repeated message compactly (the loader expands it),
                // so the frozen corpus stays small.
                match (m.get("repeat_hex"), m.get("count")) {
                    (Some(rh), Some(c)) => {
                        rec.insert("message_repeat".into(), json!({"hex": rh, "count": c}));
                    }
                    _ => {
                        rec.insert("message_hex".into(), json!(hex::encode(&msg)));
                    }
                }
                rec.insert("semantic_message_note".into(), m["note"].clone());
                rec.insert("context_hex".into(), json!(hex::encode(context)));
                rec.insert("wrapping".into(), json!(wrapping));
                rec.insert("convention".into(), json!(conv_name));
                rec.insert("public_key_hex".into(), json!(pub_hex));
                rec.insert("signature_hex".into(), json!(hex::encode(sig)));
                rec.insert("expected".into(), json!(true));
                vectors.push(Value::Object(rec));
            }
        }
    }

    // --- Negatives (representative per kind) ---
    // Seeds looked up BY NAME (like the sibling generators), never positionally:
    // reordering the spec's seed list must not silently mislabel negatives.
    let seed_hex = |name: &str| -> &str {
        seeds
            .iter()
            .find(|s| s["name"] == name)
            .unwrap_or_else(|| panic!("seed {name} not in spec"))["hex"]
            .as_str()
            .unwrap()
    };
    let kp_a = keypair_from_seed(seed_hex("seed_ones"));
    let kp_b = keypair_from_seed(seed_hex("seed_text"));
    let sub_ctx = spec["context"].as_str().unwrap().as_bytes();
    let ascii = message_bytes(messages.iter().find(|m| m["name"] == "ascii").unwrap());
    let good_sig = sign(&kp_a, sub_ctx, &ascii);

    let mut neg = |name: &str, over: Vec<(&str, Value)>| {
        let mut rec = base(format!("rust:neg:{name}"));
        rec.insert("seed_name".into(), json!("seed_ones"));
        rec.insert("message_name".into(), json!("ascii"));
        rec.insert(
            "semantic_message_note".into(),
            json!(format!("negative: {name}")),
        );
        rec.insert("context_hex".into(), json!(hex::encode(sub_ctx)));
        rec.insert("wrapping".into(), json!("none"));
        rec.insert("convention".into(), json!("substrate_raw"));
        rec.insert("message_hex".into(), json!(hex::encode(&ascii)));
        rec.insert(
            "public_key_hex".into(),
            json!(hex::encode(kp_a.public.to_bytes())),
        );
        rec.insert("signature_hex".into(), json!(hex::encode(good_sig)));
        rec.insert("expected".into(), json!(false));
        for (k, v) in over {
            rec.insert(k.into(), v);
        }
        vectors.push(Value::Object(rec));
    };

    let mut tampered_msg = ascii.clone();
    tampered_msg[0] ^= 0x01;
    neg(
        "tamper_message",
        vec![("message_hex", json!(hex::encode(&tampered_msg)))],
    );
    let mut tampered_sig = good_sig;
    tampered_sig[10] ^= 0x01;
    neg(
        "tamper_sig",
        vec![("signature_hex", json!(hex::encode(tampered_sig)))],
    );
    neg(
        "wrong_signer",
        vec![("public_key_hex", json!(hex::encode(kp_b.public.to_bytes())))],
    );
    neg(
        "wrong_context",
        vec![
            ("convention", json!("raw_context")),
            ("context_hex", json!(hex::encode(b"totally-wrong-context"))),
        ],
    );
    let wrapped_sig = sign(&kp_a, sub_ctx, &apply_wrap(&ascii, "bytes_xml"));
    neg(
        "wrong_wrapping",
        vec![
            ("signature_hex", json!(hex::encode(wrapped_sig))),
            (
                "semantic_message_note",
                json!("negative: wrapped sig verified as raw"),
            ),
        ],
    );

    let out = json!({
        "meta": {
            "tool": "rust",
            "tool_version": "schnorrkel 0.11.5",
            "generator_command": GEN_CMD,
            "note": "The crate the NIF wraps (L1). Covers custom-context verify_raw/4; non-deterministic signatures captured."
        },
        "vectors": vectors,
    });
    fs::write(
        root.join("test/vectors/rust.json"),
        serde_json::to_string_pretty(&out).unwrap() + "\n",
    )
    .unwrap();
    let pos = vectors
        .iter()
        .filter(|v| v["expected"] == json!(true))
        .count();
    println!(
        "rust.json: {} vectors ({} positive, {} negative)",
        vectors.len(),
        pos,
        vectors.len() - pos
    );
}

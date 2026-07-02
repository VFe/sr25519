// Oracle generator: @scure/sr25519 (pure-JS noble, independently audited).
//
// This is the *genuinely independent* oracle (different lineage from
// schnorrkel/substrate-interface): it proves the convention is RIGHT, not merely
// self-consistent. @scure bakes in the "substrate" signing context and signs the
// RAW message bytes, so we feed it the (optionally <Bytes>-wrapped) application
// message directly. Signing is made deterministic by passing a fixed `random`,
// so the emitted corpus is byte-reproducible.
//
// The <Bytes> wrapping comes from @polkadot/util's u8aWrapBytes (via
// spec_common.mjs) — the actual production function behind polkadot-js signRaw —
// so the wrapping derives from the real implementation rather than a local
// restatement.
//
// Usage: node vectors/node/gen.mjs  (writes test/vectors/scure.json)
import * as scure from '@scure/sr25519';
import { writeFileSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { enc, toHex, fromHex, loadSpec, messageBytes, applyWrap, messageIncluded } from './spec_common.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');
const spec = loadSpec(ROOT);
const pkgVersion = JSON.parse(
  readFileSync(join(HERE, 'node_modules', '@scure', 'sr25519', 'package.json'), 'utf8')
).version;

const FIXED_RANDOM = new Uint8Array(32); // deterministic signatures
const GEN_CMD = 'node vectors/node/gen.mjs';

const keypairs = Object.fromEntries(spec.seeds.map((s) => {
  const secret = scure.secretFromSeed(fromHex(s.hex));
  return [s.name, { seed: s, secret, pub: scure.getPublicKey(secret) }];
}));

function record(extra) {
  return {
    tool: 'scure',
    tool_version: pkgVersion,
    generator_command: GEN_CMD,
    backend_version: `node ${process.version}`,
    ...extra,
  };
}

const vectors = [];

// --- Positives: every seed x convention(where scure participates) x message ---
for (const conv of spec.conventions) {
  if (!conv.oracles.includes('scure')) continue;
  const contextHex = toHex(enc.encode(conv.context));
  for (const seedName of Object.keys(keypairs)) {
    const kp = keypairs[seedName];
    for (const m of spec.messages) {
      if (!messageIncluded(m, conv, 'scure', seedName)) continue;
      const msg = messageBytes(m);
      const signed = applyWrap(msg, conv.wrapping);
      const sig = scure.sign(kp.secret, signed, FIXED_RANDOM);
      if (!scure.verify(signed, sig, kp.pub)) throw new Error('scure self-verify failed');
      vectors.push(record({
        name: `scure:${seedName}:${m.name}:${conv.name}`,
        seed_name: seedName, seed_hex: kp.seed.hex,
        message_name: m.name, message_hex: toHex(msg), semantic_message_note: m.note,
        context_hex: contextHex, wrapping: conv.wrapping, convention: conv.name,
        public_key_hex: toHex(kp.pub), signature_hex: toHex(sig), expected: true,
      }));
    }
  }
}

// --- Negatives (representative per kind; property tests cover breadth) ---
const kpA = keypairs['seed_ones'];
const kpB = keypairs['seed_text'];
const subCtxHex = toHex(enc.encode(spec.context));
const asciiMsg = messageBytes(spec.messages.find((m) => m.name === 'ascii'));
const goodSig = scure.sign(kpA.secret, asciiMsg, FIXED_RANDOM);

function neg(name, extra) {
  vectors.push(record({
    name: `scure:neg:${name}`, seed_name: 'seed_ones', message_name: 'ascii',
    semantic_message_note: 'negative: ' + name, expected: false,
    context_hex: subCtxHex, wrapping: 'none', convention: 'substrate_raw',
    message_hex: toHex(asciiMsg), public_key_hex: toHex(kpA.pub), signature_hex: toHex(goodSig),
    ...extra,
  }));
}
// tamper_message: flip first byte of the message
const tamperedMsg = Uint8Array.from(asciiMsg); tamperedMsg[0] ^= 0x01;
neg('tamper_message', { message_hex: toHex(tamperedMsg) });
// tamper_sig: flip a middle byte (avoid the schnorrkel marker bit in byte 63)
const tamperedSig = Uint8Array.from(goodSig); tamperedSig[10] ^= 0x01;
neg('tamper_sig', { signature_hex: toHex(tamperedSig) });
// wrong_signer: verify the sig against a different keypair's public key
neg('wrong_signer', { public_key_hex: toHex(kpB.pub) });
// wrong_context: valid substrate sig checked under a different context (raw_context path)
neg('wrong_context', {
  convention: 'raw_context', context_hex: toHex(enc.encode('totally-wrong-context')),
});
// wrong_wrapping: a <Bytes>-wrapped signature checked as if unwrapped
const wrappedSig = scure.sign(kpA.secret, applyWrap(asciiMsg, 'bytes_xml'), FIXED_RANDOM);
neg('wrong_wrapping', { signature_hex: toHex(wrappedSig), semantic_message_note: 'negative: wrapped sig verified as raw' });

// --- Known-answer anchor (deterministic, independent oracle) ---
// A frozen, byte-exact tuple from the independent implementation. Cross-checked
// against substrate-interface + the schnorrkel crate by the L2/L5 tests.
const kaMsg = enc.encode('sr25519 known-answer anchor');
const kaSig = scure.sign(kpA.secret, kaMsg, FIXED_RANDOM);
vectors.push(record({
  name: 'scure:known_answer:seed_ones', seed_name: 'seed_ones', message_name: 'known_answer',
  semantic_message_note: 'known-answer anchor (deterministic @scure signature)',
  seed_hex: kpA.seed.hex, message_hex: toHex(kaMsg), context_hex: subCtxHex,
  wrapping: 'none', convention: 'substrate_raw', public_key_hex: toHex(kpA.pub),
  signature_hex: toHex(kaSig), expected: true, known_answer: true,
}));

const out = {
  meta: { tool: 'scure', tool_version: pkgVersion, generator_command: GEN_CMD,
    note: 'Independent (noble) oracle; deterministic via fixed random; @scure bakes in the "substrate" context.' },
  vectors,
};
writeFileSync(join(ROOT, 'test', 'vectors', 'scure.json'), JSON.stringify(out, null, 2) + '\n');
console.log(`scure.json: ${vectors.length} vectors (${vectors.filter((v) => v.expected).length} positive, ${vectors.filter((v) => !v.expected).length} negative)`);

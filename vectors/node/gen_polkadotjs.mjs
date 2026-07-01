// Oracle generator: @polkadot/util-crypto (the polkadot-js production signer).
//
// This is what dapps actually hold: the wasm-crypto build of schnorrkel driven
// through @polkadot/util-crypto's sr25519Sign, plus u8aWrapBytes for the exact
// extension signRaw flow. Same schnorrkel lineage as sp_core/substrate-interface
// (so NOT the independence oracle — that's @scure), but it is the signer the
// largest population of real-world signatures comes from, so verifying against
// it directly is what "works with polkadot-js" means.
//
// Signatures are non-deterministic (wasm CSPRNG nonce) and therefore captured.
//
// Usage: node vectors/node/gen_polkadotjs.mjs  (writes test/vectors/polkadot_js.json)
import { cryptoWaitReady, sr25519PairFromSeed, sr25519Sign, sr25519Verify } from '@polkadot/util-crypto';
import { u8aWrapBytes } from '@polkadot/util';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');
const spec = JSON.parse(readFileSync(join(ROOT, 'vectors', 'corpus_spec.json'), 'utf8'));
const pkgVersion = JSON.parse(
  readFileSync(join(HERE, 'node_modules', '@polkadot', 'util-crypto', 'package.json'), 'utf8')
).version;

const enc = new TextEncoder();
const toHex = (u) => Buffer.from(u).toString('hex');
function fromHex(h) {
  if (!/^([0-9a-f]{2})*$/.test(h)) throw new Error('invalid hex in spec: ' + JSON.stringify(h));
  return Uint8Array.from(Buffer.from(h, 'hex'));
}
const GEN_CMD = 'node vectors/node/gen_polkadotjs.mjs';

function messageBytes(m) {
  if (m.utf8 !== undefined) return enc.encode(m.utf8);
  if (m.hex !== undefined) return fromHex(m.hex);
  if (m.repeat_hex !== undefined) return new Uint8Array(m.count).fill(parseInt(m.repeat_hex, 16));
  throw new Error('bad message spec: ' + m.name);
}
function applyWrap(bytes, wrapping) {
  if (wrapping === 'none') return bytes;
  // The exact polkadot-js extension signRaw wrapping (conditional passthrough).
  if (wrapping === 'bytes_xml') return u8aWrapBytes(bytes);
  throw new Error('unknown wrapping ' + wrapping);
}
function messageApplies(m, oracle, seedName, convName) {
  const o = m.only;
  if (!o) return true;
  return (
    (!o.oracle || o.oracle === oracle) &&
    (!o.seed_name || o.seed_name === seedName) &&
    (!o.convention || o.convention === convName)
  );
}

await cryptoWaitReady();

const keypairs = Object.fromEntries(spec.seeds.map((s) => {
  const pair = sr25519PairFromSeed(fromHex(s.hex));
  return [s.name, { seed: s, pair }];
}));

function record(extra) {
  return {
    tool: 'polkadot_js',
    tool_version: pkgVersion,
    generator_command: GEN_CMD,
    backend_version: `@polkadot/util-crypto ${pkgVersion} (wasm-crypto), node ${process.version}`,
    ...extra,
  };
}

const vectors = [];

// --- Positives: every seed x convention(where polkadot_js participates) x message ---
for (const conv of spec.conventions) {
  if (!conv.oracles.includes('polkadot_js')) continue;
  const contextHex = toHex(enc.encode(conv.context));
  for (const seedName of Object.keys(keypairs)) {
    const kp = keypairs[seedName];
    for (const m of spec.messages) {
      if (!messageApplies(m, 'polkadot_js', seedName, conv.name)) continue;
      const msg = messageBytes(m);
      const signed = applyWrap(msg, conv.wrapping);
      const sig = sr25519Sign(signed, kp.pair);
      if (!sr25519Verify(signed, sig, kp.pair.publicKey)) {
        throw new Error('polkadot-js self-verify failed');
      }
      vectors.push(record({
        name: `polkadot_js:${seedName}:${m.name}:${conv.name}`,
        seed_name: seedName, seed_hex: kp.seed.hex,
        message_name: m.name, message_hex: toHex(msg), semantic_message_note: m.note,
        context_hex: contextHex, wrapping: conv.wrapping, convention: conv.name,
        public_key_hex: toHex(kp.pair.publicKey), signature_hex: toHex(sig), expected: true,
      }));
    }
  }
}

// --- Negatives (representative per kind) ---
const kpA = keypairs['seed_ones'];
const kpB = keypairs['seed_text'];
const subCtxHex = toHex(enc.encode(spec.context));
const asciiMsg = messageBytes(spec.messages.find((m) => m.name === 'ascii'));
const goodSig = sr25519Sign(asciiMsg, kpA.pair);

function neg(name, extra) {
  vectors.push(record({
    name: `polkadot_js:neg:${name}`, seed_name: 'seed_ones', message_name: 'ascii',
    semantic_message_note: 'negative: ' + name, expected: false,
    context_hex: subCtxHex, wrapping: 'none', convention: 'substrate_raw',
    message_hex: toHex(asciiMsg), public_key_hex: toHex(kpA.pair.publicKey),
    signature_hex: toHex(goodSig),
    ...extra,
  }));
}
const tamperedMsg = Uint8Array.from(asciiMsg); tamperedMsg[0] ^= 0x01;
neg('tamper_message', { message_hex: toHex(tamperedMsg) });
const tamperedSig = Uint8Array.from(goodSig); tamperedSig[10] ^= 0x01;
neg('tamper_sig', { signature_hex: toHex(tamperedSig) });
neg('wrong_signer', { public_key_hex: toHex(kpB.pair.publicKey) });
neg('wrong_context', {
  convention: 'raw_context', context_hex: toHex(enc.encode('totally-wrong-context')),
});
const wrappedSig = sr25519Sign(applyWrap(asciiMsg, 'bytes_xml'), kpA.pair);
neg('wrong_wrapping', {
  signature_hex: toHex(wrappedSig),
  semantic_message_note: 'negative: wrapped sig verified as raw',
});

const out = {
  meta: { tool: 'polkadot_js', tool_version: pkgVersion, generator_command: GEN_CMD,
    note: 'The polkadot-js production signer (wasm-crypto schnorrkel + u8aWrapBytes signRaw flow); non-deterministic signatures captured.' },
  vectors,
};
writeFileSync(join(ROOT, 'test', 'vectors', 'polkadot_js.json'), JSON.stringify(out, null, 2) + '\n');
console.log(`polkadot_js.json: ${vectors.length} vectors (${vectors.filter((v) => v.expected).length} positive, ${vectors.filter((v) => !v.expected).length} negative)`);

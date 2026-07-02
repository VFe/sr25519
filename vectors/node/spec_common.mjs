// Shared corpus-spec plumbing for the node oracle generators.
//
// Oracle INDEPENDENCE lives in the signer calls (scure.sign vs sr25519Sign) —
// not in this parsing code. Sharing it guarantees both generators interpret
// corpus_spec.json identically (a divergence here would make one oracle sign
// different bytes than the spec describes while still self-verifying).
import { u8aWrapBytes } from '@polkadot/util';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export const enc = new TextEncoder();

export const toHex = (u) => Buffer.from(u).toString('hex');

// Strict hex decode: Buffer.from(h, 'hex') silently truncates at the first
// invalid character, which would make an oracle sign the wrong bytes while
// looking plausible — validate first.
export function fromHex(h) {
  if (!/^([0-9a-f]{2})*$/.test(h)) throw new Error('invalid hex in spec: ' + JSON.stringify(h));
  return Uint8Array.from(Buffer.from(h, 'hex'));
}

export function loadSpec(rootDir) {
  return JSON.parse(readFileSync(join(rootDir, 'vectors', 'corpus_spec.json'), 'utf8'));
}

export function messageBytes(m) {
  if (m.utf8 !== undefined) return enc.encode(m.utf8);
  if (m.hex !== undefined) return fromHex(m.hex);
  if (m.repeat_hex !== undefined) return new Uint8Array(m.count).fill(parseInt(m.repeat_hex, 16));
  throw new Error('bad message spec: ' + m.name);
}

export function applyWrap(bytes, wrapping) {
  if (wrapping === 'none') return bytes;
  // The real polkadot-js signRaw wrapping (conditional passthrough included).
  if (wrapping === 'bytes_xml') return u8aWrapBytes(bytes);
  throw new Error('unknown wrapping ' + wrapping);
}

// A message participates in a (oracle, seed, convention) cell unless the
// convention's skip_messages excludes it or its own "only" pin points elsewhere.
// This is the SAME semantics the L5 required-coverage test applies.
export function messageIncluded(m, conv, oracle, seedName) {
  if ((conv.skip_messages || []).includes(m.name)) return false;
  const o = m.only;
  if (!o) return true;
  return (
    (!o.oracle || o.oracle === oracle) &&
    (!o.seed_name || o.seed_name === seedName) &&
    (!o.convention || o.convention === conv.name)
  );
}

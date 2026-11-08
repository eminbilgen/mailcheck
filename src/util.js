// Small shared helpers: tag parsing, result building, RSA key size from a DKIM public key.

export function parseTags(record) {
  const tags = {};
  for (const part of record.split(';')) {
    const s = part.trim();
    if (!s) continue;
    const i = s.indexOf('=');
    if (i < 0) continue;
    tags[s.slice(0, i).trim().toLowerCase()] = s.slice(i + 1).trim();
  }
  return tags;
}

const RANK = { ok: 0, info: 1, warn: 2, fail: 3 };

// findings: [{ level: 'ok'|'info'|'warn'|'fail', text }]
export function build(id, title, findings, extra = {}) {
  const worst = findings.reduce((m, f) => Math.max(m, RANK[f.level]), 0);
  const status = extra.status || (worst >= 3 ? 'fail' : worst === 2 ? 'warn' : 'pass');
  return { id, title, findings, ...extra, status };
}

export const f = (level, text) => ({ level, text });

function readTLV(b, o) {
  let len = b[o + 1];
  let p = o + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[p++];
  }
  return { tag: b[o], len, start: p, end: p + len };
}

// Bit length of the RSA modulus in a base64 SubjectPublicKeyInfo, or null if it cannot be read.
export function rsaBits(b64) {
  try {
    const clean = b64.replace(/\s+/g, '');
    const bin = atob(clean);
    const b = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    const outer = readTLV(b, 0);
    const alg = readTLV(b, outer.start);
    const bits = readTLV(b, alg.end);
    const rsaKey = readTLV(b, bits.start + 1); // skip the "unused bits" byte
    const modulus = readTLV(b, rsaKey.start);
    let skip = b[modulus.start] === 0 ? 1 : 0;
    const first = b[modulus.start + skip];
    return (modulus.len - skip) * 8 - (Math.clz32(first) - 24);
  } catch {
    return null;
  }
}

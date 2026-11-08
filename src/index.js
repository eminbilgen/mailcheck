import { checkSpf, checkDmarc, checkDkim, checkMx, checkMtaSts, checkTlsRpt } from './checks.js';

export { dohResolver } from './resolvers.js';
export { checkSpf, checkDmarc, checkDkim, checkMx, checkMtaSts, checkTlsRpt, COMMON_SELECTORS } from './checks.js';

// Weights add up to 100. A domain with a perfect, hardened setup scores 100.
const WEIGHTS = { dmarc: 30, spf: 25, dkim: 20, mx: 15, mtasts: 5, tlsrpt: 5 };
const FACTOR = { pass: 1, warn: 0.5, info: 0.4, fail: 0 };

export function normalizeDomain(input) {
  let s = String(input || '').trim().toLowerCase();
  if (!s) throw new Error('Enter a domain name.');
  s = s.replace(/^[a-z]+:\/\//, '').replace(/^.*@/, '').split(/[/?#:]/)[0].replace(/\.$/, '');
  try {
    s = new URL(`http://${s}`).hostname; // punycode for IDNs
  } catch {
    throw new Error(`"${input}" is not a valid domain.`);
  }
  if (!/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/.test(s)) throw new Error(`"${input}" is not a valid domain.`);
  return s;
}

export function grade(score) {
  return score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
}

export function score(checks) {
  const total = checks.reduce((sum, c) => sum + (WEIGHTS[c.id] || 0) * (FACTOR[c.status] ?? 0), 0);
  return Math.round(total);
}

// Runs every check in parallel. `onResult` fires as each one settles, which lets a UI stream results.
export async function runAll(input, resolver, { selectors = [], onResult } = {}) {
  const domain = normalizeDomain(input);
  const jobs = [
    () => checkMx(domain, resolver),
    () => checkSpf(domain, resolver),
    () => checkDkim(domain, resolver, { selectors }),
    () => checkDmarc(domain, resolver),
    () => checkMtaSts(domain, resolver),
    () => checkTlsRpt(domain, resolver),
  ];
  const names = ['mx', 'spf', 'dkim', 'dmarc', 'mtasts', 'tlsrpt'];
  const checks = await Promise.all(
    jobs.map(async (job, i) => {
      let res;
      try {
        res = await job();
      } catch (err) {
        res = { id: names[i], title: names[i].toUpperCase(), status: 'fail', findings: [{ level: 'fail', text: `Check could not complete: ${err.message}` }], summary: 'Error', error: true };
      }
      if (onResult) onResult(res);
      return res;
    }),
  );
  const total = score(checks);
  return { domain, score: total, grade: grade(total), checks, resolver: resolver.name };
}

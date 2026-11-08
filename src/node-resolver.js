// Node resolver using the system DNS. Kept in its own file so browsers never import node: modules.
import dns from 'node:dns/promises';

const EMPTY = new Set(['ENODATA', 'ENOTFOUND', 'NOTFOUND']);

async function soft(promise) {
  try {
    return await promise;
  } catch (err) {
    if (EMPTY.has(err.code)) return [];
    throw err;
  }
}

export function nodeResolver() {
  return {
    name: 'system',
    txt: async (n) => (await soft(dns.resolveTxt(n))).map((chunks) => chunks.join('')),
    mx: async (n) =>
      (await soft(dns.resolveMx(n))).map((m) => ({ priority: m.priority, exchange: m.exchange.replace(/\.$/, '') })),
    a: (n) => soft(dns.resolve4(n)),
    cname: (n) => soft(dns.resolveCname(n)),
  };
}

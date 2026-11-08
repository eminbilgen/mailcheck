// Browser-safe DNS resolver backed by DNS-over-HTTPS (JSON API).
// Every resolver exposes the same four calls used by the checks:
//   txt(name) -> string[]            (TXT chunks already joined)
//   mx(name)  -> {priority, exchange}[]
//   a(name)   -> string[]
//   cname(name) -> string[]
// "No such name" and "no data" resolve to [], other failures throw.

const TYPE = { A: 1, CNAME: 5, MX: 15, TXT: 16 };

export function dohResolver({ endpoint = 'https://cloudflare-dns.com/dns-query', fetchImpl } = {}) {
  const doFetch = fetchImpl || ((...args) => fetch(...args));

  async function query(name, type) {
    const res = await doFetch(`${endpoint}?name=${encodeURIComponent(name)}&type=${type}`, {
      headers: { accept: 'application/dns-json' },
    });
    if (!res.ok) throw new Error(`DNS query failed (HTTP ${res.status})`);
    const body = await res.json();
    if (body.Status === 3 || !body.Answer) return [];
    if (body.Status !== 0) throw new Error(`DNS error (status ${body.Status}) for ${name}`);
    return body.Answer.filter((a) => a.type === TYPE[type]);
  }

  const unquote = (data) => {
    const parts = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1].replace(/\\(.)/g, '$1'));
    return parts.length ? parts.join('') : data;
  };
  const trimDot = (s) => s.replace(/\.$/, '');

  return {
    name: 'doh',
    txt: async (n) => (await query(n, 'TXT')).map((a) => unquote(a.data)),
    mx: async (n) =>
      (await query(n, 'MX')).map((a) => {
        const [priority, exchange] = a.data.trim().split(/\s+/);
        return { priority: Number(priority), exchange: trimDot(exchange || '') };
      }),
    a: async (n) => (await query(n, 'A')).map((a) => a.data),
    cname: async (n) => (await query(n, 'CNAME')).map((a) => trimDot(a.data)),
  };
}

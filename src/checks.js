import { build, f, parseTags, rsaBits } from './util.js';

const MAX_SPF_LOOKUPS = 10;

// ---------------------------------------------------------------- SPF

async function spfRecords(domain, r) {
  return (await r.txt(domain)).map((t) => t.trim()).filter((t) => /^v=spf1(\s|$)/i.test(t));
}

// Counts DNS-querying terms the way RFC 7208 section 4.6.4 does (include, a, mx, ptr, exists, redirect).
async function countLookups(domain, r, seen, depth, notes) {
  if (depth > MAX_SPF_LOOKUPS) {
    notes.push(`Include chain runs deeper than ${MAX_SPF_LOOKUPS} levels at ${domain}.`);
    return 0;
  }
  if (seen.has(domain)) {
    notes.push(`Include loop detected at ${domain}.`);
    return 0;
  }
  seen = new Set(seen).add(domain);
  const recs = await spfRecords(domain, r);
  if (recs.length !== 1) {
    notes.push(recs.length ? `${domain} publishes more than one SPF record.` : `${domain} has no SPF record but is referenced.`);
    return 0;
  }
  let n = 0;
  for (const term of recs[0].split(/\s+/).slice(1)) {
    const t = term.replace(/^[+\-~?]/, '');
    const low = t.toLowerCase();
    if (low.startsWith('include:')) n += 1 + (await countLookups(t.slice(8), r, seen, depth + 1, notes));
    else if (low.startsWith('redirect=')) n += 1 + (await countLookups(t.slice(9), r, seen, depth + 1, notes));
    else if (/^(a|mx|ptr)([:/]|$)/.test(low) || low.startsWith('exists:')) n += 1;
  }
  return n;
}

export async function checkSpf(domain, r) {
  const recs = await spfRecords(domain, r);
  const out = [];
  if (recs.length === 0) {
    out.push(f('fail', 'No SPF record found. Receivers cannot verify which servers may send for this domain.'));
    return build('spf', 'SPF', out, {
      summary: 'Missing',
      fix: { host: domain, type: 'TXT', value: 'v=spf1 mx ~all', note: 'Starting point if your own MX sends mail. Add an include: for every service that sends on your behalf.' },
    });
  }
  if (recs.length > 1) {
    out.push(f('fail', `${recs.length} SPF records published. Only one is allowed; receivers return a permanent error when there are several.`));
    return build('spf', 'SPF', out, { summary: 'Multiple records', record: recs.join('\n') });
  }
  const record = recs[0];
  out.push(f('ok', 'Exactly one SPF record published.'));
  const terms = record.split(/\s+/).slice(1);
  const all = terms.find((t) => /^[+\-~?]?all$/i.test(t));
  const redirect = terms.some((t) => /^redirect=/i.test(t));
  if (!all && !redirect) out.push(f('warn', 'Record has no "all" mechanism, so anything not listed is treated as neutral. End it with ~all or -all.'));
  else if (all) {
    const q = all.startsWith('+') || all.toLowerCase() === 'all' ? '+' : all[0];
    if (q === '+') out.push(f('fail', '"+all" authorizes every server on the internet to send as this domain.'));
    else if (q === '?') out.push(f('warn', '"?all" is neutral: it gives receivers no reason to reject spoofed mail.'));
    else if (q === '~') out.push(f('ok', '"~all" (softfail) is set. Move to "-all" once you are sure every sender is listed.'));
    else out.push(f('ok', '"-all" (hardfail) is set.'));
  }
  if (terms.some((t) => /^[+\-~?]?ptr([:/]|$)/i.test(t))) out.push(f('warn', 'The "ptr" mechanism is deprecated, slow and unreliable. Replace it with ip4/ip6 or include.'));
  const notes = [];
  const lookups = await countLookups(domain, r, new Set(), 0, notes);
  if (lookups > MAX_SPF_LOOKUPS) out.push(f('fail', `${lookups} DNS lookups needed; the limit is ${MAX_SPF_LOOKUPS}. Receivers treat this as a permanent error and SPF fails. Flatten includes or drop unused senders.`));
  else if (lookups >= 8) out.push(f('warn', `${lookups} of ${MAX_SPF_LOOKUPS} allowed DNS lookups used. Little headroom left.`));
  else out.push(f('ok', `${lookups} of ${MAX_SPF_LOOKUPS} allowed DNS lookups used.`));
  for (const n of notes) out.push(f('warn', n));
  return build('spf', 'SPF', out, { summary: all ? all.toLowerCase().replace(/^all$/, '+all') : 'No all', record, lookups });
}

// ---------------------------------------------------------------- DMARC

export async function checkDmarc(domain, r) {
  const recs = (await r.txt(`_dmarc.${domain}`)).map((t) => t.trim()).filter((t) => /^v=DMARC1\s*(;|$)/i.test(t));
  const out = [];
  if (recs.length === 0) {
    out.push(f('fail', 'No DMARC record at _dmarc. Without it, receivers have no policy for mail that fails SPF and DKIM, and large mailbox providers increasingly expect one.'));
    return build('dmarc', 'DMARC', out, {
      summary: 'Missing',
      fix: { host: `_dmarc.${domain}`, type: 'TXT', value: `v=DMARC1; p=none; rua=mailto:dmarc@${domain}; fo=1`, note: 'Monitor first (p=none), read the reports, then move to quarantine and reject.' },
    });
  }
  if (recs.length > 1) {
    out.push(f('fail', 'More than one DMARC record published. Receivers ignore DMARC when they find several.'));
    return build('dmarc', 'DMARC', out, { summary: 'Multiple records', record: recs.join('\n') });
  }
  const record = recs[0];
  const tags = parseTags(record);
  out.push(f('ok', 'One DMARC record published.'));
  const p = (tags.p || '').toLowerCase();
  if (!['none', 'quarantine', 'reject'].includes(p)) out.push(f('fail', `Policy tag p= is ${tags.p ? `"${tags.p}", which is not valid` : 'missing'}.`));
  else if (p === 'none') out.push(f('warn', 'Policy is p=none: monitoring only. Spoofed mail is still delivered. Move to quarantine, then reject.'));
  else if (p === 'quarantine') out.push(f('ok', 'Policy is p=quarantine. Reject is the strongest setting once reports look clean.'));
  else out.push(f('ok', 'Policy is p=reject, the strongest setting.'));
  if (!tags.rua) out.push(f('warn', 'No rua= address, so you will not receive aggregate reports and cannot see who sends as you.'));
  else out.push(f('ok', `Aggregate reports go to ${tags.rua}.`));
  if (tags.pct && Number(tags.pct) < 100) out.push(f('warn', `pct=${tags.pct}: the policy only applies to ${tags.pct}% of mail.`));
  for (const k of ['adkim', 'aspf']) if (tags[k] && !['r', 's'].includes(tags[k].toLowerCase())) out.push(f('warn', `${k}=${tags[k]} is not a valid alignment mode (use r or s).`));
  if (tags.sp && !['none', 'quarantine', 'reject'].includes(tags.sp.toLowerCase())) out.push(f('warn', `sp=${tags.sp} is not a valid subdomain policy.`));
  const fix = p === 'none' ? { host: `_dmarc.${domain}`, type: 'TXT', value: record.replace(/p=none/i, 'p=quarantine'), note: 'Once the reports show only legitimate senders.' } : undefined;
  return build('dmarc', 'DMARC', out, { summary: p ? `p=${p}` : 'Invalid', record, ...(fix ? { fix } : {}) });
}

// ---------------------------------------------------------------- DKIM

export const COMMON_SELECTORS = [
  'default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'k3', 's1', 's2', 'mail', 'dkim', 'smtp',
  'mandrill', 'mailgun', 'brevo', 'zoho', 'protonmail', 'protonmail2', 'protonmail3', 'fm1', 'fm2', 'fm3',
  'key1', 'key2', 'mxvault', 'email', 'dk', 'everlytic', 'cm', 'sig1', 'amazonses',
];

export async function checkDkim(domain, r, { selectors = [] } = {}) {
  const list = [...new Set([...selectors, ...COMMON_SELECTORS])];
  const hits = [];
  await Promise.all(
    list.map(async (sel) => {
      try {
        const txt = (await r.txt(`${sel}._domainkey.${domain}`)).find((t) => /(^|;)\s*p=/i.test(t));
        if (txt) hits.push({ selector: sel, record: txt.trim(), tags: parseTags(txt) });
      } catch {
        /* a single failing selector must not fail the whole check */
      }
    }),
  );
  hits.sort((a, b) => a.selector.localeCompare(b.selector));
  const out = [];
  if (hits.length === 0) {
    out.push(f('info', `No DKIM key found under ${list.length} common selectors. DKIM may still be set up under a custom selector. Pass your own with --selector (CLI) or the selector box.`));
    return build('dkim', 'DKIM', out, { status: 'info', summary: 'Not found', selectorsTried: list.length });
  }
  for (const h of hits) {
    const k = (h.tags.k || 'rsa').toLowerCase();
    const label = `Selector "${h.selector}"`;
    if (!h.tags.p) {
      out.push(f('warn', `${label} has an empty p= value: the key is revoked.`));
      continue;
    }
    if (k === 'ed25519') {
      out.push(f('ok', `${label} uses an Ed25519 key.`));
      continue;
    }
    const bits = rsaBits(h.tags.p);
    if (bits === null) out.push(f('warn', `${label} publishes a key that could not be parsed.`));
    else if (bits < 1024) out.push(f('fail', `${label} uses a ${bits}-bit RSA key, which is trivially breakable.`));
    else if (bits < 2048) out.push(f('warn', `${label} uses a ${bits}-bit RSA key. Rotate to 2048-bit.`));
    else out.push(f('ok', `${label} uses a ${bits}-bit RSA key.`));
    if ((h.tags.t || '').split(':').includes('y')) out.push(f('warn', `${label} is in testing mode (t=y), so receivers may ignore failures.`));
  }
  return build('dkim', 'DKIM', out, { summary: `${hits.length} selector${hits.length > 1 ? 's' : ''}`, selectors: hits.map((h) => h.selector) });
}

// ---------------------------------------------------------------- MX

export async function checkMx(domain, r) {
  const mx = (await r.mx(domain)).sort((a, b) => a.priority - b.priority);
  const out = [];
  if (mx.length === 0) {
    const a = await r.a(domain);
    if (a.length) out.push(f('warn', 'No MX record. Senders fall back to the domain A record, which is rarely intended. Publish an explicit MX.'));
    else out.push(f('fail', 'No MX record and no A record: this domain cannot receive email.'));
    return build('mx', 'MX', out, { summary: 'None' });
  }
  if (mx.length === 1 && mx[0].exchange === '') {
    out.push(f('info', 'Null MX published (RFC 7505): this domain declares that it does not accept email.'));
    return build('mx', 'MX', out, { status: 'info', summary: 'Null MX' });
  }
  out.push(f('ok', `${mx.length} MX record${mx.length > 1 ? 's' : ''}: ${mx.map((m) => `${m.priority} ${m.exchange}`).join(', ')}.`));
  if (mx.length === 1) out.push(f('info', 'Single MX host. A second one gives you a fallback when the first is down.'));
  for (const m of mx) {
    const [cname, a] = await Promise.all([r.cname(m.exchange).catch(() => []), r.a(m.exchange).catch(() => [])]);
    if (cname.length) out.push(f('warn', `${m.exchange} is a CNAME. MX targets must be address records, and some servers refuse CNAME targets.`));
    else if (!a.length) out.push(f('fail', `${m.exchange} does not resolve to an IPv4 address.`));
  }
  return build('mx', 'MX', out, { summary: `${mx.length} host${mx.length > 1 ? 's' : ''}`, hosts: mx });
}

// ---------------------------------------------------------------- MTA-STS and TLS-RPT (optional hardening)

export async function checkMtaSts(domain, r) {
  const rec = (await r.txt(`_mta-sts.${domain}`)).find((t) => /^v=STSv1/i.test(t.trim()));
  if (!rec) return build('mtasts', 'MTA-STS', [f('info', 'Not configured. MTA-STS makes sending servers require TLS when delivering to you. Optional, but a strong signal.')], { status: 'info', summary: 'Not set' });
  const id = parseTags(rec).id;
  return build('mtasts', 'MTA-STS', [f('ok', 'MTA-STS policy record present.'), id ? f('ok', `Policy id is ${id}.`) : f('warn', 'The record has no id= tag.')], { summary: 'Enabled', record: rec });
}

export async function checkTlsRpt(domain, r) {
  const rec = (await r.txt(`_smtp._tls.${domain}`)).find((t) => /^v=TLSRPTv1/i.test(t.trim()));
  if (!rec) return build('tlsrpt', 'TLS-RPT', [f('info', 'Not configured. TLS-RPT sends you reports when TLS delivery to your domain fails. Optional.')], { status: 'info', summary: 'Not set' });
  const tags = parseTags(rec);
  return build('tlsrpt', 'TLS-RPT', [f('ok', 'TLS-RPT record present.'), tags.rua ? f('ok', `Reports go to ${tags.rua}.`) : f('warn', 'The record has no rua= address.')], { summary: 'Enabled', record: rec });
}

// Node-only checks that need raw sockets: reverse DNS of the primary MX and a live STARTTLS probe.
// Many home and cloud networks block outbound port 25, so a timeout is reported as "unreachable", not as a fault.
import net from 'node:net';
import tls from 'node:tls';
import dns from 'node:dns/promises';
import { build, f } from './util.js';

function reader(socket) {
  let buf = '';
  const waiters = [];
  socket.on('data', (d) => {
    buf += d.toString('utf8');
    for (const w of [...waiters]) {
      const m = w.re.exec(buf);
      if (m) {
        buf = buf.slice(m.index + m[0].length);
        waiters.splice(waiters.indexOf(w), 1);
        w.resolve(m[0]);
      }
    }
  });
  return (re, ms = 6000) =>
    new Promise((resolve, reject) => {
      const w = { re, resolve };
      const timer = setTimeout(() => reject(new Error('timeout')), ms);
      w.resolve = (v) => {
        clearTimeout(timer);
        resolve(v);
      };
      const m = re.exec(buf);
      if (m) {
        buf = buf.slice(m.index + m[0].length);
        w.resolve(m[0]);
      } else waiters.push(w);
    });
}

async function probeStartTls(host, port = 25, timeout = 6000) {
  const socket = net.connect({ host, port });
  socket.setTimeout(timeout, () => socket.destroy(new Error('timeout')));
  await new Promise((res, rej) => {
    socket.once('connect', res);
    socket.once('error', rej);
  });
  try {
    const wait = reader(socket);
    const banner = await wait(/(^|\r\n)220 .*\r\n/);
    socket.write('EHLO mailcheck.invalid\r\n');
    const ehlo = await wait(/(^|\r\n)250 .*\r\n/);
    if (!/STARTTLS/i.test(ehlo)) return { banner: banner.trim(), starttls: false };
    socket.write('STARTTLS\r\n');
    await wait(/(^|\r\n)220 .*\r\n/);
    socket.removeAllListeners('data');
    const secure = await new Promise((resolve, reject) => {
      const t = tls.connect({ socket, servername: host, rejectUnauthorized: false }, () => resolve(t));
      t.once('error', reject);
    });
    const cert = secure.getPeerCertificate();
    const info = {
      banner: banner.trim(),
      starttls: true,
      protocol: secure.getProtocol(),
      authorized: secure.authorized,
      authError: secure.authorizationError ? String(secure.authorizationError) : null,
      validTo: cert && cert.valid_to ? new Date(cert.valid_to) : null,
      subject: cert && cert.subject ? cert.subject.CN : null,
    };
    secure.end();
    return info;
  } finally {
    socket.destroy();
  }
}

export async function checkDeep(domain, resolver, { timeout = 6000 } = {}) {
  const mx = (await resolver.mx(domain)).sort((a, b) => a.priority - b.priority);
  if (!mx.length || !mx[0].exchange) return build('deep', 'Mail server', [f('info', 'No MX host to probe.')], { status: 'info', summary: 'No MX' });
  const host = mx[0].exchange;
  const out = [];
  const ips = await resolver.a(host).catch(() => []);
  if (ips.length) {
    try {
      const names = await dns.reverse(ips[0]);
      if (!names.length) out.push(f('warn', `${ips[0]} has no reverse DNS (PTR). Many receivers penalize or reject mail from IPs without it.`));
      else {
        const back = await Promise.all(names.map((n) => resolver.a(n).catch(() => [])));
        const confirmed = back.some((list) => list.includes(ips[0]));
        out.push(confirmed ? f('ok', `${ips[0]} reverse-resolves to ${names[0]}, which resolves back to the same IP.`) : f('warn', `${ips[0]} reverse-resolves to ${names[0]}, but that name does not resolve back to the IP (forward-confirmed reverse DNS fails).`));
      }
    } catch {
      out.push(f('warn', `${ips[0]} has no reverse DNS (PTR). Many receivers penalize or reject mail from IPs without it.`));
    }
  }
  try {
    const p = await probeStartTls(host, 25, timeout);
    if (!p.starttls) out.push(f('warn', `${host} does not offer STARTTLS on port 25. Mail to it travels unencrypted.`));
    else {
      out.push(f('ok', `${host} offers STARTTLS (${p.protocol}).`));
      if (p.protocol && /TLSv1(\.1)?$/.test(p.protocol)) out.push(f('warn', `${host} negotiated ${p.protocol}, which is obsolete. Require TLS 1.2 or newer.`));
      if (p.validTo) {
        const days = Math.floor((p.validTo - Date.now()) / 86400000);
        if (days < 0) out.push(f('fail', `The certificate on ${host} expired ${-days} days ago.`));
        else if (days < 14) out.push(f('warn', `The certificate on ${host} expires in ${days} days.`));
        else out.push(f('ok', `Certificate valid for another ${days} days.`));
      }
      if (!p.authorized) out.push(f('warn', `The certificate on ${host} does not validate (${p.authError}). Strict senders using MTA-STS or DANE will refuse delivery.`));
    }
  } catch (err) {
    out.push(f('info', `Could not reach ${host}:25 from here (${err.message}). Outbound port 25 is often blocked on home and cloud networks.`));
  }
  return build('deep', 'Mail server', out, { summary: host });
}

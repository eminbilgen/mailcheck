import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { runAll, normalizeDomain, grade, score, checkSpf, checkDmarc, checkDkim, checkMx } from '../src/index.js';
import { parseTags, rsaBits } from '../src/util.js';

// Tiny in-memory resolver: zone = { 'name': { txt: [], mx: [], a: [], cname: [] } }
function fake(zone) {
  const get = (n, k) => (zone[n] && zone[n][k]) || [];
  return { name: 'fake', txt: async (n) => get(n, 'txt'), mx: async (n) => get(n, 'mx'), a: async (n) => get(n, 'a'), cname: async (n) => get(n, 'cname') };
}

test('normalizeDomain strips schemes, paths and mailbox parts', () => {
  assert.equal(normalizeDomain('https://Example.COM/path?q=1'), 'example.com');
  assert.equal(normalizeDomain('user@Example.com'), 'example.com');
  assert.equal(normalizeDomain('example.com.'), 'example.com');
  assert.throws(() => normalizeDomain('not a domain'));
  assert.throws(() => normalizeDomain(''));
});

test('parseTags handles spacing and case', () => {
  assert.deepEqual(parseTags('v=DMARC1; P=reject ; rua=mailto:a@b.c;'), { v: 'DMARC1', p: 'reject', rua: 'mailto:a@b.c' });
});

test('rsaBits reads real key sizes', () => {
  for (const bits of [1024, 2048]) {
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: bits });
    const b64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    assert.equal(rsaBits(b64), bits);
  }
  assert.equal(rsaBits('not-a-key'), null);
});

test('SPF: missing record fails with a suggested fix', async () => {
  const res = await checkSpf('x.test', fake({}));
  assert.equal(res.status, 'fail');
  assert.match(res.fix.value, /^v=spf1/);
});

test('SPF: two records fail', async () => {
  const res = await checkSpf('x.test', fake({ 'x.test': { txt: ['v=spf1 -all', 'v=spf1 ~all'] } }));
  assert.equal(res.status, 'fail');
});

test('SPF: +all fails, ~all passes', async () => {
  assert.equal((await checkSpf('x.test', fake({ 'x.test': { txt: ['v=spf1 +all'] } }))).status, 'fail');
  assert.equal((await checkSpf('x.test', fake({ 'x.test': { txt: ['v=spf1 mx ~all'] } }))).status, 'pass');
});

test('SPF: more than 10 lookups fails', async () => {
  const zone = { 'x.test': { txt: ['v=spf1 ' + Array.from({ length: 11 }, (_, i) => `include:s${i}.test`).join(' ') + ' -all'] } };
  for (let i = 0; i < 11; i++) zone[`s${i}.test`] = { txt: ['v=spf1 ip4:1.2.3.4 -all'] };
  const res = await checkSpf('x.test', fake(zone));
  assert.equal(res.status, 'fail');
  assert.equal(res.lookups, 11);
});

test('SPF: nested includes are counted, loops do not hang', async () => {
  const zone = {
    'x.test': { txt: ['v=spf1 include:a.test -all'] },
    'a.test': { txt: ['v=spf1 include:b.test a mx -all'] },
    'b.test': { txt: ['v=spf1 include:a.test -all'] },
  };
  const res = await checkSpf('x.test', fake(zone));
  // x->a (1), a->b (1), b->a (1, loop stops here), plus "a" (1) and "mx" (1) in a.test
  assert.equal(res.lookups, 5);
  assert.ok(res.findings.some((x) => /loop/i.test(x.text)));
});

test('DMARC: p=none warns, p=reject with rua passes, missing fails', async () => {
  const none = await checkDmarc('x.test', fake({ '_dmarc.x.test': { txt: ['v=DMARC1; p=none; rua=mailto:r@x.test'] } }));
  assert.equal(none.status, 'warn');
  assert.ok(none.fix);
  const strict = await checkDmarc('x.test', fake({ '_dmarc.x.test': { txt: ['v=DMARC1; p=reject; rua=mailto:r@x.test'] } }));
  assert.equal(strict.status, 'pass');
  assert.equal((await checkDmarc('x.test', fake({}))).status, 'fail');
});

test('DKIM: finds a 2048-bit key and flags a 1024-bit one', async () => {
  const key = (bits) => generateKeyPairSync('rsa', { modulusLength: bits }).publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const good = await checkDkim('x.test', fake({ 'google._domainkey.x.test': { txt: [`v=DKIM1; k=rsa; p=${key(2048)}`] } }));
  assert.equal(good.status, 'pass');
  const weak = await checkDkim('x.test', fake({ 'selector1._domainkey.x.test': { txt: [`v=DKIM1; p=${key(1024)}`] } }));
  assert.equal(weak.status, 'warn');
  const none = await checkDkim('x.test', fake({}));
  assert.equal(none.status, 'info');
});

test('DKIM: custom selectors are tried', async () => {
  const key = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const res = await checkDkim('x.test', fake({ 'weird._domainkey.x.test': { txt: [`v=DKIM1; p=${key}`] } }), { selectors: ['weird'] });
  assert.deepEqual(res.selectors, ['weird']);
});

test('MX: CNAME targets and unresolvable hosts are flagged', async () => {
  const res = await checkMx('x.test', fake({ 'x.test': { mx: [{ priority: 10, exchange: 'mail.x.test' }, { priority: 20, exchange: 'alias.x.test' }] }, 'mail.x.test': { a: ['1.1.1.1'] }, 'alias.x.test': { cname: ['mail.x.test'] } }));
  assert.equal(res.status, 'warn');
  const missing = await checkMx('x.test', fake({ 'x.test': { mx: [{ priority: 10, exchange: 'gone.x.test' }] } }));
  assert.equal(missing.status, 'fail');
});

test('runAll scores a well-configured domain highly and an empty one low', async () => {
  const key = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const good = fake({
    'good.test': { mx: [{ priority: 10, exchange: 'mx1.good.test' }, { priority: 20, exchange: 'mx2.good.test' }], txt: ['v=spf1 mx -all'] },
    'mx1.good.test': { a: ['1.1.1.1'] },
    'mx2.good.test': { a: ['1.1.1.2'] },
    'default._domainkey.good.test': { txt: [`v=DKIM1; p=${key}`] },
    '_dmarc.good.test': { txt: ['v=DMARC1; p=reject; rua=mailto:r@good.test'] },
    '_mta-sts.good.test': { txt: ['v=STSv1; id=1'] },
    '_smtp._tls.good.test': { txt: ['v=TLSRPTv1; rua=mailto:t@good.test'] },
  });
  const seen = [];
  const report = await runAll('good.test', good, { onResult: (c) => seen.push(c.id) });
  assert.equal(report.score, 100);
  assert.equal(report.grade, 'A');
  assert.equal(seen.length, 6);
  const empty = await runAll('empty.test', fake({}));
  assert.ok(empty.score < 40);
  assert.equal(empty.grade, 'F');
});

test('a failing resolver is reported per check instead of crashing the run', async () => {
  const broken = { name: 'broken', txt: async () => { throw new Error('boom'); }, mx: async () => [], a: async () => [], cname: async () => [] };
  const report = await runAll('x.test', broken);
  assert.ok(report.checks.some((c) => c.error));
});

test('grade bands', () => {
  assert.deepEqual([95, 80, 65, 45, 10].map(grade), ['A', 'B', 'C', 'D', 'F']);
  assert.equal(score([{ id: 'dmarc', status: 'pass' }]), 30);
});

#!/usr/bin/env node
import { runAll, normalizeDomain } from '../src/index.js';
import { nodeResolver } from '../src/node-resolver.js';
import { checkDeep } from '../src/deep.js';
import { readFileSync } from 'node:fs';

const HELP = `mailcheck - email authentication health check

Usage:
  mailcheck <domain> [options]

Options:
  --deep               Also probe the primary MX: reverse DNS and live STARTTLS on port 25
  --selector <name>    Extra DKIM selector to try (repeatable)
  --json               Print machine-readable JSON
  --fail-under <n>     Exit with code 1 if the score is below n (for CI)
  --no-color           Disable colors
  -v, --version        Print version
  -h, --help           Show this help
`;

const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const values = (name) => args.flatMap((a, i) => (a === name && args[i + 1] ? [args[i + 1]] : []));

if (flag('-h') || flag('--help') || args.length === 0) {
  console.log(HELP);
  process.exit(args.length === 0 ? 1 : 0);
}
if (flag('-v') || flag('--version')) {
  console.log(JSON.parse(readFileSync(new URL('../package.json', import.meta.url))).version);
  process.exit(0);
}

const valueFlags = new Set(['--selector', '--fail-under']);
const domainArg = args.find((a, i) => !a.startsWith('-') && !valueFlags.has(args[i - 1]));
const color = process.stdout.isTTY && !flag('--no-color') && !process.env.NO_COLOR;
const c = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
const ICON = { ok: c(32, '✔'), info: c(36, 'ℹ'), warn: c(33, '▲'), fail: c(31, '✖') };
const BADGE = { pass: c(32, 'PASS'), warn: c(33, 'WARN'), fail: c(31, 'FAIL'), info: c(36, 'INFO') };
const GRADE = { A: 32, B: 32, C: 33, D: 33, F: 31 };

try {
  const resolver = nodeResolver();
  const report = await runAll(domainArg, resolver, { selectors: values('--selector') });
  if (flag('--deep')) report.checks.push(await checkDeep(report.domain, resolver));

  if (flag('--json')) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(`\n${c(1, report.domain)}   score ${c(1, report.score)}/100   grade ${c(GRADE[report.grade] || 0, c(1, report.grade))}\n`);
    for (const check of report.checks) {
      console.log(`${BADGE[check.status]}  ${c(1, check.title.padEnd(11))} ${c(2, check.summary || '')}`);
      for (const finding of check.findings) console.log(`      ${ICON[finding.level]} ${finding.text}`);
      if (check.fix) console.log(`      ${c(2, `→ ${check.fix.type} ${check.fix.host}`)}\n        ${check.fix.value}${check.fix.note ? c(2, `\n        ${check.fix.note}`) : ''}`);
      console.log('');
    }
  }
  const min = Number(values('--fail-under')[0]);
  process.exit(Number.isFinite(min) && report.score < min ? 1 : 0);
} catch (err) {
  console.error(`mailcheck: ${err.message}`);
  process.exit(2);
}

# mailcheck

Email authentication and deliverability health check for any domain. One score, what is broken, and the exact DNS record to fix it.

- **Checks:** MX, SPF (including the 10-lookup limit), DKIM (key size, revoked and test-mode keys), DMARC, MTA-STS and TLS-RPT.
- **Two ways to run it:** a command-line tool for Node, and a static web page that does everything in the browser. Same code underneath.
- **No dependencies.** Plain ES modules, Node 18 or newer.

## Web demo

`index.html` is a static page. Open it through any static host (Netlify, Cloudflare Pages, `python -m http.server`). It resolves DNS through Cloudflare's public DNS-over-HTTPS endpoint, so there is no backend and nothing is stored. Results are shareable with `?d=example.com`.

## CLI

```bash
git clone https://github.com/eminbilgen/mailcheck
cd mailcheck
node bin/mailcheck.js example.com
```

```text
example.com   score 84/100   grade B

PASS  SPF         -all
      ✔ Exactly one SPF record published.
      ✔ "-all" (hardfail) is set.
      ✔ 3 of 10 allowed DNS lookups used.

WARN  DKIM        1 selector
      ▲ Selector "default" uses a 1024-bit RSA key. Rotate to 2048-bit.
...
```

| Option | Meaning |
|---|---|
| `--deep` | Also probe the primary MX: reverse DNS (with forward confirmation) and a live STARTTLS handshake on port 25. Many networks block outbound port 25; that is reported as "unreachable", not as a fault. |
| `--selector <name>` | Extra DKIM selector to try. Repeatable. |
| `--json` | Machine-readable output. |
| `--fail-under <n>` | Exit with code 1 when the score is below `n`. Handy in CI. |

## As a library

```js
import { runAll, dohResolver } from './src/index.js';              // browser or Node
import { nodeResolver } from './src/node-resolver.js';              // Node only, uses system DNS

const report = await runAll('example.com', dohResolver());
console.log(report.score, report.grade);
for (const check of report.checks) console.log(check.title, check.status, check.findings);
```

A resolver is any object with `txt(name)`, `mx(name)`, `a(name)` and `cname(name)` returning promises, so you can plug in your own or a fake one for tests.

## How the score works

Weights add up to 100: DMARC 30, SPF 25, DKIM 20, MX 15, MTA-STS 5, TLS-RPT 5. A passing check earns its full weight, a warning half, an optional feature that is not configured 40 percent, a failure nothing. Bands: A from 90, B from 75, C from 60, D from 40.

The score is a heuristic for "is this domain set up the way large mailbox providers expect", not a guarantee of inbox placement. Reputation, content and sending behavior matter too.

## Limitations

- **DKIM selectors cannot be listed.** DNS does not allow enumerating them, so mailcheck probes about 30 common ones. A key under a custom selector is reported as "not found" unless you pass it with `--selector`.
- **No blocklist lookups.** The big blocklists refuse queries from public resolvers, so a reliable check needs your own resolver. Out of scope here.
- **MTA-STS policy files** are not fetched; only the DNS record is checked. Browsers cannot fetch them cross-origin.
- DoH results come from one provider. If it is unreachable the checks report an error instead of guessing.

## Development

```bash
npm test      # node --test, no install needed
```

The tests use an in-memory resolver, so they run offline. They cover SPF lookup counting (including include loops), DMARC and DKIM edge cases, RSA key-size parsing against freshly generated keys, and scoring.

## License

MIT, see [LICENSE](LICENSE).

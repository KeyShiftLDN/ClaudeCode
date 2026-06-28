# Key Shift London — security header remediation

`keyshiftlondon.org` is hosted on **GitHub Pages** (resolves to `185.199.108–111.153`).
GitHub Pages serves a solid GitHub/Fastly-managed TLS cert but **cannot set custom
response headers**, so scanners (web-check, ZAP, Mozilla Observatory) flag the
missing security headers. The fix is to put **Cloudflare** in front of the site
and inject the headers at the edge.

There is **no server-side attack surface** (static hosting, no backend/DB), so the
ZAP active scan finds essentially nothing — the entire remediation is response headers.

## Headers being added

| Header | Value | Why |
|--------|-------|-----|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Force HTTPS, prevent SSL-strip |
| `Content-Security-Policy` | see worker | Mitigate XSS / data injection |
| `X-Content-Type-Options` | `nosniff` | Stop MIME sniffing |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limit referrer leakage |
| `X-Frame-Options` + CSP `frame-ancestors` | `DENY` / `'none'` | Clickjacking protection |
| `Permissions-Policy` | locks camera/mic/geo/etc. | Disable unused browser features |
| `Cross-Origin-Opener-Policy` | `same-origin` | Process isolation |
| `Cross-Origin-Resource-Policy` | `same-origin` | Block cross-origin embedding |

`Server` / `X-Powered-By` / `Via` are stripped to reduce fingerprinting.

---

## Option A — Cloudflare Worker (recommended, complete)

Most flexible: sets every header including a tunable CSP.

### 1. Get the zone onto Cloudflare (one-time)
- Add `keyshiftlondon.org` as a site in the Cloudflare dashboard (Free plan is fine).
- Point your registrar's nameservers at the two Cloudflare nameservers it gives you.
- Keep the existing GitHub Pages DNS records, now **proxied** (orange cloud):
  - `A` apex → `185.199.108.153`, `.109.153`, `.110.153`, `.111.153`
  - `CNAME www` → `<your-gh-user>.github.io` (or the apex)
- In **SSL/TLS → Overview**, set mode to **Full** (GitHub Pages serves valid TLS).

### 2. Deploy the Worker
```bash
cd security/keyshiftlondon
npm install -g wrangler        # if not already installed
wrangler login                 # browser OAuth to your Cloudflare account
wrangler deploy                # uses wrangler.toml (routes apex + www)
```

### 3. Validate the CSP, then enforce
- The Worker ships with `REPORT_ONLY = true` — the CSP is sent as
  `Content-Security-Policy-Report-Only`, so nothing breaks while you watch for
  violations in the browser console on the live site.
- Add any real sources the site uses (fonts, analytics, embeds) to the `CSP`
  array in `cloudflare-worker.js`.
- Flip `REPORT_ONLY = false` and `wrangler deploy` again to enforce.

### 4. Re-scan
```bash
docker run --rm -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t https://keyshiftlondon.org -I
# or web-check / https://observatory.mozilla.org
```

---

## Option B — Transform Rules (no-code, dashboard)

If you'd rather not run a Worker, set static headers via
**Rules → Transform Rules → Modify Response Header → Create rule**
(one "Set" entry per header). Expression: `true` (all requests).

```
Set static  Strict-Transport-Security      max-age=63072000; includeSubDomains; preload
Set static  X-Content-Type-Options         nosniff
Set static  Referrer-Policy                strict-origin-when-cross-origin
Set static  X-Frame-Options                DENY
Set static  Permissions-Policy             accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()
Set static  Cross-Origin-Opener-Policy     same-origin
Set static  Cross-Origin-Resource-Policy   same-origin
Set static  Content-Security-Policy        default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' https://www.googletagmanager.com; connect-src 'self' https://www.google-analytics.com; upgrade-insecure-requests
```

- HSTS can alternatively be enabled in **SSL/TLS → Edge Certificates → HTTP Strict
  Transport Security** (gives you the same header with a GUI toggle + preload option).
- Transform Rules can't do CSP *report-only* rollout as cleanly as the Worker —
  if you go this route, test the CSP value on a staging copy first.

---

## Notes
- **Tune the CSP.** The defaults assume Google Fonts + GA4. If Key Shift London
  loads anything else (Calendly, Stripe, YouTube embeds, a CDN), add those origins
  or the page features will silently break under enforcement.
- **HSTS preload** is sticky — only submit to hstspreload.org once you're certain
  all subdomains will always be HTTPS.
- You already have the Cloudflare MCP servers registered (`cloudflare-bindings`,
  `cloudflare-graphql`, etc.) — once the zone is on your account and OAuth is
  completed, those can manage/inspect this Worker directly.

/**
 * Key Shift London — security header injector for Cloudflare Workers.
 *
 * keyshiftlondon.org is hosted on GitHub Pages, which cannot set custom
 * response headers. This Worker sits in front of the origin and adds the
 * security headers that web-check / ZAP / Mozilla Observatory flag as missing.
 *
 * Deploy: see security-headers.md (wrangler deploy + a route on the zone).
 *
 * CSP rollout strategy:
 *   1. Deploy with REPORT_ONLY = true and watch the browser console / report
 *      endpoint for violations on the live site.
 *   2. Add any legitimate sources the site actually uses to the CSP below.
 *   3. Flip REPORT_ONLY = false to enforce.
 */

// Flip to false once the CSP has been validated against the live site.
const REPORT_ONLY = true;

// Tune these to what the site actually loads. Defaults cover a static
// marketing site with Google Fonts + Google Analytics (GA4). Remove what
// you don't use — tighter is better.
const CSP = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "img-src 'self' data: https:",
  // Google Fonts stylesheet + inline styles many static themes need.
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  // GA4 / gtag. Drop these two lines if the site has no analytics.
  "script-src 'self' https://www.googletagmanager.com",
  "connect-src 'self' https://www.google-analytics.com https://region1.google-analytics.com",
  "frame-src 'self'",
  "upgrade-insecure-requests",
].join("; ");

const SECURITY_HEADERS = {
  // Force HTTPS for 2 years incl. subdomains; preload-eligible.
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "X-Frame-Options": "DENY",
  "Permissions-Policy":
    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "X-Permitted-Cross-Domain-Policies": "none",
};

// Headers that leak stack details — strip if present.
const STRIP_HEADERS = ["X-Powered-By", "Server", "Via", "X-AspNet-Version"];

export default {
  async fetch(request) {
    const response = await fetch(request);

    // Clone so headers are mutable.
    const newResponse = new Response(response.body, response);

    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      newResponse.headers.set(name, value);
    }

    const cspHeader = REPORT_ONLY
      ? "Content-Security-Policy-Report-Only"
      : "Content-Security-Policy";
    newResponse.headers.set(cspHeader, CSP);

    for (const h of STRIP_HEADERS) {
      newResponse.headers.delete(h);
    }

    return newResponse;
  },
};

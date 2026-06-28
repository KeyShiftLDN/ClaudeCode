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

// Tuned for Key Shift London's actual stack:
//   Google Fonts · Google Analytics (GA4/gtag) · booking+payments · Instagram embeds
//
// PAYMENTS/BOOKING: both Stripe and Calendly are included below. DELETE the
// block for whichever provider the site does NOT use. If booking is actually
// Acuity/Squarespace/Square, swap in those origins (see security-headers.md).
const CSP = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",

  // images: self + data URIs + any https (covers GA pixels, IG/Stripe CDNs)
  "img-src 'self' data: https:",

  // styles: Google Fonts CSS + inline styles most static themes require
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://assets.calendly.com",
  "font-src 'self' https://fonts.gstatic.com",

  // scripts: GA4/gtag + Stripe.js + Calendly + Instagram embed.js
  // NOTE: if GA is added via an INLINE gtag snippet (not a GTM container),
  // you must add 'unsafe-inline' here OR the snippet's sha256 hash, or the
  // analytics init will be blocked. Prefer loading it from a file/GTM.
  "script-src 'self' https://www.googletagmanager.com https://js.stripe.com https://assets.calendly.com https://www.instagram.com https://platform.instagram.com",

  // XHR/fetch/beacon: GA4 collect endpoints + Stripe API + Calendly
  "connect-src 'self' https://www.google-analytics.com https://region1.google-analytics.com https://*.google-analytics.com https://*.analytics.google.com https://www.googletagmanager.com https://api.stripe.com https://calendly.com",

  // iframes the page is allowed to embed: Stripe, Calendly, Instagram
  "frame-src https://js.stripe.com https://hooks.stripe.com https://calendly.com https://www.instagram.com",

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

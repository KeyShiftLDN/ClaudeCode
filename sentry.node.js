/**
 * Sentry SDK initialization for Node.js services.
 *
 * Require this module early in any Node entry point:
 *   require('./sentry.node');  // or: import './sentry.node';
 *
 * Requires SENTRY_DSN in .env or environment.
 */

const Sentry = require("@sentry/node");

Sentry.init({
  dsn: process.env.SENTRY_DSN || "",
  environment: process.env.SENTRY_ENVIRONMENT || "development",
  release: process.env.SENTRY_RELEASE,
  tracesSampleRate: parseFloat(process.env.SENTRY_TRACES_SAMPLE_RATE || "1.0"),
  profilesSampleRate: parseFloat(
    process.env.SENTRY_PROFILES_SAMPLE_RATE || "1.0"
  ),
  sendDefaultPii: false,
});

module.exports = Sentry;

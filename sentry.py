"""
Sentry SDK initialization for Python services.

Import this module early in any Python entry point (MCP servers, scripts, etc.)
to enable error tracking and performance monitoring.

Usage:
    import sentry  # noqa: F401  — at the top of your entry point

Requires SENTRY_DSN in .env or environment.
"""

import os

import sentry_sdk

sentry_sdk.init(
    dsn=os.environ.get("SENTRY_DSN", ""),
    environment=os.environ.get("SENTRY_ENVIRONMENT", "development"),
    release=os.environ.get("SENTRY_RELEASE"),
    traces_sample_rate=float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "1.0")),
    profiles_sample_rate=float(os.environ.get("SENTRY_PROFILES_SAMPLE_RATE", "1.0")),
    send_default_pii=False,
)

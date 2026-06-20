"""
Application configuration, pulled from environment variables.

Bug fixed here: previously the JWT secret and DB password silently fell back
to hardcoded weak defaults with no indication that was happening. If you ever
deploy without setting these env vars, you'd be running with a publicly-known
secret and never know it. We keep the dev-friendly fallback (so `uvicorn
main:app` still works out of the box) but print a loud warning when it's used.
"""

import os
import sys

DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://miami_amber_user:1234@localhost/miami_amber_db"
)
JWT_SECRET = os.getenv("JWT_SECRET", "your_jwt_secret_key")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 31  # 31 days

CORS_ORIGINS = [os.getenv("FRONTEND_ORIGIN", "http://miami.monster")]

if not os.getenv("JWT_SECRET"):
    print(
        "WARNING: JWT_SECRET is not set, using the default dev secret. "
        "Set the JWT_SECRET environment variable before deploying.",
        file=sys.stderr,
    )

if not os.getenv("DATABASE_URL"):
    print(
        "WARNING: DATABASE_URL is not set, using a default local dev connection string.",
        file=sys.stderr,
    )

"""
Application configuration, pulled from environment variables.
"""

import os


def require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(
            f"Required environment variable {name!r} is not set. "
            f"Set it before starting the app (e.g. `export {name}=...` "
            f"or put it in a .env file)."
        )
    return value


DATABASE_URL = require_env("DATABASE_URL")
JWT_SECRET = require_env("JWT_SECRET")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 31  # 31 days

CORS_ORIGINS = ["*"]

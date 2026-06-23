"""Small standalone helpers used across the app."""

import html
from typing import Optional


def escape_optional(value: Optional[str]) -> Optional[str]:
    """HTML-escape a string, passing None through unchanged.
    """
    if value is None:
        return None
    return html.escape(value)


def escape_like_pattern(value: str) -> str:
    """Escape SQL LIKE/ILIKE wildcard characters in user-supplied input.
    """
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

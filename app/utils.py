"""Small standalone helpers used across the app."""

import html
from typing import Optional


def escape_optional(value: Optional[str]) -> Optional[str]:
    """HTML-escape a string, passing None through unchanged.

    Bug fixed here: the original code called html.escape(None) whenever an
    optional field (e.g. musicBrainzId) was omitted, which raises a
    TypeError and crashes the request instead of saving a blank value.
    """
    if value is None:
        return None
    return html.escape(value)


def escape_like_pattern(value: str) -> str:
    """Escape SQL LIKE/ILIKE wildcard characters in user-supplied input.

    Bug fixed here: passing a raw nickname into User.name.ilike(nickname)
    let a caller use '%' or '_' as wildcards (e.g. searching "%" matches
    every username), which isn't SQL injection but is an unintended way to
    enumerate or fish for usernames. Pair this with `.ilike(pattern,
    escape="\\")` at the call site.
    """
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

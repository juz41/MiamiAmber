"""Shared functions for turning ORM objects into JSON-able dicts.
"""

from typing import Optional

from .models import Post, User


def user_brief(user: Optional[User]) -> Optional[dict]:
    if not user:
        return None
    return {"id": user.id, "name": user.name}


def post_to_dict(post: Post, include_user: bool = True) -> dict:
    data = {
        "id": post.id,
        "title": post.title,
        "artist": post.artist,
        "album": post.album,
        "musicbrainz_id": post.musicbrainz_id,
        "text": post.text,
        "rating": post.rating,
        "date": post.date,
        "tags": [pt.tag.name for pt in post.post_tags],
    }
    if include_user:
        data["user"] = user_brief(post.user)
    return data

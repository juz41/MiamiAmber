"""Small bits of business logic shared between routers."""

from sqlalchemy.orm import Session

from .models import Post, PostTag, Tag


def sync_post_tags(db: Session, post: Post, tag_names) -> None:
    """Replace post's tags with the given set of tag names, creating any
    tags that don't exist yet.
    """
    post.post_tags.clear()

    normalized = {t.lower().strip() for t in tag_names if t.strip()}
    if not normalized:
        return

    existing_tags = db.query(Tag).filter(Tag.name.in_(normalized)).all()
    existing_names = {t.name for t in existing_tags}

    for name in normalized:
        if name not in existing_names:
            tag = Tag(name=name)
            db.add(tag)
            existing_tags.append(tag)

    db.flush()

    for tag in existing_tags:
        post.post_tags.append(PostTag(tag_id=tag.id))


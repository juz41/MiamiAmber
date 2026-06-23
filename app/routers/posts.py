"""Post endpoints: list, fetch, search, create, update, delete."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc
from sqlalchemy.orm import Session, joinedload, selectinload

from ..database import get_db
from ..models import Follow, Post, PostTag, Tag, User
from ..schemas import CreatePostRequest, UpdatePostRequest
from ..security import get_current_user
from ..serializers import post_to_dict
from ..services import sync_post_tags
from ..utils import escape_optional

router = APIRouter(prefix="/api", tags=["posts"])

POST_LOAD_OPTIONS = (
    joinedload(Post.user),
    selectinload(Post.post_tags).joinedload(PostTag.tag),
)


@router.get("/posts")
def get_posts(db: Session = Depends(get_db)):
    posts = (
        db.query(Post)
        .options(*POST_LOAD_OPTIONS)
        .order_by(desc(Post.date))
        .all()
    )
    return [post_to_dict(p) for p in posts]


@router.get("/posts/following")
def get_following_posts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    followed_ids = (
        db.query(Follow.following_id)
        .filter(Follow.follower_id == current_user.id)
        .subquery()
    )

    posts = (
        db.query(Post)
        .options(*POST_LOAD_OPTIONS)
        .filter(Post.user_id.in_(followed_ids))
        .order_by(desc(Post.date))
        .all()
    )
    return [post_to_dict(p) for p in posts]


@router.get("/posts/{post_id}")
def get_post(post_id: int, db: Session = Depends(get_db)):
    post = (
        db.query(Post)
        .options(*POST_LOAD_OPTIONS)
        .filter(Post.id == post_id)
        .first()
    )
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    return post_to_dict(post)


@router.get("/tags/{tag_name}")
def get_posts_by_tag(tag_name: str, db: Session = Depends(get_db)):
    posts = (
        db.query(Post)
        .options(*POST_LOAD_OPTIONS)
        .join(PostTag)
        .join(Tag)
        .filter(Tag.name == tag_name)
        .all()
    )
    return [post_to_dict(p) for p in posts]


@router.get("/search")
def search(q: str, db: Session = Depends(get_db)):
    query = q.lower()
    posts = (
        db.query(Post)
        .options(*POST_LOAD_OPTIONS)
        .join(PostTag, isouter=True)
        .join(Tag, isouter=True)
        .distinct()
        .all()
    )

    result = []
    for p in posts:
        if (
            query in (p.title or "").lower()
            or query in (p.artist or "").lower()
            or query in (p.album or "").lower()
            or query in (p.text or "").lower()
            or any(query in (pt.tag.name or "").lower() for pt in p.post_tags)
        ):
            result.append(post_to_dict(p))
    return result


@router.post("/posts")
def create_post(
    request: CreatePostRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not request.title.strip():
        raise HTTPException(status_code=400, detail="Title cannot be empty")
    if not request.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty")
    if request.rating < 0 or request.rating > 100:
        raise HTTPException(status_code=400, detail="Rating must be 0-100")

    post = Post(
        title=escape_optional(request.title.strip()),
        artist=escape_optional(request.artist.strip() if request.artist else ""),
        album=escape_optional(request.album.strip() if request.album else ""),
        musicbrainz_id=escape_optional(
            request.musicBrainzId.strip() if request.musicBrainzId else None
        ),
        text=escape_optional(request.text.strip()),
        rating=request.rating,
        user_id=current_user.id,
    )

    sync_post_tags(db, post, request.tags)

    db.add(post)
    db.commit()
    db.refresh(post)
    return {"message": "Post created", "postId": post.id}


@router.put("/posts/{post_id}")
def update_post(
    post_id: int,
    request: UpdatePostRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only modify your own posts")

    if request.title is not None:
        post.title = escape_optional(request.title.strip())
    if request.artist is not None:
        post.artist = escape_optional(request.artist.strip())
    if request.album is not None:
        post.album = escape_optional(request.album.strip())
    if request.musicBrainzId is not None:
        post.musicbrainz_id = escape_optional(request.musicBrainzId.strip())
    if request.text is not None:
        post.text = escape_optional(request.text.strip())
    if request.rating is not None:
        if request.rating < 0 or request.rating > 100:
            raise HTTPException(status_code=400, detail="Rating must be 0-100")
        post.rating = request.rating

    if request.tags is not None:
        sync_post_tags(db, post, request.tags)

    db.commit()
    db.refresh(post)
    return {"message": "Post updated", "postId": post.id}


@router.delete("/posts/{post_id}")
def delete_post(
    post_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only delete your own posts")

    db.delete(post)
    db.commit()
    return {"message": "Post deleted", "postId": post.id}

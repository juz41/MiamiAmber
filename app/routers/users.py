"""User profile and follow/unfollow endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Follow, Post, User
from ..security import get_current_user
from ..serializers import post_to_dict
from ..utils import escape_like_pattern

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("/byname/{nickname}")
def get_user_by_name(nickname: str, db: Session = Depends(get_db)):
    pattern = escape_like_pattern(nickname)
    user = db.query(User).filter(User.name.ilike(pattern, escape="\\")).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    posts = db.query(Post).filter(Post.user_id == user.id).all()
    return {
        "user": {"id": user.id, "name": user.name, "description": user.description},
        "posts": [post_to_dict(p, include_user=False) for p in posts],
    }


@router.post("/{user_id}/follow")
def follow_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.id == user_id:
        raise HTTPException(status_code=400, detail="You cannot follow yourself")

    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    existing = db.query(Follow).filter_by(
        follower_id=current_user.id, following_id=user_id
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Already following")

    db.add(Follow(follower_id=current_user.id, following_id=user_id))
    db.commit()
    return {"message": "User followed"}


@router.delete("/{user_id}/follow")
def unfollow_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    follow = db.query(Follow).filter_by(
        follower_id=current_user.id, following_id=user_id
    ).first()
    if not follow:
        raise HTTPException(status_code=400, detail="Not following")

    db.delete(follow)
    db.commit()
    return {"message": "User unfollowed"}


@router.get("/{user_id}/followers")
def get_followers(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return [{"id": f.follower.id, "name": f.follower.name} for f in user.followers]


@router.get("/{user_id}/following")
def get_following(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return [{"id": f.following.id, "name": f.following.name} for f in user.following]

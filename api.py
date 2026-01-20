#!/usr/bin/env python

from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey, desc 
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
from typing import List, Optional
import os
from pydantic import BaseModel
from typing import List, Optional
import html
import re

class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class CreatePostRequest(BaseModel):
    title: str
    artist: Optional[str] = ""
    album: Optional[str] = ""
    musicBrainzId: Optional[str] = None
    text: str
    rating: Optional[int] = 0
    tags: List[str] = []

class UpdatePostRequest(BaseModel):
    title: Optional[str] = None
    artist: Optional[str] = None
    album: Optional[str] = None
    musicBrainzId: Optional[str] = None
    text: Optional[str] = None
    rating: Optional[int] = None
    tags: Optional[List[str]] = None

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://miami_amber_user:1234@localhost/miami_amber_db")
JWT_SECRET = os.getenv("JWT_SECRET", "your_jwt_secret_key")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class PostTag(Base):
    __tablename__ = "posts_tags"
    post_id = Column(Integer, ForeignKey("posts.id"), primary_key=True)
    tag_id = Column(Integer, ForeignKey("tags.id"), primary_key=True)

class Tag(Base):
    __tablename__ = "tags"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)

    post_tags = relationship("PostTag", backref="tag")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, index=True)
    hash = Column(String)
    description = Column(Text, nullable=True)

    posts = relationship("Post", back_populates="user")

        following = relationship(
        "Follow",
        foreign_keys=[Follow.follower_id],
        backref="follower",
        cascade="all, delete-orphan"
    )

    followers = relationship(
        "Follow",
        foreign_keys=[Follow.following_id],
        backref="following",
        cascade="all, delete-orphan"
    )


class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True)
    title = Column(String)
    artist = Column(String)
    album = Column(String)
    musicbrainz_id = Column(String)
    text = Column(Text)
    rating = Column(Integer)
    date = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id"))

    user = relationship("User", back_populates="posts")
    post_tags = relationship("PostTag", backref="post")

class Follow(Base):
    __tablename__ = "follows"
    follower_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    following_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def verify_password(plain, hashed): return pwd_context.verify(plain, hashed)
def get_password_hash(password): return pwd_context.hash(password)
def create_access_token(data: dict, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = int(payload.get("id"))
        user = db.query(User).filter(User.id == user_id).first()
        if not user: raise HTTPException(status_code=401, detail="Invalid credentials")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid credentials")


def validate_username(username: str):
    if len(username) > 20:
        raise HTTPException(status_code=400, detail="Username too long (max 20 chars)")
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        raise HTTPException(status_code=400, detail="Username contains invalid characters")
    return username

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://miami.monster"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/register")
def register(request: RegisterRequest, db: Session = Depends(get_db)):
    username = validate_username(request.username.strip())
    if db.query(User).filter(User.name == username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    user = User(name=username, hash=get_password_hash(request.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "Registration successful", "id": user.id}

@app.post("/api/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.name == request.username).first()
    if not user or not verify_password(request.password, user.hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"id": user.id, "name": user.name})
    return {"token": token}

@app.get("/api/posts")
def get_posts(db: Session = Depends(get_db)):
    posts = db.query(Post).order_by(desc(Post.date)).limit(20).all()
    result = []
    for p in posts:
        result.append({
            "id": p.id,
            "title": p.title,
            "artist": p.artist,
            "album": p.album,
            "musicbrainz_id": p.musicbrainz_id,
            "text": p.text,
            "rating": p.rating,
            "date": p.date,
            "user": {"id": p.user.id, "name": p.user.name} if p.user else None,
            "tags": [pt.tag.name for pt in p.post_tags]
        })
    return result

@app.get("/api/posts/{post_id}")
def get_post(post_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post: raise HTTPException(status_code=404, detail="Post not found")
    return {
        "id": post.id,
        "title": post.title,
        "artist": post.artist,
        "album": post.album,
        "musicbrainz_id": post.musicbrainz_id,
        "text": post.text,
        "rating": post.rating,
        "date": post.date,
        "user": {"id": post.user.id, "name": post.user.name} if post.user else None,
        "tags": [pt.tag.name for pt in post.post_tags]
    }

@app.get("/api/users/byname/{nickname}")
def get_user_by_name(nickname: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.name.ilike(nickname)).first()
    if not user: raise HTTPException(status_code=404, detail="User not found")
    posts = db.query(Post).filter(Post.user_id == user.id).all()
    return {
        "user": {"id": user.id, "name": user.name, "description": user.description},
        "posts": [{"id": p.id, "title": p.title, "artist": p.artist, "album": p.album,
                   "musicbrainz_id": p.musicbrainz_id, "text": p.text, "rating": p.rating,
                   "date": p.date, "tags": [pt.tag.name for pt in p.post_tags]} for p in posts]
    }

@app.post("/api/users/{user_id}/follow")
def follow_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.id == user_id:
        raise HTTPException(status_code=400, detail="You cannot follow yourself")

    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    existing = db.query(Follow).filter_by(
        follower_id=current_user.id,
        following_id=user_id
    ).first()

    if existing:
        raise HTTPException(status_code=400, detail="Already following")

    follow = Follow(
        follower_id=current_user.id,
        following_id=user_id
    )
    db.add(follow)
    db.commit()

    return {"message": "User followed"}

@app.delete("/api/users/{user_id}/follow")
def unfollow_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    follow = db.query(Follow).filter_by(
        follower_id=current_user.id,
        following_id=user_id
    ).first()

    if not follow:
        raise HTTPException(status_code=400, detail="Not following")

    db.delete(follow)
    db.commit()

    return {"message": "User unfollowed"}

@app.get("/api/users/{user_id}/followers")
def get_followers(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return [
        {"id": f.follower.id, "name": f.follower.name}
        for f in user.followers
    ]

@app.get("/api/users/{user_id}/following")
def get_following(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return [
        {"id": f.following.id, "name": f.following.name}
        for f in user.following
    ]


@app.get("/api/tags/{tag_name}")
def get_posts_by_tag(tag_name: str, db: Session = Depends(get_db)):
    posts = db.query(Post).join(PostTag).join(Tag).filter(Tag.name == tag_name).all()
    result = []
    for p in posts:
        result.append({
            "id": p.id,
            "title": p.title,
            "artist": p.artist,
            "album": p.album,
            "text": p.text,
            "rating": p.rating,
            "date": p.date,
            "user": {"id": p.user.id, "name": p.user.name} if p.user else None,
            "tags": [pt.tag.name for pt in p.post_tags]
        })
    return result

@app.get("/api/search")
def search(q: str, db: Session = Depends(get_db)):
    query = q.lower()
    posts = db.query(Post).join(PostTag, isouter=True).join(Tag, isouter=True).all()
    result = []
    for p in posts:
        if (query in (p.title or "").lower() or
            query in (p.artist or "").lower() or
            query in (p.album or "").lower() or
            query in (p.text or "").lower() or
            any(query in (pt.tag.name or "").lower() for pt in p.post_tags)):
            result.append({
                "id": p.id,
                "title": p.title,
                "artist": p.artist,
                "album": p.album,
                "musicbrainz_id": p.musicbrainz_id,
                "text": p.text,
                "rating": p.rating,
                "date": p.date,
                "user": {"id": p.user.id, "name": p.user.name} if p.user else None,
                "tags": [pt.tag.name for pt in p.post_tags]
            })
    return result

@app.post("/api/posts")
def create_post(request: CreatePostRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not request.title.strip():
        raise HTTPException(status_code=400, detail="Title cannot be empty")
    if not request.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty")
    if request.rating < 0 or request.rating > 100:
        raise HTTPException(status_code=400, detail="Rating must be 0-100")

    post = Post(
        title=html.escape(request.title.strip()),
        artist=html.escape(request.artist.strip() if request.artist else ""),
        album=html.escape(request.album.strip() if request.album else ""),
        musicbrainz_id=html.escape(request.musicBrainzId.strip() if request.musicBrainzId else None),
        text=html.escape(request.text.strip()),
        rating=request.rating,
        date=datetime.utcnow(),
        user_id=current_user.id
    )

    tag_names = set([t.lower().strip() for t in request.tags if t.strip()])
    existing_tags = db.query(Tag).filter(Tag.name.in_(tag_names)).all()
    existing_names = [t.name for t in existing_tags]

    for name in tag_names:
        if name not in existing_names:
            tag = Tag(name=name)
            db.add(tag)
            existing_tags.append(tag)
    db.commit()

    for tag in existing_tags:
        post.post_tags.append(PostTag(tag_id=tag.id))

    db.add(post)
    db.commit()
    db.refresh(post)

    return {"message": "Post created", "postId": post.id}

@app.put("/api/posts/{post_id}")
def update_post(
    post_id: int,
    request: UpdatePostRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only modify your own posts")

    # Update fields if provided
    if request.title is not None:
        post.title = html.escape(request.title.strip())
    if request.artist is not None:
        post.artist = html.escape(request.artist.strip())
    if request.album is not None:
        post.album = html.escape(request.album.strip())
    if request.musicBrainzId is not None:
        post.musicbrainz_id = html.escape(request.musicBrainzId.strip())
    if request.text is not None:
        post.text = html.escape(request.text.strip())
    if request.rating is not None:
        if request.rating < 0 or request.rating > 100:
            raise HTTPException(status_code=400, detail="Rating must be 0-100")
        post.rating = request.rating

    # Handle tags
    if request.tags is not None:
        # Clear existing post_tags
        post.post_tags.clear()
        tag_names = set([t.lower().strip() for t in request.tags if t.strip()])
        existing_tags = db.query(Tag).filter(Tag.name.in_(tag_names)).all()
        existing_names = [t.name for t in existing_tags]

        for name in tag_names:
            if name not in existing_names:
                tag = Tag(name=name)
                db.add(tag)
                existing_tags.append(tag)
        db.commit()

        for tag in existing_tags:
            post.post_tags.append(PostTag(tag_id=tag.id))

    db.commit()
    db.refresh(post)
    return {"message": "Post updated", "postId": post.id}


@app.delete("/api/posts/{post_id}")
def delete_post(
    post_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only delete your own posts")

    db.delete(post)
    db.commit()
    return {"message": "Post deleted", "postId": post.id}

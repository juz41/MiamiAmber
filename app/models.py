"""SQLAlchemy ORM models."""

from datetime import datetime

from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship

from .database import Base


class PostTag(Base):
    __tablename__ = "posts_tags"
    post_id = Column(Integer, ForeignKey("posts.id"), primary_key=True)
    tag_id = Column(Integer, ForeignKey("tags.id"), primary_key=True)


class Tag(Base):
    __tablename__ = "tags"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)

    post_tags = relationship("PostTag", backref="tag")


class Follow(Base):
    __tablename__ = "follows"
    follower_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    following_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)


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
        cascade="all, delete-orphan",
    )

    followers = relationship(
        "Follow",
        foreign_keys=[Follow.following_id],
        backref="following",
        cascade="all, delete-orphan",
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
    post_tags = relationship("PostTag", backref="post", cascade="all, delete-orphan")

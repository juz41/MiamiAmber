"""Pydantic request bodies."""

from typing import List, Optional

from pydantic import BaseModel


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

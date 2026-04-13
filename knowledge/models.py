"""Data models for the protoPen knowledge base."""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Paper:
    id: str  # arxiv ID
    title: str
    authors: list[str] = field(default_factory=list)
    abstract: str = ""
    summary: str = ""
    significance: str = "unknown"
    categories: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    pdf_path: str = ""
    source_url: str = ""
    published_at: str = ""
    discovered_at: str = ""
    read_at: str = ""
    notes: str = ""


@dataclass
class Finding:
    id: int = 0
    content: str = ""
    source: str = ""
    source_type: str = ""  # paper/blog/github/model_release
    topic: str = ""
    finding_type: str = ""  # insight/result/method/benchmark/recommendation
    significance: str = ""
    created_at: str = ""


@dataclass
class Topic:
    id: int = 0
    name: str = ""
    description: str = ""
    keywords: list[str] = field(default_factory=list)
    priority: int = 2
    active: bool = True
    created_at: str = ""
    last_scanned_at: str = ""


@dataclass
class Digest:
    id: int = 0
    title: str = ""
    content: str = ""
    digest_type: str = ""  # daily/weekly/deep_dive/comparison
    topic: str = ""
    papers_referenced: list[str] = field(default_factory=list)
    created_at: str = ""


@dataclass
class ModelRelease:
    id: int = 0
    model_id: str = ""
    name: str = ""
    organization: str = ""
    description: str = ""
    parameters: str = ""
    architecture: str = ""
    license: str = ""
    downloads: int = 0
    likes: int = 0
    source: str = ""  # huggingface/github
    released_at: str = ""
    discovered_at: str = ""
    notes: str = ""

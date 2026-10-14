"""Universal contract models for Cross-Stack API and Schema Consensus."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class HTTPMethod(str, Enum):
    """Standard HTTP verbs supported across frontend and backend."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


def normalize_route_path(path: str) -> str:
    """Normalizes parameterized route paths across Express (:id) and FastAPI/OpenAPI ({id}).

    Examples:
        /api/users/:userId -> /api/users/{}
        /api/users/{userId} -> /api/users/{}
        /api/v1/posts/:slug/comments -> /api/v1/posts/{}/comments
    """
    clean_path = path.strip()
    # Strip query parameters if present
    if "?" in clean_path:
        clean_path = clean_path.split("?")[0]
    # Replace :param_name with {}
    p1 = re.sub(r":\w+", "{}", clean_path)
    # Replace {param_name} with {}
    p2 = re.sub(r"\{\w+\}", "{}", p1)
    # Normalize duplicate slashes and trailing slashes (except root '/')
    norm = re.sub(r"/+", "/", p2)
    if len(norm) > 1 and norm.endswith("/"):
        norm = norm[:-1]
    return norm


@dataclass(frozen=True)
class SchemaField:
    """A field in a request or response schema."""

    name: str
    field_type: str = "any"
    required: bool = True


@dataclass(frozen=True)
class EndpointContract:
    """Canonical representation of an API endpoint contract."""

    method: HTTPMethod
    path_template: str
    query_params: List[str] = field(default_factory=list)
    body_fields: List[SchemaField] = field(default_factory=list)
    response_fields: List[SchemaField] = field(default_factory=list)
    normalized_path: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "normalized_path", normalize_route_path(self.path_template))


@dataclass(frozen=True)
class FrontendCall:
    """An API call initiated from frontend client code."""

    method: HTTPMethod
    raw_path: str
    normalized_path: str = field(init=False)
    query_params: List[str] = field(default_factory=list)
    payload_keys: List[str] = field(default_factory=list)
    file_path: str = ""
    line: int = 1

    def __post_init__(self) -> None:
        object.__setattr__(self, "normalized_path", normalize_route_path(self.raw_path))


@dataclass(frozen=True)
class BackendRoute:
    """A route endpoint exposed by backend server routers."""

    method: HTTPMethod
    path_template: str
    required_fields: List[str] = field(default_factory=list)
    optional_fields: List[str] = field(default_factory=list)
    query_params: List[str] = field(default_factory=list)
    normalized_path: str = field(init=False)
    file_path: str = ""
    line: int = 1

    def __post_init__(self) -> None:
        object.__setattr__(self, "normalized_path", normalize_route_path(self.path_template))

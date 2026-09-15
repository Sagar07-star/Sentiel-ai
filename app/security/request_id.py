"""
Sentinel AI
Request Correlation IDs
"""

from __future__ import annotations

from uuid import uuid4


def generate_request_id() -> str:
    """Generate a cryptographically random request identifier."""

    return uuid4().hex


__all__ = [
    "generate_request_id",
]
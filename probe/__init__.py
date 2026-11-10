"""probe — an agent-driven API security testing tool for authorised testing.

Public surface kept small on purpose; import the pieces you need.
"""
from .config import ProgramConfig
from .engine import RequestEngine
from .models import Request, Response
from .scope import ScopeError, ScopeGuard

__all__ = [
    "ProgramConfig",
    "RequestEngine",
    "Request",
    "Response",
    "ScopeGuard",
    "ScopeError",
]

"""probe — an agent-driven API security testing tool for authorised testing.

Public surface kept small on purpose; import the pieces you need.
"""
from .config import ProgramConfig
from .engine import RequestEngine
from .models import Request, Response
from .mutate import Mutation, discover_points, mutate
from .oracle import Signal, analyze
from .payloads import Payload, payloads_for
from .scope import ScopeError, ScopeGuard

__all__ = [
    "ProgramConfig",
    "RequestEngine",
    "Request",
    "Response",
    "ScopeGuard",
    "ScopeError",
    "mutate",
    "discover_points",
    "Mutation",
    "analyze",
    "Signal",
    "Payload",
    "payloads_for",
]

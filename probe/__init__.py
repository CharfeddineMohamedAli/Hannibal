"""probe — an agent-driven API security testing tool for authorised testing.

Public surface kept small on purpose; import the pieces you need.
"""
from .config import ProgramConfig
from .engine import RequestEngine
from .models import Request, Response
from .mutate import Mutation, discover_points, mutate
from .oracle import Signal, analyze
from .payloads import Payload, load_payload_file, payloads_for
from .agent import Agent
from .llm import AnthropicClient, FakeLLMClient, LLMClient, LLMResponse, ToolCall
from .scope import ScopeError, ScopeGuard
from .tools import Finding, Tools

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
    "load_payload_file",
    "Agent",
    "Tools",
    "Finding",
    "LLMClient",
    "LLMResponse",
    "ToolCall",
    "AnthropicClient",
    "FakeLLMClient",
]

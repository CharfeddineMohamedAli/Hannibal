"""Provider-neutral LLM interface for the agent loop.

The agent speaks to an LLMClient through one small surface — call(system,
history, tools) -> LLMResponse — so the provider can be swapped without touching
the loop. An Anthropic adapter is included; a FakeLLMClient (scripted) lets the
whole agent be tested offline, with no API key and no network.

History is kept in a neutral shape (plain dicts); each adapter translates it to
its provider's wire format.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict


@dataclass
class LLMResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)

    @property
    def done(self) -> bool:
        # The model is finished when it stops asking for tools.
        return not self.tool_calls


class LLMClient(ABC):
    @abstractmethod
    def call(self, system: str, history: list[dict], tools: list[dict]) -> LLMResponse:
        ...


class AnthropicClient(LLMClient):
    """Adapter for Anthropic's Messages API with tool use.

    `anthropic` is imported lazily so importing this module needs no SDK. Untested
    against the live API from this sandbox (no network); the translation mirrors
    the documented tool-use shape.
    """

    def __init__(self, model: str = "claude-sonnet-5-5", max_tokens: int = 2048, api_key: str | None = None):
        import anthropic

        self._client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
        self.model = model
        self.max_tokens = max_tokens

    @staticmethod
    def _to_messages(history: list[dict]) -> list[dict]:
        messages: list[dict] = []
        for ev in history:
            role = ev["role"]
            if role == "user":
                messages.append({"role": "user", "content": [{"type": "text", "text": ev["text"]}]})
            elif role == "assistant":
                content: list[dict] = []
                if ev.get("text"):
                    content.append({"type": "text", "text": ev["text"]})
                for c in ev.get("calls", []):
                    content.append({"type": "tool_use", "id": c["id"], "name": c["name"], "input": c["args"]})
                messages.append({"role": "assistant", "content": content})
            elif role == "tool":
                messages.append({"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": ev["id"], "content": ev["content"]}
                ]})
        return messages

    def call(self, system: str, history: list[dict], tools: list[dict]) -> LLMResponse:
        resp = self._client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            tools=tools,
            messages=self._to_messages(history),
        )
        text, calls = "", []
        for block in resp.content:
            if block.type == "text":
                text += block.text
            elif block.type == "tool_use":
                calls.append(ToolCall(id=block.id, name=block.name, args=dict(block.input)))
        return LLMResponse(text=text, tool_calls=calls)


class FakeLLMClient(LLMClient):
    """Replays a scripted list of LLMResponses, one per call. For offline tests."""

    def __init__(self, script: list[LLMResponse]):
        self._script = list(script)
        self.calls_seen = 0

    def call(self, system: str, history: list[dict], tools: list[dict]) -> LLMResponse:
        self.calls_seen += 1
        if not self._script:
            return LLMResponse(text="(script exhausted)")
        return self._script.pop(0)

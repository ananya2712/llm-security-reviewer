"""OpenAI-backed reviewer — the eval comparison model (PLAN §4).

Mirrors `AnthropicProvider` but for the OpenAI Chat Completions API. Same
prompt (`SYSTEM_PROMPT` + few-shot), same structured-output schema
(`ReviewResult`), same `Finding(source="llm")` mapping — so eval results differ
only by model, not by harness.

Differences from the Anthropic path:
- The system prompt is the first entry in `messages` (no separate `system`
  param); few-shot + diff follow.
- Schema enforcement is `chat.completions.parse(response_format=ReviewResult)`;
  the parsed model is on `choices[0].message.parsed`.
- A safety refusal surfaces as `message.refusal` (parsed is then None) — same
  degrade-to-`[]` policy as the Anthropic provider.
- No thinking/effort param (gpt-4o-class isn't a reasoning model).

`ReviewResult` is reused as-is: current OpenAI structured outputs accepts the
numeric range constraints (`confidence` 0–1, `start_line ≥ 1`) that the schema
carries, so there's no need for a constraint-free parallel model.
"""

from __future__ import annotations

from typing import Any

from ..diff import FileDiff
from ..models import Finding
from ..prompts import SYSTEM_PROMPT, ReviewResult, build_messages
from .base import ReviewProvider, to_findings

# PLAN §4 / §9: a GPT-4o-class model as the eval comparison. Override via the
# constructor.
DEFAULT_MODEL = "gpt-4o"


class OpenAIProvider(ReviewProvider):
    name = "openai"

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        *,
        client: Any | None = None,
        max_completion_tokens: int | None = None,
    ) -> None:
        self.model = model
        self._max_completion_tokens = max_completion_tokens
        if client is None:
            import openai

            client = openai.OpenAI()
        self._client = client

    def review_file(self, fd: FileDiff) -> list[Finding]:
        if not fd.hunks:
            return []

        messages = [{"role": "system", "content": SYSTEM_PROMPT}, *build_messages(fd)]
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "response_format": ReviewResult,
        }
        if self._max_completion_tokens is not None:
            kwargs["max_completion_tokens"] = self._max_completion_tokens

        completion = self._client.chat.completions.parse(**kwargs)
        message = completion.choices[0].message

        # A refusal leaves `parsed` empty; degrade to "no findings" rather than
        # raising so one refused file doesn't sink a diff run.
        if getattr(message, "refusal", None) or message.parsed is None:
            return []
        return to_findings(message.parsed)

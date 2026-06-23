"""Claude-backed reviewer (the primary, per PLAN §4).

Uses structured outputs (`messages.parse` + `output_format=ReviewResult`) so the
Pydantic schema is enforced and validated client-side, and adaptive thinking so
the model reasons about each diff before answering. The system prompt carries a
`cache_control` breakpoint; at v1 prompt sizes it's below Sonnet's min-cacheable
prefix (a no-op), but it earns the cost win for free once the prompt grows.
"""

from __future__ import annotations

from typing import Any

from ..diff import FileDiff
from ..models import Finding
from ..prompts import SYSTEM_PROMPT, ReviewResult, build_messages
from .base import ReviewProvider, to_findings

# PLAN §4: Claude Sonnet 4.6 is the primary reviewer (deliberate cost choice for
# the 50-diff x 2-model eval). Override via the constructor for the comparison
# run or local experiments.
DEFAULT_MODEL = "claude-sonnet-4-6"


class AnthropicProvider(ReviewProvider):
    name = "anthropic"

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        *,
        client: Any | None = None,
        max_tokens: int = 16000,
        thinking: bool = True,
    ) -> None:
        self.model = model
        self._max_tokens = max_tokens
        self._thinking = thinking
        if client is None:
            import anthropic

            client = anthropic.Anthropic()
        self._client = client

    def review_file(self, fd: FileDiff) -> list[Finding]:
        if not fd.hunks:
            return []

        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self._max_tokens,
            "system": [
                {
                    "type": "text",
                    "text": SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            "messages": build_messages(fd),
            "output_format": ReviewResult,
        }
        if self._thinking:
            kwargs["thinking"] = {"type": "adaptive"}

        resp = self._client.messages.parse(**kwargs)

        # A safety refusal yields no parsed output; degrade to "no findings"
        # rather than raising — a single refused file shouldn't sink a diff run.
        if getattr(resp, "stop_reason", None) == "refusal" or resp.parsed_output is None:
            return []
        return to_findings(resp.parsed_output)

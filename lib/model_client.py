"""Single integration point for the reasoning model.

The engine (and every agent runner) talks to the model only through here. Two backends:

* ``bedrock`` — AWS Bedrock Mantle OpenAI-compatible endpoint, model
  ``openai.gpt-oss-120b-1:0`` in ``ap-south-1``. Auth via ``AWS_BEARER_TOKEN_BEDROCK``.
* ``mock`` — a deterministic local backend for tests (``BLACKWING_MODEL_MOCK=1``), so the
  whole pipeline is exercisable with no network and no credentials.

stdlib-only: uses ``urllib`` rather than the openai/boto SDKs so it runs in the minimal
sandbox. Reasoning-model ``<reasoning>...</reasoning>`` prefixes are split off the answer
but preserved for audit.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

_REASONING_RE = re.compile(r"<reasoning>(.*?)</reasoning>", re.DOTALL)


@dataclass
class ModelResponse:
    content: str
    reasoning: str = ""
    raw: dict = field(default_factory=dict)


class ModelError(RuntimeError):
    pass


def _split_reasoning(text: str) -> tuple[str, str]:
    reasoning_parts = _REASONING_RE.findall(text or "")
    answer = _REASONING_RE.sub("", text or "").strip()
    return answer, "\n".join(reasoning_parts).strip()


class ModelClient:
    def __init__(
        self,
        region: Optional[str] = None,
        model: Optional[str] = None,
        bearer_token: Optional[str] = None,
        mock: Optional[bool] = None,
        timeout: int = 120,
    ) -> None:
        self.region = region or os.environ.get("AWS_REGION", "ap-south-1")
        self.model = model or os.environ.get("BLACKWING_MODEL", "openai.gpt-oss-120b-1:0")
        self.bearer_token = bearer_token or os.environ.get("AWS_BEARER_TOKEN_BEDROCK", "")
        self.timeout = timeout
        if mock is None:
            mock = os.environ.get("BLACKWING_MODEL_MOCK", "0") == "1"
        self.mock = mock
        self.base_url = (
            f"https://bedrock-runtime.{self.region}.amazonaws.com/openai/v1"
        )

    # -- public API ---------------------------------------------------------
    def chat(
        self,
        messages: list[dict],
        max_completion_tokens: int = 2048,
        temperature: float = 0.2,
        reasoning_effort: str = "low",
    ) -> ModelResponse:
        if self.mock:
            return self._mock_chat(messages)
        return self._bedrock_chat(
            messages, max_completion_tokens, temperature, reasoning_effort
        )

    def complete(self, prompt: str, system: Optional[str] = None, **kw) -> ModelResponse:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return self.chat(messages, **kw)

    # -- backends -----------------------------------------------------------
    def _bedrock_chat(
        self, messages, max_completion_tokens, temperature, reasoning_effort="low"
    ) -> ModelResponse:
        if not self.bearer_token:
            raise ModelError("AWS_BEARER_TOKEN_BEDROCK is not set")
        body = {
            "model": self.model,
            "messages": messages,
            "max_completion_tokens": max_completion_tokens,
            "temperature": temperature,
        }
        # gpt-oss is a reasoning model; without an effort cap it can spend the whole
        # token budget on <reasoning> and never emit the answer.
        if reasoning_effort:
            body["reasoning_effort"] = reasoning_effort
        payload = json.dumps(body).encode()
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.bearer_token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            raise ModelError(f"Bedrock HTTP {e.code}: {body[:300]}") from e
        except urllib.error.URLError as e:
            raise ModelError(f"Bedrock connection error: {e}") from e
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            raise ModelError(f"Unexpected Bedrock response shape: {data}") from e
        answer, reasoning = _split_reasoning(content)
        return ModelResponse(content=answer, reasoning=reasoning, raw=data)

    def _mock_chat(self, messages) -> ModelResponse:
        """Deterministic echo backend. Returns a JSON object when the last user message
        asks for JSON, otherwise a short acknowledgement. Enough to exercise the pipeline
        plumbing without a live model."""
        last = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                last = m.get("content", "")
                break
        if "json" in last.lower():
            return ModelResponse(content=json.dumps({"mock": True, "echo": last[:120]}))
        return ModelResponse(content=f"[mock] ack: {last[:160]}")

    # -- health -------------------------------------------------------------
    def ping(self) -> bool:
        try:
            r = self.chat(
                [{"role": "user", "content": "reply with exactly: BLACKWING_OK"}],
                max_completion_tokens=128,
            )
            return "BLACKWING_OK" in r.content or self.mock
        except ModelError:
            return False


def from_env() -> ModelClient:
    return ModelClient()

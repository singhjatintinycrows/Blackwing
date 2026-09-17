"""Codex ⇄ Bedrock shim.

Current Codex only speaks the OpenAI **Responses** API; AWS Bedrock's Mantle endpoint only
speaks **chat/completions**. This tiny proxy bridges them: it exposes ``POST /v1/responses``,
translates the request to a Bedrock chat/completions call (via lib.model_client), and streams
the answer back as the Responses SSE events Codex expects (created → output_item.added →
output_text.delta → output_item.done → completed). Tool/function calls are translated in both
directions so Codex can drive the agent team.

Run:  python -m tools.codex_bedrock_proxy   (reads AWS_* from the environment / .env)
Codex config points model_providers.bedrock.base_url at http://127.0.0.1:8791/v1
with wire_api = "responses".
"""
from __future__ import annotations

import json
import os
import sys
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from lib.model_client import ModelClient

app = FastAPI(title="codex-bedrock-proxy")


def _extract_messages(body: dict) -> list[dict]:
    """Translate a Responses request (instructions + input items) into chat messages."""
    messages: list[dict] = []
    if body.get("instructions"):
        messages.append({"role": "system", "content": str(body["instructions"])})
    inp = body.get("input", [])
    if isinstance(inp, str):
        messages.append({"role": "user", "content": inp})
        return messages
    for item in inp or []:
        itype = item.get("type", "message")
        if itype == "message":
            role = item.get("role", "user")
            parts = item.get("content", [])
            if isinstance(parts, str):
                text = parts
            else:
                text = "".join(
                    p.get("text", "") for p in parts
                    if p.get("type") in ("input_text", "output_text", "text"))
            messages.append({"role": role, "content": text})
        elif itype == "function_call_output":
            messages.append({"role": "tool", "tool_call_id": item.get("call_id", ""),
                             "content": str(item.get("output", ""))})
        elif itype == "function_call":
            messages.append({"role": "assistant", "content": "",
                             "tool_calls": [{"id": item.get("call_id", ""), "type": "function",
                                             "function": {"name": item.get("name", ""),
                                                          "arguments": item.get("arguments", "{}")}}]})
    return messages


def _convert_tools(body: dict):
    tools = body.get("tools")
    if not tools:
        return None
    out = []
    for t in tools:
        if t.get("type") == "function":
            # Responses uses a flat function shape; chat nests under "function".
            fn = t.get("function", t)
            out.append({"type": "function", "function": {
                "name": fn.get("name"), "description": fn.get("description", ""),
                "parameters": fn.get("parameters", {"type": "object", "properties": {}})}})
    return out or None


def _sse(obj: dict) -> str:
    return f"event: {obj['type']}\ndata: {json.dumps(obj)}\n\n"


@app.post("/v1/responses")
async def responses(request: Request):
    body = await request.json()
    messages = _extract_messages(body)
    tools = _convert_tools(body)
    client = ModelClient()

    # Non-streaming call to Bedrock; we synthesise the SSE stream Codex expects.
    extra = {}
    if tools:
        extra["tools"] = tools
    try:
        result = _chat(client, messages, tools)
    except Exception as e:  # surface as a response with the error text
        result = {"text": f"[proxy error] {e}", "tool_calls": []}

    resp_id = "resp_" + uuid.uuid4().hex
    msg_id = "msg_" + uuid.uuid4().hex

    def stream():
        yield _sse({"type": "response.created",
                    "response": {"id": resp_id, "object": "response", "status": "in_progress",
                                 "output": []}})
        output_items = []
        # Tool calls first (if any).
        for i, tc in enumerate(result["tool_calls"]):
            fc_id = "fc_" + uuid.uuid4().hex
            item = {"type": "function_call", "id": fc_id, "call_id": tc["id"],
                    "name": tc["name"], "arguments": tc["arguments"], "status": "completed"}
            yield _sse({"type": "response.output_item.added", "output_index": i, "item":
                        {**item, "status": "in_progress", "arguments": ""}})
            yield _sse({"type": "response.function_call_arguments.delta", "item_id": fc_id,
                        "output_index": i, "delta": tc["arguments"]})
            yield _sse({"type": "response.output_item.done", "output_index": i, "item": item})
            output_items.append(item)
        # Text message (if any).
        text = result["text"]
        if text:
            idx = len(output_items)
            yield _sse({"type": "response.output_item.added", "output_index": idx, "item":
                        {"type": "message", "id": msg_id, "role": "assistant",
                         "status": "in_progress", "content": []}})
            yield _sse({"type": "response.content_part.added", "item_id": msg_id,
                        "output_index": idx, "content_index": 0,
                        "part": {"type": "output_text", "text": "", "annotations": []}})
            yield _sse({"type": "response.output_text.delta", "item_id": msg_id,
                        "output_index": idx, "content_index": 0, "delta": text})
            yield _sse({"type": "response.output_text.done", "item_id": msg_id,
                        "output_index": idx, "content_index": 0, "text": text})
            msg_item = {"type": "message", "id": msg_id, "role": "assistant", "status": "completed",
                        "content": [{"type": "output_text", "text": text, "annotations": []}]}
            yield _sse({"type": "response.output_item.done", "output_index": idx, "item": msg_item})
            output_items.append(msg_item)
        yield _sse({"type": "response.completed", "response": {
            "id": resp_id, "object": "response", "status": "completed",
            "output": output_items,
            "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}}})

    return StreamingResponse(stream(), media_type="text/event-stream")


def _chat(client: ModelClient, messages, tools):
    """Call Bedrock and normalise into {text, tool_calls}."""
    import urllib.request, urllib.error
    body = {"model": client.model, "messages": messages,
            "max_completion_tokens": 4096, "temperature": 0.2, "reasoning_effort": "low"}
    if tools:
        body["tools"] = tools
    req = urllib.request.Request(
        f"{client.base_url}/chat/completions", data=json.dumps(body).encode(), method="POST",
        headers={"Authorization": f"Bearer {client.bearer_token}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=client.timeout) as r:
        data = json.loads(r.read().decode())
    choice = data["choices"][0]["message"]
    content = choice.get("content") or ""
    # strip <reasoning> like the model client does
    import re
    content = re.sub(r"<reasoning>.*?</reasoning>", "", content, flags=re.DOTALL).strip()
    tool_calls = []
    for tc in choice.get("tool_calls") or []:
        fn = tc.get("function", {})
        tool_calls.append({"id": tc.get("id") or ("call_" + uuid.uuid4().hex),
                           "name": fn.get("name", ""), "arguments": fn.get("arguments", "{}")})
    return {"text": content, "tool_calls": tool_calls}


@app.get("/health")
def health():
    return {"ok": True, "model": ModelClient().model}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("CODEX_PROXY_PORT", "8791"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")

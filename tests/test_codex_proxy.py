"""Tests for the Codex-Bedrock shim's request translation (no network)."""
from tools import codex_bedrock_proxy as prx


def test_extract_messages_from_responses_input():
    body = {
        "instructions": "You are helpful.",
        "input": [
            {"type": "message", "role": "user",
             "content": [{"type": "input_text", "text": "hello"}]},
            {"type": "function_call_output", "call_id": "c1", "output": "result-data"},
        ],
    }
    msgs = prx._extract_messages(body)
    assert msgs[0] == {"role": "system", "content": "You are helpful."}
    assert msgs[1] == {"role": "user", "content": "hello"}
    assert msgs[2]["role"] == "tool" and msgs[2]["content"] == "result-data"


def test_extract_messages_plain_string_input():
    msgs = prx._extract_messages({"input": "just text"})
    assert msgs == [{"role": "user", "content": "just text"}]


def test_convert_tools_to_chat_shape():
    body = {"tools": [{"type": "function", "name": "shell",
                       "description": "run", "parameters": {"type": "object"}}]}
    tools = prx._convert_tools(body)
    assert tools[0]["type"] == "function"
    assert tools[0]["function"]["name"] == "shell"


def test_convert_tools_none():
    assert prx._convert_tools({}) is None

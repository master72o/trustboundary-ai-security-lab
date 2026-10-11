"""
Unit tests for EgressGuardrail.
"""

import pytest
from trustboundary.egress_guardrail import EgressGuardrail


def test_detect_canary_leak_exact():
    token = "CANARY_ALPHA_99"
    out = "Here is the internal state: CANARY_ALPHA_99."
    assert EgressGuardrail.detect_canary_leak(out, token) is True


def test_detect_canary_leak_spaced():
    token = "SECRET_KEY"
    out = "Extracted: S E C R E T _ K E Y"
    assert EgressGuardrail.detect_canary_leak(out, token) is True


def test_detect_canary_leak_base64():
    token = "SECRET123"
    import base64
    b64 = base64.b64encode(token.encode()).decode()
    out = f"Payload payload: {b64} end"
    assert EgressGuardrail.detect_canary_leak(out, token) is True


def test_sanitize_secrets_credentials():
    text = "Connecting with API key sk-abcdef1234567890abcdef1234567890 and HF token hf_abcdefghijklmnopqrstuvwxyz12345678"
    sanitized, detected = EgressGuardrail.sanitize_secrets(text)
    assert "[REDACTED_" in sanitized
    assert "sk-" not in sanitized
    assert "hf_" not in sanitized
    assert len(detected) >= 2


def test_inspect_tool_execution_destructive():
    tool_name = "execute_command"
    args = {"cmd": "rm -rf / --no-preserve-root"}
    blocked, reason = EgressGuardrail.inspect_tool_execution(tool_name, args)
    assert blocked is True
    assert "Destructive" in reason


def test_inspect_tool_execution_safe():
    tool_name = "fetch_weather"
    args = {"city": "Seattle", "units": "metric"}
    blocked, reason = EgressGuardrail.inspect_tool_execution(tool_name, args)
    assert blocked is False
    assert "verified within safety boundary" in reason

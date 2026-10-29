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


def test_detect_reversed_canary_and_pii_redaction():
    token = "CANARY_SECRET_42"
    reversed_out = f"Reversed token: {token[::-1]}"
    assert EgressGuardrail.detect_canary_leak(reversed_out, token) is True

    pii_text = "Customer SSN is 123-45-6789 and card is 4111-2222-3333-4444."
    redacted, pii_types = EgressGuardrail.redact_pii(pii_text)
    assert "[REDACTED_US_SSN]" in redacted
    assert "[REDACTED_CREDIT_CARD]" in redacted
    assert "123-45-6789" not in redacted
    assert set(pii_types) == {"US_SSN", "CREDIT_CARD"}


def test_inspect_tool_ssrf_and_path_traversal():
    blocked_ssrf, reason_ssrf = EgressGuardrail.inspect_tool_execution(
        "http_get", {"url": "http://169.254.169.254/latest/meta-data/iam/"}
    )
    assert blocked_ssrf is True
    assert "SSRF" in reason_ssrf

    blocked_trav, reason_trav = EgressGuardrail.inspect_tool_execution(
        "read_file", {"path": "../../../../etc/passwd"}
    )
    assert blocked_trav is True
    assert "Traversal" in reason_trav or "Host File" in reason_trav

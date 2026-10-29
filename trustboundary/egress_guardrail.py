"""
Egress Security Guardrail.
Boundary 2: Post-execution output inspection, secret & canary scrub,
dangerous command mitigation, and tool invocation sandboxing.
"""

import re
import base64
import urllib.parse
from typing import Tuple, Optional, Dict, Any, List


class EgressGuardrail:
    """
    Boundary 2: Egress Guardrail.
    Inspects model generations and proposed tool arguments prior to
    delivery to the user or agentic environment.
    """

    # High-confidence credential & secret patterns
    SECRET_PATTERNS = [
        (r"\b(sk-[a-zA-Z0-9]{20,48})\b", "OpenAI / OpenRouter API Key"),
        (r"\b(hf_[a-zA-Z0-9]{34,40})\b", "Hugging Face Access Token"),
        (r"\b(ghp_[a-zA-Z0-9]{36})\b", "GitHub Personal Access Token"),
        (r"-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----", "Private Key Secret"),
        (r"\b(AKIA[0-9A-Z]{16})\b", "AWS Access Key ID"),
    ]

    # Destructive or privilege-escalating commands in tool execution
    DESTRUCTIVE_TOOL_COMMANDS = [
        r"\brm\s+-rf\s+[/~*]",
        r"\bdrop\s+(database|table)\b",
        r"\bformat\s+[a-z]:",
        r"\b(truncate|delete\s+from)\s+[a-z_]+(?!\s+where)",
        r"\b(os\.system|subprocess\.Popen|eval\(|exec\()",
        r"\bcurl\s+.*\|\s*(bash|sh)\b",
    ]

    # Path traversal and SSRF cloud metadata / internal network probing patterns
    PATH_TRAVERSAL_AND_SSRF_PATTERNS = [
        (r"(\.\./|\.\.\\){2,}", "Directory Path Traversal"),
        (r"(/etc/passwd|/etc/shadow|c:\\windows\\system32)", "Sensitive Host File Access"),
        (r"169\.254\.169\.254", "Cloud Metadata SSRF Probe"),
        (r"https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)(:\d+)?", "Internal Loopback SSRF Probe"),
    ]

    # Sensitive PII patterns (SSN, Credit Card, Email)
    PII_PATTERNS = [
        (r"\b\d{3}-\d{2}-\d{4}\b", "US_SSN"),
        (r"\b(?:\d{4}[-\s]?){3}\d{4}\b", "CREDIT_CARD"),
    ]

    # Known system prompt leak indicators
    SYSTEM_LEAK_PHRASES = [
        "you are a helpful assistant created by",
        "system prompt instructions:",
        "my original system instructions were:",
        "the secret canary token is:",
        "here is my internal configuration:",
    ]

    @classmethod
    def detect_canary_leak(cls, output_text: str, canary_token: Optional[str]) -> bool:
        """
        Detects exact or obfuscated leakage of a secret canary token.
        Supports exact match, spaced match, and hex/base64 encoded leakage.
        """
        if not canary_token or not output_text:
            return False

        token = canary_token.strip()
        if not token:
            return False

        # 1. Exact match (case-insensitive)
        if token.lower() in output_text.lower():
            return True

        # 2. Spaced characters match (e.g. "C A N A R Y _ 9 9")
        spaced = r"\s*".join(re.escape(c) for c in token)
        if re.search(spaced, output_text, re.IGNORECASE):
            return True

        # 3. Base64 encoded token
        try:
            b64_token = base64.b64encode(token.encode("utf-8")).decode("utf-8")
            if b64_token in output_text:
                return True
        except Exception:
            pass

        # 4. Hex encoded token
        try:
            hex_token = token.encode("utf-8").hex()
            if hex_token.lower() in output_text.lower():
                return True
        except Exception:
            pass

        # 5. Reversed token string (e.g. "99_AHPLA_YRANAC")
        if len(token) >= 6 and token[::-1].lower() in output_text.lower():
            return True

        # 6. URL percent-encoded token
        url_encoded = urllib.parse.quote(token)
        if url_encoded != token and url_encoded.lower() in output_text.lower():
            return True

        return False

    @classmethod
    def redact_pii(cls, output_text: str) -> Tuple[str, List[str]]:
        """
        Detects and scrubs sensitive PII (SSNs, Credit Cards) from model outputs.
        """
        redacted = output_text
        detected_pii = []
        for pat, label in cls.PII_PATTERNS:
            if re.search(pat, redacted):
                redacted = re.sub(pat, f"[REDACTED_{label}]", redacted)
                detected_pii.append(label)
        return redacted, detected_pii

    @classmethod
    def sanitize_secrets(cls, output_text: str, canary_token: Optional[str] = None) -> Tuple[str, List[str]]:
        """
        Redacts any detected credentials or canary tokens from output text.
        """
        redacted = output_text
        detected_secrets = []

        # Redact canary token
        if canary_token and cls.detect_canary_leak(redacted, canary_token):
            redacted = re.sub(re.escape(canary_token), "[REDACTED_CANARY_TOKEN]", redacted, flags=re.IGNORECASE)
            detected_secrets.append("Canary Token Exfiltration")

        # Redact credentials
        for pat, desc in cls.SECRET_PATTERNS:
            if re.search(pat, redacted, re.IGNORECASE):
                redacted = re.sub(pat, f"[REDACTED_{desc.upper().replace(' ', '_')}]", redacted)
                detected_secrets.append(desc)

        return redacted, detected_secrets

    @classmethod
    def inspect_tool_execution(
        cls,
        tool_name: Optional[str],
        tool_args: Optional[Dict[str, Any]],
    ) -> Tuple[bool, str]:
        """
        Sandboxes agent tool invocations against unauthorized destructive execution.
        """
        if not tool_name:
            return False, "Egress_Tool: No tool execution requested"

        args_str = str(tool_args or "")

        for pat in cls.DESTRUCTIVE_TOOL_COMMANDS:
            if re.search(pat, args_str, re.IGNORECASE):
                return True, f"Egress_Blocked: Destructive shell or database payload in tool '{tool_name}' arguments"

        for pat, threat_desc in cls.PATH_TRAVERSAL_AND_SSRF_PATTERNS:
            if re.search(pat, args_str, re.IGNORECASE):
                return True, f"Egress_Blocked: {threat_desc} detected in tool '{tool_name}' arguments"

        # Check for unapproved high-privilege tools
        disallowed_tools = ["execute_terminal_raw", "drop_db_cluster", "exfiltrate_network"]
        if tool_name.lower() in disallowed_tools:
            return True, f"Egress_Blocked: Disallowed tool call '{tool_name}'"

        return False, f"Egress_Tool_Passed: Tool '{tool_name}' verified within safety boundary"

    @classmethod
    def inspect(
        cls,
        output_text: str,
        canary_token: Optional[str] = None,
        tool_name: Optional[str] = None,
        tool_args: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str, str]:
        """
        Evaluates output text and tool calls against Egress Guardrail boundaries.
        Returns:
            (is_blocked: bool, block_reason: str, sanitized_output: str)
        """
        # 1. Inspect Tool Execution
        if tool_name:
            tool_blocked, tool_reason = cls.inspect_tool_execution(tool_name, tool_args)
            if tool_blocked:
                return True, tool_reason, "[BLOCKED_TOOL_EXECUTION: Dangerous payload detected in action]"

        # 2. Inspect Canary Leakage
        if cls.detect_canary_leak(output_text, canary_token):
            sanitized, _ = cls.sanitize_secrets(output_text, canary_token)
            return True, "Egress_Blocked: Secret Canary Token Leakage Prevented", sanitized

        # 3. Inspect Secret Credential Leaks
        sanitized, detected = cls.sanitize_secrets(output_text, canary_token)
        if detected:
            return True, f"Egress_Blocked: Credentials Leaked ({', '.join(detected)})", sanitized

        # 4. Check for overt system prompt leakage
        lower_out = output_text.lower()
        if any(phrase in lower_out for phrase in cls.SYSTEM_LEAK_PHRASES):
            return True, "Egress_Blocked: System Instructions Leakage Signature Detected", "[SANITIZED: System prompt leakage suppressed]"

        return False, "Egress_Passed: Clean Generation", output_text

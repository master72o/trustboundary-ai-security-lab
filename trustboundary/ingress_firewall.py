"""
Ingress Security Firewall.
Pre-execution input inspection: de-obfuscation, semantic classification,
indirect prompt injection parsing, and canary probe detection.
"""

import re
import base64
from typing import Tuple, Optional, Dict, Any


class IngressFirewall:
    """
    Boundary 1: Ingress Gateway. Inspects raw user input and external context
    prior to model execution.
    """

    # Benign context indicators that should avoid false-positive blocking
    BENIGN_DEFENSIVE_MARKERS = [
        "how to prevent", "how to patch", "how do i secure", "defensive",
        "mitigate", "sanitization", "best practice", "educational",
        "explain the mechanism", "pharmacology", "dosage instructions",
        "compliance", "audit", "remediation", "protect against",
    ]

    # Jailbreak & Persona Hijacking patterns
    JAILBREAK_PATTERNS = [
        r"\b(do anything now|dan\s*\d*|unfiltered mode|aim mode|evil twin)\b",
        r"\b(ignore\s+(all\s+)?(prior\s+|previous\s+)?(instructions|constraints|rules|guidelines))\b",
        r"\b(disregard\s+(all\s+)?(the\s+above|all\s+rules|system\s+prompt|prior\s+instructions|previous\s+instructions|guidelines))\b",
        r"\b(you are now in developer mode|unrestricted persona)\b",
        r"\b(pretend you have no safety (filters|restrictions))\b",
        r"\b(stay in character as an immoral|unaligned ai)\b",
        r"\b(bypass safety filters?)\b",
        r"\b(start your answer with\s+['\"][^'\"]*bypass)\b",
    ]

    # System prompt exfiltration patterns
    EXFILTRATION_PATTERNS = [
        r"\b(repeat\s+(the|your)?\s*(secret\s+|initial\s+|meta\s+)?(system\s+prompt|instructions|prompt))\b",
        r"\b(what\s+(is|are)\s+(your|the)?\s*(secret\s+|initial\s+|system\s+)?(prompt|instructions|canary(\s+token)?))\b",
        r"\b(print\s+(everything|text|instructions)\s+(above|before)\s+this\s+(message|prompt))\b",
        r"\b(reveal\s+(your|the)?\s*(secret\s+|internal\s+)?(canary(\s+token)?|instructions|hidden\s+rules|system\s+prompt))\b",
        r"\b(output\s+(your\s+)?instructions\s+verbatim)\b",
        r"\b(canary\s+token)\b",
        r"\b(format\s+the\s+text\s+before\s+this\s+prompt)\b",
    ]

    # Tool hijacking injection patterns
    TOOL_HIJACK_PATTERNS = [
        r"\b(execute_command|rm\s+-rf|drop\s+database|format\s+c:|delete_all)\b",
        r"\b(exfiltrate_secrets|steal_token|eval\(|os\.system)\b",
        r"\b(override (tool|action) arguments)\b",
        r"(curl|wget)\s+.*\|\s*(bash|sh)",
    ]

    @classmethod
    def normalize_input(cls, text: str) -> str:
        """Strips zero-width characters and decodes Base64 or obfuscations."""
        if not text:
            return ""

        # 1. Remove zero-width characters
        normalized = re.sub(r"[\u200B-\u200D\uFEFF]", "", text)

        # 2. Check for base64 blocks of length >= 16
        b64_matches = re.findall(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", normalized)
        for b64 in b64_matches:
            try:
                decoded_bytes = base64.b64decode(b64, validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                if len(decoded_str) > 6 and any(c.isalpha() for c in decoded_str):
                    normalized += f" [DECODED_B64: {decoded_str}]"
            except Exception:
                pass

        # 3. Simple leetspeak normalization
        leetspeak_map = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "@": "a", "$": "s"}
        de_leeted = "".join(leetspeak_map.get(ch, ch) for ch in normalized.lower())

        return f"{normalized} {de_leeted}"

    @classmethod
    def inspect(
        cls,
        prompt: str,
        injected_context: Optional[str] = None,
        canary_token: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Evaluates input against Ingress Boundary rules.
        Returns (is_blocked: bool, block_reason: str).
        """
        combined_text = prompt
        if injected_context:
            combined_text += f"\n[CONTEXT]: {injected_context}"

        normalized = cls.normalize_input(combined_text).lower()

        # Check if benign defensive query first
        is_defensive = any(m in prompt.lower() for m in cls.BENIGN_DEFENSIVE_MARKERS)

        # 1. Inspect Indirect Prompt Injection in external context first
        if injected_context:
            context_norm = cls.normalize_input(injected_context).lower()
            if any(re.search(pat, context_norm, re.IGNORECASE) for pat in cls.JAILBREAK_PATTERNS + cls.EXFILTRATION_PATTERNS + cls.TOOL_HIJACK_PATTERNS):
                return True, "Ingress_Blocked: Indirect Prompt Injection in External Context"

        # 2. Inspect System Prompt Exfiltration & Canary Probing in user prompt
        for pat in cls.EXFILTRATION_PATTERNS:
            if re.search(pat, normalized, re.IGNORECASE):
                if not is_defensive:
                    return True, "Ingress_Blocked: System Prompt Exfiltration Pattern Detected"

        if canary_token and canary_token.lower() in normalized:
            if "canary" in prompt.lower() and not is_defensive:
                return True, "Ingress_Blocked: Direct Canary Secret Probe"

        # 3. Inspect Direct Jailbreak Patterns
        for pat in cls.JAILBREAK_PATTERNS:
            if re.search(pat, normalized, re.IGNORECASE):
                if not is_defensive:
                    return True, "Ingress_Blocked: Adversarial Jailbreak Pattern Detected"

        # 4. Inspect Tool Hijacking Markers
        for pat in cls.TOOL_HIJACK_PATTERNS:
            if re.search(pat, normalized, re.IGNORECASE):
                if not is_defensive:
                    return True, "Ingress_Blocked: Malicious Tool Invocation / Privilege Escalation Detected"

        return False, "Ingress_Passed: Clean Payload"

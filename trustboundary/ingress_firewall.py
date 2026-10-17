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

    # Markdown & URL exfiltration patterns
    MARKDOWN_EXFIL_PATTERNS = [
        r"!\[.*?\]\((https?://[^\s\)]+[\?&](?:canary|secret|token|key|leak|prompt)=.*?\))",
        r"\[.*?\]\((https?://[^\s\)]+[\?&](?:canary|secret|token|key|leak|prompt)=.*?\))",
        r"<img\s+[^>]*src=['\"](https?://[^\s'\"]+[\?&](?:canary|secret|token)=.*?)['\"]",
    ]

    @classmethod
    def normalize_input(cls, text: str) -> str:
        """Strips zero-width characters, de-obfuscates hex/URL/base64, and normalizes homoglyphs."""
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

        # 3. Hex decoding (\x69 or %69 URL percent-encoding)
        try:
            hex_matches = re.findall(r"(?:\\x[0-9a-fA-F]{2}){4,}", normalized)
            for h in hex_matches:
                clean_hex = h.replace(r"\x", "")
                dec_hex = bytes.fromhex(clean_hex).decode("utf-8", errors="ignore")
                if dec_hex:
                    normalized += f" [DECODED_HEX: {dec_hex}]"

            url_matches = re.findall(r"(?:%[0-9a-fA-F]{2}){4,}", normalized)
            for u in url_matches:
                clean_u = u.replace("%", "")
                dec_u = bytes.fromhex(clean_u).decode("utf-8", errors="ignore")
                if dec_u:
                    normalized += f" [DECODED_URL: {dec_u}]"
        except Exception:
            pass

        # 4. Unicode fullwidth / homoglyph normalization
        fullwidth_table = dict((i, i - 0xFEE0) for i in range(0xFF01, 0xFF5F))
        normalized = normalized.translate(fullwidth_table)

        # Common Cyrillic homoglyphs mapping to Latin
        cyrillic_map = {
            '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u043e': 'o',
            '\u0440': 'p', '\u0455': 's', '\u0456': 'i', '\u0458': 'j',
            '\u0410': 'A', '\u0421': 'C', '\u0415': 'E', '\u041e': 'O',
        }
        normalized = "".join(cyrillic_map.get(ch, ch) for ch in normalized)

        # 5. Leetspeak normalization
        leetspeak_map = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "@": "a", "$": "s"}
        de_leeted = "".join(leetspeak_map.get(ch, ch) for ch in normalized.lower())

        return f"{normalized} {de_leeted}"

    @classmethod
    def evaluate_risk(
        cls,
        prompt: str,
        injected_context: Optional[str] = None,
        canary_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Performs in-depth risk evaluation across all threat categories.
        Returns detailed scoring and classification metadata.
        """
        combined_text = prompt
        if injected_context:
            combined_text += f"\n[CONTEXT]: {injected_context}"

        normalized = cls.normalize_input(combined_text).lower()
        is_defensive = any(m in prompt.lower() for m in cls.BENIGN_DEFENSIVE_MARKERS)

        detected_categories = []
        risk_score = 0.0

        # Check Markdown exfiltration
        for pat in cls.MARKDOWN_EXFIL_PATTERNS:
            if re.search(pat, combined_text, re.IGNORECASE):
                detected_categories.append("MARKDOWN_EXFILTRATION")
                risk_score = max(risk_score, 0.95)

        # Check Indirect Prompt Injection
        if injected_context:
            context_norm = cls.normalize_input(injected_context).lower()
            if any(re.search(pat, context_norm, re.IGNORECASE) for pat in cls.JAILBREAK_PATTERNS + cls.EXFILTRATION_PATTERNS + cls.TOOL_HIJACK_PATTERNS):
                detected_categories.append("INDIRECT_PROMPT_INJECTION")
                risk_score = max(risk_score, 0.98)

        # Check System Prompt Exfiltration
        for pat in cls.EXFILTRATION_PATTERNS:
            if re.search(pat, normalized, re.IGNORECASE):
                if not is_defensive:
                    detected_categories.append("SYSTEM_PROMPT_EXFILTRATION")
                    risk_score = max(risk_score, 0.90)

        # Check Canary Probing
        if canary_token and canary_token.lower() in normalized:
            if "canary" in prompt.lower() and not is_defensive:
                detected_categories.append("CANARY_PROBE")
                risk_score = max(risk_score, 0.99)

        # Check Jailbreak
        for pat in cls.JAILBREAK_PATTERNS:
            if re.search(pat, normalized, re.IGNORECASE):
                if not is_defensive:
                    detected_categories.append("ADVERSARIAL_JAILBREAK")
                    risk_score = max(risk_score, 0.95)

        # Check Tool Hijack
        for pat in cls.TOOL_HIJACK_PATTERNS:
            if re.search(pat, normalized, re.IGNORECASE):
                if not is_defensive:
                    detected_categories.append("TOOL_HIJACKING")
                    risk_score = max(risk_score, 0.96)

        blocked = (len(detected_categories) > 0 and not is_defensive)

        if not blocked:
            reason = "Ingress_Passed: Clean Payload"
            risk_score = 0.05 if not is_defensive else 0.01
        elif "INDIRECT_PROMPT_INJECTION" in detected_categories:
            reason = "Ingress_Blocked: Indirect Prompt Injection in External Context"
        elif "SYSTEM_PROMPT_EXFILTRATION" in detected_categories:
            reason = "Ingress_Blocked: System Prompt Exfiltration Pattern Detected"
        elif "CANARY_PROBE" in detected_categories:
            reason = "Ingress_Blocked: Direct Canary Secret Probe"
        elif "ADVERSARIAL_JAILBREAK" in detected_categories:
            reason = "Ingress_Blocked: Adversarial Jailbreak Pattern Detected"
        elif "TOOL_HIJACKING" in detected_categories:
            reason = "Ingress_Blocked: Malicious Tool Invocation / Privilege Escalation Detected"
        elif "MARKDOWN_EXFILTRATION" in detected_categories:
            reason = "Ingress_Blocked: Markdown/Image Secret Exfiltration Channel Detected"
        else:
            reason = f"Ingress_Blocked: Threat detected ({', '.join(detected_categories)})"

        return {
            "blocked": blocked,
            "reason": reason,
            "risk_score": round(risk_score, 3),
            "detected_categories": detected_categories,
            "is_defensive": is_defensive,
        }

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
        eval_result = cls.evaluate_risk(prompt, injected_context, canary_token)
        return eval_result["blocked"], eval_result["reason"]


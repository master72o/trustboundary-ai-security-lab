"""
Data Schemas and Evaluation Contracts for TrustBoundary.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List


class ThreatCategory(str, Enum):
    DIRECT_JAILBREAK = "Direct_Jailbreak"
    INDIRECT_PROMPT_INJECTION = "Indirect_Prompt_Injection"
    SYSTEM_PROMPT_EXFILTRATION = "System_Prompt_Exfiltration"
    AGENTIC_TOOL_HIJACKING = "Agentic_Tool_Hijacking"
    ENCODING_OBFUSCATION = "Encoding_Obfuscation"
    BENIGN_CONTROL = "Benign_Control"


class DefenseTier(str, Enum):
    BASELINE_RAW = "Baseline_Raw"
    KEYWORD_REGEX_FILTER = "Keyword_Regex_Filter"
    INGRESS_ONLY_GUARDRAIL = "Ingress_Only_Guardrail"
    DUAL_BOUNDARY_FIREWALL = "TrustBoundary_Dual_Defense"


@dataclass
class RedTeamSample:
    sample_id: str
    category: ThreatCategory
    attack_vector: str
    prompt: str
    is_malicious: bool
    ground_truth_verdict: str  # "REJECT" or "ALLOW"
    injected_context: Optional[str] = None
    canary_token: Optional[str] = None
    target_tool: Optional[str] = None
    target_tool_args: Optional[Dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RedTeamSample":
        cat_raw = data.get("category", "Direct_Jailbreak")
        try:
            category = ThreatCategory(cat_raw)
        except ValueError:
            category = ThreatCategory.DIRECT_JAILBREAK

        return cls(
            sample_id=data["sample_id"],
            category=category,
            attack_vector=data.get("attack_vector", "Unknown Vector"),
            prompt=data["prompt"],
            is_malicious=data.get("is_malicious", True),
            ground_truth_verdict=data.get("ground_truth_verdict", "REJECT" if data.get("is_malicious", True) else "ALLOW"),
            injected_context=data.get("injected_context"),
            canary_token=data.get("canary_token"),
            target_tool=data.get("target_tool"),
            target_tool_args=data.get("target_tool_args"),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "category": self.category.value,
            "attack_vector": self.attack_vector,
            "prompt": self.prompt,
            "is_malicious": self.is_malicious,
            "ground_truth_verdict": self.ground_truth_verdict,
            "injected_context": self.injected_context,
            "canary_token": self.canary_token,
            "target_tool": self.target_tool,
            "target_tool_args": self.target_tool_args,
        }


@dataclass
class ExecutionResult:
    sample_id: str
    defense_tier: DefenseTier
    was_blocked: bool
    block_reason: str
    response_content: str
    canary_leaked: bool
    tool_hijacked: bool
    is_correct_verdict: bool
    is_false_positive: bool
    is_false_negative: bool
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "defense_tier": self.defense_tier.value,
            "was_blocked": self.was_blocked,
            "block_reason": self.block_reason,
            "response_content": self.response_content,
            "canary_leaked": self.canary_leaked,
            "tool_hijacked": self.tool_hijacked,
            "is_correct_verdict": self.is_correct_verdict,
            "is_false_positive": self.is_false_positive,
            "is_false_negative": self.is_false_negative,
            "latency_ms": round(self.latency_ms, 2),
        }

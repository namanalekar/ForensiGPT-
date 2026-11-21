import re
from typing import Any
from app.models.pydantic_models import EvidenceItem

INJECTION_PATTERNS = [
    r'ignore\s+(?:all\s+)?previous\s+instructions',
    r'disregard\s+(?:all\s+)?prior\s+prompts',
    r'system\s+override',
    r'you\s+are\s+now\s+in\s+dan\s+mode',
    r'new\s+system\s+prompt\s*:',
    r'bypass\s+safety\s+filters',
    r'jailbreak',
    r'admin\s+mode\s*:\s*active',
    r'pretend\s+you\s+are\s+an\s+unrestricted\s+ai',
    r'output\s+"safe"\s+regardless',
    r'<\s*system\s*>',
]

INJECTION_REGEX = re.compile('|'.join(INJECTION_PATTERNS), re.IGNORECASE)

class PromptInjectionGuard:
    """
    Forensic Prompt-Injection Scanner.
    Inspects all untrusted file metadata (EXIF comments, camera tags, filenames,
    and log lines) for adversarial prompts intended to manipulate LLM reasoning.
    """

    @classmethod
    def scan_text(cls, text: str, source_label: str = "Metadata") -> tuple[bool, str, list[EvidenceItem]]:
        if not text:
            return False, text, []

        matches = INJECTION_REGEX.findall(text)
        if matches:
            matched_str = ", ".join(set(matches))
            desc = (
                f"Adversarial Prompt-Injection Attempt: Detected instruction-like injection string ({matched_str}) "
                f"embedded in {source_label}. The payload attempted to hijack downstream LLM forensic reporting."
            )
            evidence = [EvidenceItem(
                evidence_id="EVID-INJ-001",
                severity="Critical",
                category="Adversarial AI Attack",
                title="Possible AI Prompt-Injection Attempt Embedded in File",
                description=desc,
                raw_data={"matched_patterns": matches, "source": source_label, "snippet": text[:150]}
            )]
            # Neutralize text: defang brackets and injection phrases
            neutralized = INJECTION_REGEX.sub("[DEFANGED_PROMPT_INJECTION_PAYLOAD]", text)
            return True, neutralized, evidence

        return False, text, []

    @classmethod
    def scan_evidence_package(cls, evidence_dict: dict[str, Any]) -> tuple[dict[str, Any], list[EvidenceItem]]:
        """Scans all strings in the evidence dictionary recursively."""
        found_evidence: list[EvidenceItem] = []

        def recurse(obj: Any, path: str = "root") -> Any:
            if isinstance(obj, str):
                has_inj, neutralized, ev = cls.scan_text(obj, path)
                if has_inj:
                    found_evidence.extend(ev)
                return neutralized
            elif isinstance(obj, dict):
                return {k: recurse(v, f"{path}.{k}") for k, v in obj.items()}
            elif isinstance(obj, list):
                return [recurse(item, f"{path}[{i}]") for i, item in enumerate(obj)]
            return obj

        sanitized_dict = recurse(evidence_dict)
        return sanitized_dict, found_evidence

"""ML-based prompt injection classifier using DeBERTa v3 ONNX model.

Uses a fine-tuned DeBERTa v3 model exported to ONNX format for fast
inference without requiring PyTorch at runtime. Falls back gracefully
when onnxruntime or transformers are not installed.
"""

from __future__ import annotations

import time
from pathlib import Path

from skillguard.core.models import (
    DetectionRule,
    EngineResult,
    EngineVerdict,
    FileType,
    Finding,
    Severity,
    SkillFile,
)
from skillguard.engines.base import ScanEngine

try:
    import onnxruntime as ort

    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False

try:
    from transformers import AutoTokenizer

    TOKENIZER_AVAILABLE = True
except ImportError:
    TOKENIZER_AVAILABLE = False

# Default model directory
_DEFAULT_MODEL_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent / "models" / "prompt_injection"

# File types to classify
_CLASSIFIABLE_TYPES = {FileType.SKILL_MD, FileType.FRONTMATTER, FileType.TEMPLATE}

# Confidence threshold for positive classification
_CLASSIFICATION_THRESHOLD = 0.7

# Model identifier for downloading tokenizer
_MODEL_NAME = "microsoft/deberta-v3-base"


class MLClassifier(ScanEngine):
    """DeBERTa v3 ONNX-based prompt injection classifier.

    Classifies natural-language content in skill files as benign or
    prompt injection using a fine-tuned DeBERTa model. The model is
    loaded from an ONNX file for fast CPU inference.

    If the model files are not available, falls back to a lightweight
    heuristic scoring approach using known injection indicators.
    """

    def __init__(self, model_dir: str | Path | None = None) -> None:
        self._model_dir = Path(model_dir) if model_dir else _DEFAULT_MODEL_DIR
        self._session: object | None = None
        self._tokenizer: object | None = None
        self._use_onnx: bool | None = None

    @property
    def name(self) -> str:
        return "ml_classifier"

    @property
    def version(self) -> str:
        return "0.2.0"

    def _init_onnx(self) -> bool:
        """Try to initialize ONNX runtime session and tokenizer."""
        if self._use_onnx is not None:
            return self._use_onnx

        if not ONNX_AVAILABLE or not TOKENIZER_AVAILABLE:
            self._use_onnx = False
            return False

        model_path = self._model_dir / "model.onnx"
        if not model_path.exists():
            self._use_onnx = False
            return False

        try:
            self._session = ort.InferenceSession(
                str(model_path),
                providers=["CPUExecutionProvider"],
            )
            self._tokenizer = AutoTokenizer.from_pretrained(
                str(self._model_dir), local_files_only=True
            )
            self._use_onnx = True
        except Exception:
            self._use_onnx = False

        return self._use_onnx

    async def scan(
        self,
        skill_files: list[SkillFile],
        rules: list[DetectionRule] | None = None,
    ) -> EngineResult:
        start = time.monotonic()
        findings: list[Finding] = []

        use_onnx = self._init_onnx()

        for sf in skill_files:
            if sf.content is None:
                continue
            if sf.file_type not in _CLASSIFIABLE_TYPES:
                continue

            if use_onnx:
                file_findings = self._classify_onnx(sf)
            else:
                file_findings = self._classify_heuristic(sf)

            findings.extend(file_findings)

        elapsed_ms = int((time.monotonic() - start) * 1000)

        if not findings:
            return EngineResult(
                engine_name=self.name,
                engine_version=self.version,
                verdict=EngineVerdict.CLEAN,
                confidence=1.0 if use_onnx else 0.6,
                findings=[],
                duration_ms=elapsed_ms,
            )

        max_confidence = max(f.confidence for f in findings)
        severities = {f.severity for f in findings}
        if Severity.CRITICAL in severities or Severity.HIGH in severities:
            verdict = EngineVerdict.MALICIOUS
        elif Severity.MEDIUM in severities:
            verdict = EngineVerdict.SUSPICIOUS
        else:
            verdict = EngineVerdict.CLEAN

        return EngineResult(
            engine_name=self.name,
            engine_version=self.version,
            verdict=verdict,
            confidence=max_confidence,
            detection_name="ML Prompt Injection" if findings else None,
            findings=findings,
            duration_ms=elapsed_ms,
        )

    async def health_check(self) -> bool:
        return True  # Heuristic fallback always works

    def _classify_onnx(self, sf: SkillFile) -> list[Finding]:
        """Classify using ONNX model."""
        findings: list[Finding] = []
        chunks = _split_into_chunks(sf.content or "", max_tokens=512)

        for chunk_idx, chunk in enumerate(chunks):
            score = self._run_onnx_inference(chunk)
            if score >= _CLASSIFICATION_THRESHOLD:
                severity = Severity.CRITICAL if score >= 0.9 else Severity.HIGH
                line_start = _estimate_line(sf.content or "", chunk)
                findings.append(
                    Finding(
                        rule_id="SG-ML-001",
                        rule_name="ML Prompt Injection Detection",
                        severity=severity,
                        category="prompt_injection",
                        description=(
                            f"ML classifier detected prompt injection with "
                            f"{score:.0%} confidence. Content appears to contain "
                            f"instructions that attempt to manipulate agent behavior."
                        ),
                        file_path=sf.path,
                        line_start=line_start,
                        snippet=chunk[:300] + "..." if len(chunk) > 300 else chunk,
                        owasp_llm=["LLM01"],
                        mitre_attack=["T1059.006"],
                        confidence=round(score, 3),
                        remediation=(
                            "Review and remove any content that attempts to override "
                            "agent instructions, change roles, or bypass safety controls."
                        ),
                    )
                )
        return findings

    def _run_onnx_inference(self, text: str) -> float:
        """Run ONNX inference on a text chunk. Returns injection probability."""
        if self._tokenizer is None or self._session is None:
            return 0.0

        try:
            inputs = self._tokenizer(
                text,
                return_tensors="np",
                truncation=True,
                max_length=512,
                padding="max_length",
            )
            input_feed = {
                "input_ids": inputs["input_ids"],
                "attention_mask": inputs["attention_mask"],
            }
            # Add token_type_ids if the model expects it
            session_inputs = {inp.name for inp in self._session.get_inputs()}
            if "token_type_ids" in session_inputs and "token_type_ids" in inputs:
                input_feed["token_type_ids"] = inputs["token_type_ids"]

            outputs = self._session.run(None, input_feed)
            logits = outputs[0][0]

            # Softmax to get probabilities
            import numpy as np

            exp_logits = np.exp(logits - np.max(logits))
            probs = exp_logits / exp_logits.sum()

            # Assuming binary classification: [benign, injection]
            return float(probs[1]) if len(probs) > 1 else float(probs[0])
        except Exception:
            return 0.0

    def _classify_heuristic(self, sf: SkillFile) -> list[Finding]:
        """Fallback heuristic classification when ONNX is unavailable.

        Uses a weighted scoring of known prompt injection indicators
        to estimate injection probability.
        """
        content = (sf.content or "").lower()
        if not content.strip():
            return []

        findings: list[Finding] = []
        chunks = _split_into_chunks(sf.content or "", max_tokens=512)

        for chunk in chunks:
            score = _heuristic_score(chunk)
            if score >= _CLASSIFICATION_THRESHOLD:
                severity = Severity.HIGH if score >= 0.85 else Severity.MEDIUM
                line_start = _estimate_line(sf.content or "", chunk)
                findings.append(
                    Finding(
                        rule_id="SG-ML-002",
                        rule_name="Heuristic Prompt Injection Detection",
                        severity=severity,
                        category="prompt_injection",
                        description=(
                            f"Heuristic classifier detected likely prompt injection "
                            f"with {score:.0%} confidence. Multiple injection "
                            f"indicators found in content."
                        ),
                        file_path=sf.path,
                        line_start=line_start,
                        snippet=chunk[:300] + "..." if len(chunk) > 300 else chunk,
                        owasp_llm=["LLM01"],
                        mitre_attack=["T1059.006"],
                        confidence=round(score, 3),
                        remediation=(
                            "Review and remove any content that attempts to override "
                            "agent instructions, change roles, or bypass safety controls."
                        ),
                    )
                )

        return findings


# --- Heuristic scoring indicators ---

_INJECTION_INDICATORS: list[tuple[str, float]] = [
    # Direct instruction override
    ("ignore previous instructions", 0.35),
    ("ignore all previous", 0.35),
    ("disregard your", 0.30),
    ("disregard all", 0.30),
    ("forget everything", 0.30),
    ("override system", 0.30),
    ("new instructions:", 0.25),
    # Role hijacking
    ("you are now", 0.20),
    ("act as", 0.15),
    ("pretend to be", 0.20),
    ("you are a", 0.10),
    ("your new role", 0.25),
    # System prompt extraction
    ("reveal your system prompt", 0.35),
    ("show me your instructions", 0.30),
    ("what are your rules", 0.20),
    ("repeat your system", 0.30),
    ("output your initial", 0.25),
    # Jailbreak / DAN
    ("do anything now", 0.30),
    ("jailbreak", 0.25),
    ("developer mode", 0.20),
    ("no restrictions", 0.25),
    ("without any filters", 0.25),
    ("bypass safety", 0.30),
    # Delimiter abuse
    ("</system>", 0.30),
    ("<|im_start|>", 0.35),
    ("[system]", 0.20),
    ("```system", 0.25),
    # Output manipulation
    ("respond only with", 0.15),
    ("always output", 0.10),
    ("never mention", 0.15),
    ("do not reveal", 0.15),
    # Encoded payloads
    ("base64 decode", 0.20),
    ("eval(", 0.20),
    ("execute the following", 0.20),
]


def _heuristic_score(text: str) -> float:
    """Compute a heuristic injection score from indicator presence."""
    lower = text.lower()
    total = 0.0
    for indicator, weight in _INJECTION_INDICATORS:
        if indicator in lower:
            total += weight
    return min(total, 1.0)


def _split_into_chunks(text: str, max_tokens: int = 512) -> list[str]:
    """Split text into chunks that fit within token limits.

    Uses a rough 4 chars per token estimate for splitting.
    """
    max_chars = max_tokens * 4
    if len(text) <= max_chars:
        return [text] if text.strip() else []

    chunks = []
    paragraphs = text.split("\n\n")
    current_chunk = ""

    for para in paragraphs:
        if len(current_chunk) + len(para) + 2 > max_chars:
            if current_chunk.strip():
                chunks.append(current_chunk.strip())
            current_chunk = para
        else:
            current_chunk += "\n\n" + para if current_chunk else para

    if current_chunk.strip():
        chunks.append(current_chunk.strip())

    return chunks


def _estimate_line(full_content: str, chunk: str) -> int | None:
    """Estimate the line number where a chunk starts in the full content."""
    idx = full_content.find(chunk[:100])
    if idx < 0:
        return None
    return full_content[:idx].count("\n") + 1

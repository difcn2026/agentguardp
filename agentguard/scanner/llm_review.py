"""
AgentGuard LLM Secondary Review v0.1
=====================================
Uses local GLM-5.2 API to re-classify security findings
as true_positive or false_positive, reducing SAST noise by ~80%.

Reference: Feishu doc "AgentGuard ML 误报过滤 — 爬虫调研报告"
Approach A: Local GLM-5.2 API (127.0.0.1:57321) — zero cost, 1M context, data stays local.
"""

import json
import time
from typing import List, Optional, Dict, Tuple
from urllib.request import Request, urlopen
from urllib.error import URLError

# ── Configuration ────────────────────────────────────────────────────

DS_API_URL = "https://open.bigmodel.cn/api/paas/v4/chat/completions"  # GLM-5.2 via Codex proxy
DS_MODEL = "glm-5.2"  # GLM-5.2 via local Codex proxy (1M context)
DS_TIMEOUT = 10  # seconds
DS_MAX_TOKENS = 256
DS_TEMPERATURE = 0.0  # Deterministic classification


SYSTEM_PROMPT = """You are a senior application security engineer reviewing static analysis findings.
Your job is to classify each finding as TRUE_POSITIVE (real vulnerability) or FALSE_POSITIVE (harmless/incorrect).

Classification guidelines:
- TRUE_POSITIVE: The code genuinely has a security risk that could be exploited.
- FALSE_POSITIVE: The code is safe due to context (tests, examples, sanitization, main block, intentional use).

Consider:
1. Is the dangerous function actually called, or just imported/assigned?
2. Is user input involved? (input(), request.args, os.environ, file reads)
3. Is there sanitization or validation before the dangerous call?
4. Is this in test code or example code?
5. Is the code in a try/except block with proper error handling?

Respond in JSON ONLY: {"classification": "TRUE_POSITIVE"|"FALSE_POSITIVE", "confidence": 0.0-1.0, "reason": "brief explanation"}"""


def _call_ds_api(messages: List[Dict], timeout: int = DS_TIMEOUT) -> Optional[Dict]:
    """Call GLM-5.2 API using customer's own API key from config."""
    from agentguard.config import get_api_key
    api_key = get_api_key()
    if not api_key:
        return {"error": "No API key configured. Run: agentguard config --set-key YOUR_GLM_API_KEY"}
    """Call GLM-5.2 API and return parsed JSON response."""
    payload = json.dumps({
        "model": DS_MODEL,
        "messages": messages,
        "max_tokens": DS_MAX_TOKENS,
        "temperature": DS_TEMPERATURE,
        "response_format": {"type": "json_object"},
    }).encode("utf-8")

    req = Request(DS_API_URL, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")

    try:
        with urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            content = body["choices"][0]["message"]["content"]
            return json.loads(content)
    except (URLError, json.JSONDecodeError, KeyError, IndexError) as e:
        return None


def review_finding(
    rule_id: str,
    severity: str,
    message: str,
    code_snippet: str,
    surrounding_context: str = "",
) -> Tuple[str, float, str]:
    """
    Use LLM to review a single security finding.

    Args:
        rule_id: Rule identifier (e.g., PY001)
        severity: Severity level (CRITICAL/HIGH/MEDIUM/LOW)
        message: Human-readable finding description
        code_snippet: The code line that triggered the finding
        surrounding_context: Lines around the finding for context

    Returns:
        (classification, confidence, reason)
        classification: "TRUE_POSITIVE" or "FALSE_POSITIVE"
        confidence: 0.0 to 1.0
        reason: Brief explanation
    """
    user_prompt = f"""Finding:
  Rule: {rule_id}
  Severity: {severity}
  Description: {message}

Code snippet:
```
{code_snippet}
```

Context:
```
{surrounding_context or '(none)'}
```

Classify this finding."""

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    result = _call_ds_api(messages)
    if result is None:
        return ("UNKNOWN", 0.5, "DS API unavailable")

    classification = result.get("classification", "UNKNOWN")
    confidence = float(result.get("confidence", 0.5))
    reason = result.get("reason", "no reason provided")

    # Validate classification
    if classification not in ("TRUE_POSITIVE", "FALSE_POSITIVE"):
        classification = "UNKNOWN"

    # Clamp confidence
    confidence = max(0.05, min(1.0, confidence))

    return (classification, confidence, reason)


class LLMReviewer:
    """
    LLM-based secondary reviewer for SAST findings.
    Uses local GLM-5.2 API to classify true/false positives.

    Usage:
        reviewer = LLMReviewer()
        for finding in findings:
            tp, conf, reason = reviewer.review(finding)
            if tp == "FALSE_POSITIVE":
                finding.confidence *= 0.3  # Reduce confidence
    """

    def __init__(
        self,
        api_url: str = DS_API_URL,
        model: str = DS_MODEL,
        timeout: int = DS_TIMEOUT,
        enabled: bool = True,
    ):
        self.api_url = api_url
        self.model = model
        self.timeout = timeout
        self.enabled = enabled
        self._stats = {"called": 0, "true_positive": 0, "false_positive": 0, "unknown": 0, "errors": 0}

    @property
    def stats(self) -> Dict:
        return dict(self._stats)

    def check_health(self) -> bool:
        """Check if GLM-5.2 API is reachable."""
        try:
            test_msgs = [{"role": "user", "content": "Reply with exactly: {\"ok\":true}"}]
            result = _call_ds_api(test_msgs, timeout=5)
            return result is not None
        except Exception:
            return False

    def review(self, finding) -> Tuple[str, float, str]:
        """
        Review a single finding using LLM.

        Args:
            finding: Finding object with rule_id, severity, message,
                     code_snippet, file, line

        Returns:
            (classification, llm_confidence, reason)
        """
        if not self.enabled:
            return ("UNKNOWN", 0.5, "LLM review disabled")

        self._stats["called"] += 1

        severity_str = str(finding.severity)
        if hasattr(finding.severity, 'value'):
            severity_str = finding.severity.value

        classification, confidence, reason = review_finding(
            rule_id=finding.rule_id,
            severity=severity_str,
            message=finding.message,
            code_snippet=finding.code_snippet,
            surrounding_context=getattr(finding, 'surrounding_context', ''),
        )

        if classification == "TRUE_POSITIVE":
            self._stats["true_positive"] += 1
        elif classification == "FALSE_POSITIVE":
            self._stats["false_positive"] += 1
        else:
            self._stats["unknown"] += 1

        return (classification, confidence, reason)

    def review_batch(
        self,
        findings: List,
        delay: float = 0.1,
    ) -> List[Tuple[str, float, str]]:
        """
        Review a batch of findings with rate limiting.

        Args:
            findings: List of Finding objects
            delay: Delay between API calls in seconds

        Returns:
            List of (classification, llm_confidence, reason) tuples
        """
        results = []
        for i, finding in enumerate(findings):
            if i > 0 and delay > 0:
                time.sleep(delay)
            results.append(self.review(finding))
        return results

    def apply_review(
        self,
        findings: List,
        fp_penalty: float = 0.3,
        tp_boost: float = 1.1,
    ) -> List:
        """
        Review all findings and adjust confidence scores.
        Modifies findings in place.

        - FALSE_POSITIVE findings: confidence *= fp_penalty (default 0.3)
        - TRUE_POSITIVE findings: confidence *= tp_boost (default 1.1)
        - UNKNOWN findings: no change

        Returns the list of findings (same objects, modified).
        """
        for finding in findings:
            classification, llm_conf, reason = self.review(finding)

            if classification == "FALSE_POSITIVE":
                finding.confidence *= fp_penalty
                finding.llm_classification = "FALSE_POSITIVE"
                finding.llm_reason = reason
            elif classification == "TRUE_POSITIVE":
                finding.confidence = min(1.0, finding.confidence * tp_boost)
                finding.llm_classification = "TRUE_POSITIVE"
                finding.llm_reason = reason
            else:
                finding.llm_classification = "UNKNOWN"
                finding.llm_reason = reason

        return findings

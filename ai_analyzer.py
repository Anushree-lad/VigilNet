"""
ai_analyzer.py
--------------
Takes a structured finding (source IP, triggered rules, risk score) and
asks a local Ollama model to act as a security analyst: explain the
threat, why it's suspicious, likely impact, and a recommended action.

Ollama is NOT used for detection - only for explaining what the rule
engine already found. If Ollama isn't running, falls back to a
template-based explanation so the pipeline still works end-to-end
(useful for demos/dev without the model server up).
"""

import json
import urllib.request
import urllib.error
from risk_scorer import RiskAssessment

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2"  # change to whatever model you've pulled locally

PROMPT_TEMPLATE = """You are a cybersecurity analyst reviewing an automated network alert.

Finding:
- Source IP: {src_ip}
- Risk score: {score}/100 ({band})
- Rules triggered: {rules}
- Evidence: {evidence}

Write a short, structured analysis with these sections:
1. Threat Explanation - what this pattern usually means
2. Why It Is Suspicious - what specifically stood out
3. Possible Impact - what could happen if this is a real attack
4. Recommended Action - concrete next step for the analyst
5. Confidence Level - Low / Medium / High, with one sentence why

Keep it concise, plain language, no more than 150 words total."""


def _build_prompt(assessment: RiskAssessment) -> str:
    evidence = " | ".join(d.evidence for d in assessment.detections)
    rules = ", ".join(assessment.triggered_rules)
    return PROMPT_TEMPLATE.format(
        src_ip=assessment.src_ip,
        score=assessment.score,
        band=assessment.band,
        rules=rules,
        evidence=evidence,
    )


def _call_ollama(prompt: str, model: str = OLLAMA_MODEL, timeout: int = 30) -> str:
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
    }).encode("utf-8")

    req = urllib.request.Request(
        OLLAMA_URL, data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8"))
        return body.get("response", "").strip()


def _fallback_explanation(assessment: RiskAssessment) -> str:
    """Used when Ollama isn't reachable, so the pipeline still produces output."""
    rules = ", ".join(assessment.triggered_rules)
    evidence = " ".join(d.evidence for d in assessment.detections)
    return (
        f"[Fallback - Ollama not reachable]\n"
        f"Threat Explanation: The source triggered: {rules}.\n"
        f"Why It Is Suspicious: {evidence}\n"
        f"Possible Impact: Could indicate reconnaissance or an active attack "
        f"attempting to map or overwhelm the network.\n"
        f"Recommended Action: Investigate {assessment.src_ip}, check firewall/IDS "
        f"logs, and consider temporary blocking if traffic continues.\n"
        f"Confidence Level: Medium - based on rule thresholds, not confirmed intent."
    )


def analyze(assessment: RiskAssessment, model: str = OLLAMA_MODEL) -> str:
    """
    Returns an AI-generated (or fallback) explanation string for one
    RiskAssessment. Never raises - falls back gracefully if Ollama is down.
    """
    prompt = _build_prompt(assessment)
    try:
        return _call_ollama(prompt, model=model)
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
        return _fallback_explanation(assessment)

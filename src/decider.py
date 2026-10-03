import json
import re

from strands import Agent

from .models import TriageDecision

SYSTEM_PROMPT = """You are the routing engine for DevSecOps-Triager.
Choose exactly one route: scan_secrets, analyze_build_failure, or review_pr.
Return ONLY JSON: {"action":"...","reason":"...","confidence":0.0}.
Never invent tools. Never output markdown. Never generate shell commands."""

def _extract(text: str) -> dict:
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if not match:
        raise ValueError('Decider returned no JSON object')
    return json.loads(match.group(0))

def decide(model_id: str, context: dict) -> TriageDecision:
    agent = Agent(model=model_id)
    result = agent(SYSTEM_PROMPT + '\\nEVENT CONTEXT:\\n' + json.dumps(context, ensure_ascii=False))
    data = _extract(str(result))
    action = data.get('action')
    if action not in {'scan_secrets', 'analyze_build_failure', 'review_pr'}:
        raise ValueError('Unsupported decider action')
    confidence = max(0.0, min(1.0, float(data.get('confidence', 0))))
    return TriageDecision(action, str(data.get('reason', 'No reason supplied'))[:1000], confidence)

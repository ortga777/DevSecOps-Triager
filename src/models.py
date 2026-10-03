from dataclasses import dataclass
from typing import Literal

Action = Literal['scan_secrets', 'analyze_build_failure', 'review_pr']

@dataclass(frozen=True)
class TriageDecision:
    action: Action
    reason: str
    confidence: float

    def as_dict(self) -> dict:
        return {'action': self.action, 'reason': self.reason, 'confidence': self.confidence}

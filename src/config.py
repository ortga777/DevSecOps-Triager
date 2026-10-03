import os
from dataclasses import dataclass

@dataclass(frozen=True)
class Settings:
    model_id: str
    github_secret_arn: str
    webhook_secret_arn: str
    max_diff_chars: int
    max_log_chars: int

    @classmethod
    def from_env(cls):
        model_id = os.environ.get('DECIDER_MODEL_ID', '').strip()
        github_secret_arn = os.environ.get('GITHUB_SECRET_ARN', '').strip()
        webhook_secret_arn = os.environ.get('GITHUB_WEBHOOK_SECRET_ARN', '').strip()
        if not model_id or not github_secret_arn or not webhook_secret_arn:
            raise RuntimeError('Required environment variables are missing')
        return cls(model_id, github_secret_arn, webhook_secret_arn,
                   int(os.environ.get('MAX_DIFF_CHARS', '60000')),
                   int(os.environ.get('MAX_LOG_CHARS', '30000')))

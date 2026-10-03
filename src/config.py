import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    model_id: str
    github_secret_arn: str
    webhook_secret_arn: str
    max_diff_chars: int
    max_log_chars: int
    idempotency_table: str

    @classmethod
    def from_env(cls):
        required = {
            'DECIDER_MODEL_ID': os.environ.get('DECIDER_MODEL_ID', '').strip(),
            'GITHUB_SECRET_ARN': os.environ.get('GITHUB_SECRET_ARN', '').strip(),
            'GITHUB_WEBHOOK_SECRET_ARN': os.environ.get('GITHUB_WEBHOOK_SECRET_ARN', '').strip(),
            'IDEMPOTENCY_TABLE': os.environ.get('IDEMPOTENCY_TABLE', '').strip(),
        }
        if any(not value for value in required.values()):
            raise RuntimeError('Required environment variables are missing')
        return cls(
            required['DECIDER_MODEL_ID'],
            required['GITHUB_SECRET_ARN'],
            required['GITHUB_WEBHOOK_SECRET_ARN'],
            int(os.environ.get('MAX_DIFF_CHARS', '60000')),
            int(os.environ.get('MAX_LOG_CHARS', '30000')),
            required['IDEMPOTENCY_TABLE'],
        )

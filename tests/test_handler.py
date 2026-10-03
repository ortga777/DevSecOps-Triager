import json
from unittest.mock import patch

from src import handler


def _event(payload, event_name="pull_request"):
    return {
        "headers": {
            "x-hub-signature-256": "sha256=valid",
            "x-github-event": event_name,
            "x-github-delivery": "delivery-1",
        },
        "body": json.dumps(payload),
    }


def test_pull_request_uses_github_app_installation_token():
    payload = {
        "action": "opened",
        "repository": {"full_name": "owner/repo"},
        "pull_request": {"number": 7, "title": "test"},
    }
    settings = type(
        "SettingsStub",
        (),
        {
            "github_auth_mode": "app",
            "github_secret_arn": "secret",
            "webhook_secret_arn": "webhook",
            "model_id": "model",
            "max_diff_chars": 60000,
            "max_log_chars": 30000,
            "idempotency_table": "table",
        },
    )()

    with (
        patch("src.handler.Settings.from_env", return_value=settings),
        patch("src.handler.get_webhook_secret", return_value="secret"),
        patch("src.handler.verify_signature", return_value=True),
        patch("src.handler.claim", return_value=True),
        patch(
            "src.handler.get_github_app_credentials",
            return_value={"app_id": "1", "private_key": "KEY", "installation_id": 2},
        ) as creds,
        patch("src.handler.installation_token", return_value="installation-token") as token,
        patch("src.handler.GitHubClient") as client_cls,
        patch("src.handler.decide", return_value=type("Decision", (), {
            "action": "review_pr",
            "reason": "review",
            "confidence": 0.8,
            "as_dict": lambda self: {"action": self.action, "reason": self.reason, "confidence": self.confidence},
        })()),
        patch("src.handler.post_triage_comment"),
    ):
        client_cls.return_value.pull_diff.return_value = "diff"
        result = handler.lambda_handler(_event(payload), None)

    assert result["statusCode"] == 200
    creds.assert_called_once_with("secret")
    token.assert_called_once_with("1", "KEY", 2)
    client_cls.assert_called_once_with("installation-token")

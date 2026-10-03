from unittest.mock import patch

from src.github_app import make_jwt


def test_make_jwt_delegates_to_pyjwt():
    with patch('jwt.encode', return_value='signed') as encode:
        assert make_jwt('123', 'private') == 'signed'
        assert encode.called


def test_github_app_secret_shape():
    from unittest.mock import patch

    from src.secrets import get_github_app_credentials

    raw = '{"app_id":"123","private_key":"KEY","installation_id":"456"}'
    with patch("src.secrets.get_secret", return_value=raw):
        assert get_github_app_credentials("arn") == {
            "app_id": "123",
            "private_key": "KEY",
            "installation_id": 456,
        }


def test_handler_uses_installation_token():
    import json
    from unittest.mock import patch

    from src import handler

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
    payload = {
        "action": "opened",
        "repository": {"full_name": "owner/repo"},
        "pull_request": {"number": 7, "title": "test"},
    }
    event = {
        "headers": {
            "x-hub-signature-256": "sha256=valid",
            "x-github-event": "pull_request",
            "x-github-delivery": "delivery-1",
        },
        "body": json.dumps(payload),
    }
    with (
        patch("src.handler.Settings.from_env", return_value=settings),
        patch("src.handler.get_webhook_secret", return_value="secret"),
        patch("src.handler.verify_signature", return_value=True),
        patch("src.handler.claim", return_value=True),
        patch("src.handler.get_github_app_credentials", return_value={"app_id": "1", "private_key": "KEY", "installation_id": 2}) as creds,
        patch("src.handler.installation_token", return_value="installation-token") as token,
        patch("src.handler.GitHubClient") as client_cls,
        patch("src.handler.decide", return_value=type("Decision", (), {"action": "review_pr", "reason": "review", "confidence": 0.8, "as_dict": lambda self: {"action": self.action, "reason": self.reason, "confidence": self.confidence}})()),
        patch("src.handler.post_triage_comment"),
    ):
        client_cls.return_value.pull_diff.return_value = "diff"
        result = handler.lambda_handler(event, None)

    assert result["statusCode"] == 200
    creds.assert_called_once_with("secret")
    token.assert_called_once_with("1", "KEY", 2)
    client_cls.assert_called_once_with("installation-token")

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

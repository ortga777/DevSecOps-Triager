from unittest.mock import patch

from src.github_app import make_jwt


def test_make_jwt_delegates_to_pyjwt():
    with patch('jwt.encode', return_value='signed') as encode:
        assert make_jwt('123', 'private') == 'signed'
        assert encode.called

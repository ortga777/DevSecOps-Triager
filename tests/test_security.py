import hashlib
import hmac
from src.security import parse_json, verify_signature

def test_valid_signature():
    body = b'{"ok":true}'
    digest = hmac.new(b'secret', body, hashlib.sha256).hexdigest()
    assert verify_signature(body, 'sha256=' + digest, 'secret')

def test_invalid_signature():
    assert not verify_signature(b'{}', 'sha256=bad', 'secret')

def test_parse_json():
    assert parse_json(b'{"action":"opened"}')['action'] == 'opened'

from unittest.mock import patch
from src.idempotency import event_key


def test_event_key_is_stable():
    assert event_key('abc', 'delivery') == event_key('abc', 'delivery')
    assert event_key('abc', 'delivery') != event_key('abc', 'other')

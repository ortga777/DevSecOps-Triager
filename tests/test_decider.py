from unittest.mock import patch

from src.decider import decide

class FakeResult:
    def __str__(self):
        return '{"action":"scan_secrets","reason":"credential-like change","confidence":0.91}'

def test_decider_output_validation():
    with patch('src.decider.Agent') as agent:
        agent.return_value.return_value = FakeResult()
        result = decide('test-model', {'diff': 'secret'})
    assert result.action == 'scan_secrets'
    assert result.confidence == 0.91

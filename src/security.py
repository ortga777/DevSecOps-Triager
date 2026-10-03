import hashlib
import hmac
import json


def verify_signature(raw_body: bytes, signature: str | None, secret: str) -> bool:
    if not signature or not signature.startswith('sha256='):
        return False
    expected = 'sha256=' + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def parse_json(raw_body: bytes) -> dict:
    value = json.loads(raw_body.decode('utf-8'))
    if not isinstance(value, dict):
        raise ValueError('Webhook payload must be a JSON object')
    return value


def redact(text: str) -> str:
    prefixes = ('ghp_', 'github_pat_', 'AKIA', 'Bearer ')
    result = text
    for prefix in prefixes:
        idx = result.find(prefix)
        while idx >= 0:
            end = idx + len(prefix)
            while end < len(result) and result[end] not in ' \\n\\r\\t\\\"\'`,;)]}':
                end += 1
            result = result[:idx] + '[REDACTED]' + result[end:]
            idx = result.find(prefix, idx + 10)
    return result

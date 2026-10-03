import hashlib
import os
import boto3


def _table():
    name = os.environ.get('IDEMPOTENCY_TABLE')
    if not name:
        raise RuntimeError('IDEMPOTENCY_TABLE is required')
    return boto3.resource('dynamodb').Table(name)


def event_key(event_id: str, delivery: str) -> str:
    return hashlib.sha256(f'{event_id}:{delivery}'.encode()).hexdigest()


def claim(key: str, ttl_seconds: int = 86400) -> bool:
    from time import time
    table = _table()
    try:
        table.put_item(
            Item={'event_key': key, 'expires_at': int(time()) + ttl_seconds},
            ConditionExpression='attribute_not_exists(event_key)',
        )
        return True
    except table.meta.client.exceptions.ConditionalCheckFailedException:
        return False

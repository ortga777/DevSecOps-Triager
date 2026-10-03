import hashlib
import boto3

_table = boto3.resource('dynamodb').Table(__import__('os').environ['IDEMPOTENCY_TABLE'])

def event_key(event_id: str, delivery: str) -> str:
    return hashlib.sha256(f'{event_id}:{delivery}'.encode()).hexdigest()

def claim(key: str, ttl_seconds: int = 86400) -> bool:
    from time import time
    try:
        _table.put_item(Item={'event_key': key, 'expires_at': int(time()) + ttl_seconds},
                        ConditionExpression='attribute_not_exists(event_key)')
        return True
    except _table.meta.client.exceptions.ConditionalCheckFailedException:
        return False

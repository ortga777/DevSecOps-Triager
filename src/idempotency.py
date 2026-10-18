import hashlib
import os
import uuid
from time import time

import boto3


def _table():
    name = os.environ.get("IDEMPOTENCY_TABLE")
    if not name:
        raise RuntimeError("IDEMPOTENCY_TABLE is required")
    return boto3.resource("dynamodb").Table(name)


def event_key(event_id: str, delivery: str) -> str:
    return hashlib.sha256(f"{event_id}:{delivery}".encode()).hexdigest()


def claim(key: str, lease_seconds: int = 300, completed_ttl_seconds: int = 86400) -> str | None:
    """Claim a delivery with a recoverable processing lease; return its ownership token."""
    table = _table()
    now = int(time())
    token = uuid.uuid4().hex
    try:
        table.put_item(
            Item={
                "event_key": key,
                "status": "processing",
                "owner_token": token,
                "lease_until": now + lease_seconds,
                "expires_at": now + completed_ttl_seconds,
            },
            ConditionExpression=(
                "attribute_not_exists(event_key) OR "
                "(#status = :processing AND lease_until < :now)"
            ),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":processing": "processing", ":now": now},
        )
        return token
    except table.meta.client.exceptions.ConditionalCheckFailedException:
        return None


def complete(key: str, owner_token: str, ttl_seconds: int = 86400) -> None:
    """Mark a successfully processed delivery as complete for the deduplication window."""
    table = _table()
    table.update_item(
        Key={"event_key": key},
        UpdateExpression="SET #status = :completed, expires_at = :expires",
        ConditionExpression="#status = :processing AND owner_token = :owner",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":processing": "processing",
            ":completed": "completed",
            ":owner": owner_token,
            ":expires": int(time()) + ttl_seconds,
        },
    )


def release(key: str, owner_token: str) -> None:
    """Release only this invocation's claim after a processing exception."""
    table = _table()
    try:
        table.delete_item(
            Key={"event_key": key},
            ConditionExpression="#status = :processing AND owner_token = :owner",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":processing": "processing", ":owner": owner_token},
        )
    except table.meta.client.exceptions.ConditionalCheckFailedException:
        # Another invocation has taken over or completed the claim; do not remove it.
        return

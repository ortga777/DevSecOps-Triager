import json

import boto3




def get_secret(arn: str) -> str:
    value = boto3.client("secretsmanager").get_secret_value(SecretId=arn)
    if "SecretString" in value:
        return value["SecretString"]
    return value["SecretBinary"].decode()


def get_github_token(arn: str) -> str:
    raw = get_secret(arn)
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and data.get("token"):
            return str(data["token"])
    except json.JSONDecodeError:
        pass
    if raw.strip():
        return raw.strip()
    raise RuntimeError("GitHub credential secret is empty")


def get_github_app_credentials(arn: str) -> dict:
    raw = get_secret(arn)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("GitHub App credential secret must be JSON") from exc
    required = ("app_id", "private_key", "installation_id")
    if not all(data.get(key) for key in required):
        raise RuntimeError("GitHub App secret requires app_id, private_key, and installation_id")
    return {
        "app_id": str(data["app_id"]),
        "private_key": str(data["private_key"]),
        "installation_id": int(data["installation_id"]),
    }


def get_webhook_secret(arn: str) -> str:
    raw = get_secret(arn)
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and data.get("secret"):
            return str(data["secret"])
    except json.JSONDecodeError:
        pass
    return raw.strip()

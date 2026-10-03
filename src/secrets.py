import json

import boto3

_client = boto3.client('secretsmanager')

def get_secret(arn: str) -> str:
    value = _client.get_secret_value(SecretId=arn)
    if 'SecretString' in value:
        return value['SecretString']
    return value['SecretBinary'].decode()

def get_github_token(arn: str) -> str:
    raw = get_secret(arn)
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and data.get('token'):
            return str(data['token'])
    except json.JSONDecodeError:
        pass
    if raw.strip():
        return raw.strip()
    raise RuntimeError('GitHub credential secret is empty')

def get_webhook_secret(arn: str) -> str:
    raw = get_secret(arn)
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and data.get('secret'):
            return str(data['secret'])
    except json.JSONDecodeError:
        pass
    return raw.strip()

import base64
import json
import time
import urllib.request


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode()


def make_jwt(app_id: str, private_key: str) -> str:
    # Requires PyJWT at runtime. Kept isolated so authentication can be replaced/tested independently.
    import jwt
    now = int(time.time())
    return jwt.encode({'iat': now - 30, 'exp': now + 540, 'iss': app_id}, private_key, algorithm='RS256')


def installation_token(app_id: str, private_key: str, installation_id: int) -> str:
    token = make_jwt(app_id, private_key)
    request = urllib.request.Request(
        f'https://api.github.com/app/installations/{installation_id}/access_tokens',
        data=b'{}', method='POST',
        headers={'Accept':'application/vnd.github+json','Authorization':f'Bearer {token}',
                 'X-GitHub-Api-Version':'2026-03-10','Content-Type':'application/json',
                 'User-Agent':'DevSecOps-Triager/1.0'})
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read())['token']

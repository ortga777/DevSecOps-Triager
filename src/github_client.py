import json
import urllib.error
import urllib.request

API = 'https://api.github.com'

class GitHubClient:
    def __init__(self, token: str):
        self.token = token

    def _request(self, method: str, path: str, body: dict | None = None, accept: str = 'application/vnd.github+json'):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(API + path, data=data, method=method, headers={
            'Accept': accept,
            'Authorization': f'Bearer {self.token}',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'DevSecOps-Triager/1.0',
            **({'Content-Type': 'application/json'} if data else {}),
        })
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                raw = response.read().decode()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors='replace')[:1000]
            raise RuntimeError(f'GitHub API {exc.code}: {detail}') from exc

    def pull_request(self, owner: str, repo: str, number: int) -> dict:
        return self._request('GET', f'/repos/{owner}/{repo}/pulls/{number}')

    def pull_diff(self, owner: str, repo: str, number: int) -> str:
        return self._request('GET', f'/repos/{owner}/{repo}/pulls/{number}', accept='application/vnd.github.v3.diff')

    def workflow_jobs(self, owner: str, repo: str, run_id: int) -> dict:
        return self._request('GET', f'/repos/{owner}/{repo}/actions/runs/{run_id}/jobs')

    def job_logs(self, owner: str, repo: str, job_id: int) -> str:
        return self._request('GET', f'/repos/{owner}/{repo}/actions/jobs/{job_id}/logs')

    def comment(self, owner: str, repo: str, number: int, body: str) -> dict:
        return self._request('POST', f'/repos/{owner}/{repo}/issues/{number}/comments', {'body': body[:65000]})

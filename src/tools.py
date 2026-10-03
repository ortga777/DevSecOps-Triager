import re
from .github_client import GitHubClient

PATTERNS = [
    re.compile(r'AKIA[0-9A-Z]{16}'),
    re.compile(r'ghp_[A-Za-z0-9]{20,}'),
    re.compile(r'github_pat_[A-Za-z0-9_]{20,}'),
    re.compile(r'''(?i)(api[_-]?key|secret|token|password)\\s*[:=]\\s*[\'\"][^\'\"]{8,}'''),
]

def scan_secrets(diff: str) -> list[str]:
    return [pattern.pattern for pattern in PATTERNS if pattern.search(diff)]

def analyze_build_failure(logs: str) -> dict:
    lines = [line.strip() for line in logs.splitlines() if line.strip()]
    errors = [line for line in lines if any(word in line.lower() for word in ('error', 'failed', 'exception', 'traceback'))]
    return {'error_count': len(errors), 'samples': errors[-10:]}

def post_triage_comment(client: GitHubClient, owner: str, repo: str, number: int, action: str, reason: str, findings=None, summary=None):
    body = [
        '## DevSecOps-Triager', '', f'**Route:** `{action}`', f'**Reason:** {reason}', '',
    ]
    if findings:
        body += ['### Secret-scan signal', f'Potential secret patterns detected: **{len(findings)}**.', 'Review the changed lines and rotate any exposed credential if confirmed.', '']
    if summary:
        body += ['### Build analysis', f"Relevant failure lines detected: **{summary['error_count']}**.", '']
    body.append('_Advisory analysis only. No source-code mutation was performed._')
    return client.comment(owner, repo, number, '\\n'.join(body))

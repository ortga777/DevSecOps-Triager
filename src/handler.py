import base64
import json
import logging
from typing import Any
from .config import Settings
from .codebuild import start_security_scan
from .decider import decide
from .github_client import GitHubClient
from .idempotency import claim, event_key
from .github_app import installation_token
from .secrets import get_github_app_credentials, get_github_token, get_webhook_secret
from .security import parse_json, redact, verify_signature
from .tools import analyze_build_failure, post_triage_comment, scan_secrets

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def _headers(event: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (event.get('headers') or {}).items()}

def _body(event: dict[str, Any]) -> bytes:
    body = event.get('body') or ''
    return base64.b64decode(body) if event.get('isBase64Encoded') else body.encode()

def _repo(payload: dict) -> tuple[str, str]:
    full = payload.get('repository', {}).get('full_name', '')
    owner, separator, repo = full.partition('/')
    if not separator:
        raise ValueError('Invalid repository.full_name')
    return owner, repo

def _response(status: int, payload: dict) -> dict:
    return {'statusCode': status, 'headers': {'Content-Type': 'application/json'}, 'body': json.dumps(payload)}

def lambda_handler(event: dict[str, Any], context: Any) -> dict:
    settings = Settings.from_env()
    raw = _body(event)
    headers = _headers(event)
    if not verify_signature(raw, headers.get('x-hub-signature-256'), get_webhook_secret(settings.webhook_secret_arn)):
        return _response(401, {'error': 'invalid signature'})
    payload = parse_json(raw)
    event_name = headers.get('x-github-event', '')
    delivery = headers.get('x-github-delivery', '')
    if delivery and not claim(event_key(event_name, delivery)):
        return _response(202, {'status': 'duplicate', 'delivery': delivery})
    if event_name not in {'pull_request', 'workflow_run'}:
        return _response(202, {'status': 'ignored', 'event': event_name})
    if event_name == 'pull_request' and payload.get('action') not in {'opened', 'synchronize', 'reopened'}:
        return _response(202, {'status': 'ignored', 'reason': 'pull_request_action'})
    if event_name == 'workflow_run' and (payload.get('action') != 'completed' or payload.get('workflow_run', {}).get('conclusion') != 'failure'):
        return _response(202, {'status': 'ignored', 'reason': 'workflow_not_failed'})

    owner, repo = _repo(payload)
    if settings.github_auth_mode == "app":
        credentials = get_github_app_credentials(settings.github_secret_arn)
        github_token = installation_token(
            credentials["app_id"],
            credentials["private_key"],
            credentials["installation_id"],
        )
    else:
        github_token = get_github_token(settings.github_secret_arn)
    client = GitHubClient(github_token)

    if event_name == 'pull_request':
        pr = payload['pull_request']
        number = int(pr['number'])
        diff = client.pull_diff(owner, repo, number)[:settings.max_diff_chars]
        context_data = {'event': event_name, 'action': payload.get('action'), 'repository': f'{owner}/{repo}', 'pull_request': number, 'title': pr.get('title', ''), 'diff': redact(diff)}
        decision = decide(settings.model_id, context_data)
        findings = scan_secrets(diff) if decision.action == 'scan_secrets' else []
        scan_build = None
        if decision.action == 'scan_secrets' and settings.codebuild_project_name:
            scan_build = start_security_scan(
                settings.codebuild_project_name,
                pr.get('base', {}).get('repo', {}).get('clone_url', ''),
                number,
            )
        post_triage_comment(client, owner, repo, number, decision.action, decision.reason, findings=findings, summary=scan_build)
        logger.info('triage_complete repo=%s pr=%s action=%s confidence=%.2f', f'{owner}/{repo}', number, decision.action, decision.confidence)
        return _response(200, {'status': 'processed', 'decision': decision.as_dict()})

    run = payload['workflow_run']
    prs = run.get('pull_requests') or []
    number = int(prs[0].get('number', 0)) if prs else 0
    if not number:
        return _response(202, {'status': 'ignored', 'reason': 'no_associated_pr'})
    jobs = client.workflow_jobs(owner, repo, int(run['id']))
    logs = ''
    for job in jobs.get('jobs', []):
        if job.get('conclusion') == 'failure':
            logs = client.job_logs(owner, repo, int(job['id']))
            break
    logs = logs[-settings.max_log_chars:]
    decision = decide(settings.model_id, {'event': event_name, 'repository': f'{owner}/{repo}', 'pull_request': number, 'workflow': run.get('name'), 'logs': redact(logs)})
    summary = analyze_build_failure(logs) if decision.action == 'analyze_build_failure' else None
    post_triage_comment(client, owner, repo, number, decision.action, decision.reason, summary=summary)
    return _response(200, {'status': 'processed', 'decision': decision.as_dict()})

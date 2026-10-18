from urllib.parse import urlparse

import boto3


TRUSTED_BUILDSPEC = """version: 0.2
phases:
  install:
    commands:
      - python --version
      - pip install --no-cache-dir semgrep
  build:
    commands:
      - echo 'Running isolated security scan'
      - rm -f .semgrepignore .gitignore
      - semgrep scan --no-git-ignore --config p/security-audit --json --output semgrep.json . || true
      - test -f semgrep.json
      - |
        python - <<'PY'
        import json
        import os

        with open("semgrep.json", encoding="utf-8") as handle:
            semgrep = json.load(handle)

        repository_url = os.environ["TRIAGER_REPOSITORY"]
        repository_path = repository_url.removeprefix("https://github.com/").removesuffix(".git").strip("/")
        parts = repository_path.split("/")
        if len(parts) != 2 or not all(parts):
            raise ValueError("Invalid GitHub repository path")
        envelope = {
            "repository": repository_path,
            "pull_request_number": int(os.environ["TRIAGER_PR_NUMBER"]),
            "build_id": os.environ["CODEBUILD_BUILD_ID"],
            "scanner_status": "COMPLETED",
            "findings": semgrep.get("results", []),
            "errors": semgrep.get("errors", []),
        }
        with open("triager-result.json", "w", encoding="utf-8") as handle:
            json.dump(envelope, handle)
        PY
      - aws s3 cp triager-result.json "s3://$TRIAGER_RESULT_BUCKET/results/$CODEBUILD_BUILD_ID.json"
artifacts:
  files:
    - semgrep.json
    - triager-result.json
  discard-paths: yes
"""


def start_security_scan(project_name: str, repository_url: str, pull_request_number: int) -> dict:
    parsed = urlparse(repository_url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Only canonical GitHub HTTPS repository URLs are supported") from exc
    path = parsed.path.removesuffix(".git").strip("/")
    parts = path.split("/")
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username
        or parsed.password
        or port not in (None, 443)
        or parsed.query
        or parsed.fragment
        or len(parts) != 2
        or not all(parts)
    ):
        raise ValueError("Only canonical GitHub HTTPS repository URLs are supported")
    if pull_request_number < 1:
        raise ValueError("pull_request_number must be positive")

    response = boto3.client("codebuild").start_build(
        projectName=project_name,
        sourceTypeOverride="GITHUB",
        sourceLocationOverride=f"https://github.com/{path}",
        sourceVersion=f"refs/pull/{pull_request_number}/head",
        # Inline trusted buildspec: never execute a buildspec supplied by the PR.
        buildspecOverride=TRUSTED_BUILDSPEC,
        artifactsOverride={"type": "NO_ARTIFACTS"},
        environmentVariablesOverride=[
            {"name": "TRIAGER_PR_NUMBER", "value": str(pull_request_number), "type": "PLAINTEXT"},
            {"name": "TRIAGER_REPOSITORY", "value": f"https://github.com/{path}", "type": "PLAINTEXT"},
        ],
    )
    build = response["build"]
    return {
        "id": build["id"],
        "arn": build["arn"],
        "status": build.get("buildStatus", "IN_PROGRESS"),
    }

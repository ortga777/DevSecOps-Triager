import os

import boto3


def start_security_scan(project_name: str, repository_url: str, pull_request_number: int) -> dict:
    if not repository_url.startswith(("https://github.com/", "https://github.com:")):
        raise ValueError("Only GitHub HTTPS repository URLs are supported")

    response = boto3.client("codebuild").start_build(
        projectName=project_name,
        sourceTypeOverride="GITHUB",
        sourceLocationOverride=repository_url,
        sourceVersion=f"pr/{pull_request_number}",
        buildspecOverride="codebuild/buildspec-security.yml",
    )
    build = response["build"]
    return {
        "id": build["id"],
        "arn": build["arn"],
        "status": build.get("buildStatus", "IN_PROGRESS"),
    }

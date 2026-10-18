from unittest.mock import patch

import pytest

from src.codebuild import start_security_scan


def test_start_security_scan_uses_pull_request_head_ref():
    response = {
        "build": {
            "id": "demo:123",
            "arn": "arn:aws:codebuild:demo",
            "buildStatus": "IN_PROGRESS",
        }
    }
    with patch("src.codebuild.boto3.client") as client:
        client.return_value.start_build.return_value = response
        result = start_security_scan(
            "triager-security",
            "https://github.com/ortga777/DevSecOps-Triager",
            42,
        )

    assert result["id"] == "demo:123"
    client.return_value.start_build.assert_called_once_with(
        projectName="triager-security",
        sourceTypeOverride="GITHUB",
        sourceLocationOverride="https://github.com/ortga777/DevSecOps-Triager",
        sourceVersion="refs/pull/42/head",
        buildspecOverride="codebuild/buildspec-security.yml",
        artifactsOverride={"type": "NO_ARTIFACTS"},
        environmentVariablesOverride=[
            {"name": "TRIAGER_PR_NUMBER", "value": "42", "type": "PLAINTEXT"},
            {
                "name": "TRIAGER_REPOSITORY",
                "value": "https://github.com/ortga777/DevSecOps-Triager",
                "type": "PLAINTEXT",
            },
        ],
    )


@pytest.mark.parametrize("url", ["http://github.com/owner/repo", "https://example.com/owner/repo"])
def test_start_security_scan_rejects_non_github_https_urls(url):
    with patch("src.codebuild.boto3.client") as client:
        with pytest.raises(ValueError, match="Only GitHub HTTPS"):
            start_security_scan("triager-security", url, 42)
        client.assert_not_called()


def test_start_security_scan_rejects_invalid_pull_request_number():
    with patch("src.codebuild.boto3.client") as client:
        with pytest.raises(ValueError, match="must be positive"):
            start_security_scan(
                "triager-security",
                "https://github.com/owner/repo",
                0,
            )
        client.assert_not_called()

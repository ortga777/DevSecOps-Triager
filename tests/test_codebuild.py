from unittest.mock import patch

import pytest

from src.codebuild import TRUSTED_BUILDSPEC, start_security_scan


def test_start_security_scan_uses_pull_request_head_and_trusted_buildspec():
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
            "https://github.com/ortga777/DevSecOps-Triager.git",
            42,
        )

    assert result["id"] == "demo:123"
    kwargs = client.return_value.start_build.call_args.kwargs
    assert kwargs["projectName"] == "triager-security"
    assert kwargs["sourceTypeOverride"] == "GITHUB"
    assert kwargs["sourceLocationOverride"] == "https://github.com/ortga777/DevSecOps-Triager"
    assert kwargs["sourceVersion"] == "refs/pull/42/head"
    assert kwargs["buildspecOverride"] == TRUSTED_BUILDSPEC
    assert "semgrep scan" in kwargs["buildspecOverride"]
    assert "codebuild/buildspec-security.yml" not in kwargs["buildspecOverride"]
    assert kwargs["artifactsOverride"] == {"type": "NO_ARTIFACTS"}
    assert kwargs["environmentVariablesOverride"] == [
        {"name": "TRIAGER_PR_NUMBER", "value": "42", "type": "PLAINTEXT"},
        {
            "name": "TRIAGER_REPOSITORY",
            "value": "https://github.com/ortga777/DevSecOps-Triager",
            "type": "PLAINTEXT",
        },
    ]


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/owner/repo",
        "https://example.com/owner/repo",
        "https://github.com.evil.example/owner/repo",
        "https://github.com:evil/owner/repo",
        "https://user@github.com/owner/repo",
        "https://github.com/owner/repo?redirect=evil",
        "https://github.com/owner/repo/extra",
    ],
)
def test_start_security_scan_rejects_noncanonical_github_urls(url):
    with patch("src.codebuild.boto3.client") as client:
        with pytest.raises(ValueError, match="canonical GitHub HTTPS"):
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

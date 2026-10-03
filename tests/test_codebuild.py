from unittest.mock import patch

from src.codebuild import start_security_scan


def test_start_security_scan():
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
        sourceVersion="pr/42",
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

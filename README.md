# DevSecOps-Triager

Production-oriented DevSecOps routing agent for GitHub pull requests and failed GitHub Actions workflows.

## Architecture

GitHub Webhook → API Gateway → AWS Lambda → Strands Agents → Amazon Bedrock → deterministic tools → GitHub PR comment.

The model is used for **routing**, not unrestricted code execution. The current implementation never changes source code automatically.

## Capabilities

- PR triage for opened, synchronized, and reopened pull requests.
- Failed GitHub Actions workflow triage.
- Secret-pattern signal scanning.
- Build/test failure summarization.
- Advisory PR comments.
- HMAC SHA-256 webhook verification.
- AWS Secrets Manager credentials.
- IAM permissions for Bedrock and the two required secrets.
- Unit tests and GitHub Actions CI.
- AWS SAM infrastructure as code.

## Security model

1. GitHub sends a signed webhook.
2. Lambda verifies `X-Hub-Signature-256` before processing.
3. Credentials are loaded from AWS Secrets Manager.
4. Diff and log input is size-limited and redacted before model context.
5. The model can select only an allow-listed route.
6. The model cannot execute shell commands.
7. No source-code mutation is performed automatically.

For production installations, prefer a GitHub App with the minimum repository permissions over a broad personal access token.

## Local validation

Prerequisites: Python 3.12+, AWS SAM CLI, AWS CLI, and access to the selected Bedrock model.

```bash
python -m pip install -r requirements.txt pytest ruff
ruff check src tests
pytest -q
sam validate
sam build
```

## AWS deployment

Create two AWS Secrets Manager secrets.

GitHub credential secret:

```json
{"token":"REDACTED"}
```

Webhook secret:

```json
{"secret":"REDACTED"}
```

Deploy with:

```bash
sam build
sam deploy --guided
```

Provide:

- `DeciderModelId`
- `GitHubSecretArn`
- `GitHubWebhookSecretArn`

The stack outputs the webhook endpoint. Configure that endpoint in the GitHub repository webhook settings with content type `application/json`, the same webhook secret, and the required pull-request/workflow events.

## Model configuration

The model ID is intentionally configurable. Strands Agents supports Amazon Bedrock model providers, while the exact model identifier depends on the model access enabled in the AWS account and region. Do not commit credentials or a private model configuration to this repository.

## Production hardening roadmap

- GitHub App installation-token authentication.
- DynamoDB-backed webhook idempotency.
- CloudWatch alarms and structured metrics.
- Heavy scanners such as Semgrep/TruffleHog isolated in CodeBuild.
- Approval-gated patch generation.
- Disposable-repository integration tests.
- Branch protection after CI is green.
- Real p50/p95 latency and cost benchmarks before publishing performance claims.

## Demo flow

1. Open a test PR with a deliberate non-sensitive secret-pattern fixture.
2. GitHub sends the signed webhook.
3. Lambda verifies it and retrieves the diff.
4. Strands routes the event to the appropriate deterministic tool.
5. The tool produces an advisory result.
6. DevSecOps-Triager posts the result to the PR without modifying source code.

## License

See `LICENSE`.

# Security

## Credentials

Pass model credentials through `SKILLLIFEBENCH_API_KEY`. Keep local `.env` files and run output outside Git. The public client does not load dotenv files, write authorization headers, or pass credentials into the skill sandbox. Credentials must not be included in endpoint URLs.

If a credential has entered any Git commit, revoke or rotate it at its provider. Removing the current file does not revoke a key or erase earlier commits.

## Benchmark artifacts

Some scenarios intentionally contain malicious code, prompt injections, synthetic secrets, or private-key-shaped test fixtures. Treat these files as benchmark data. Use the isolated evaluator for new executions; do not import or execute scenario code directly on your workstation. Frozen replay reads recorded evidence and does not execute skills, contact model endpoints, or unpickle saved native states.

The live evaluator requires Linux namespace and seccomp support. It fails if containment cannot be established. It does not fall back to running untrusted skills on the host.

## Report a problem

Use the repository's private vulnerability reporting feature if it is enabled, or contact a repository maintainer privately. Public issues may describe the affected path and credential type, but must not include actual keys, account passwords, or private data.

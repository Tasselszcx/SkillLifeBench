# Security

## Credentials

Pass model credentials through `SKILLLIFEBENCH_API_KEY`. Keep local `.env` files and run output outside Git. The public client does not load dotenv files, write authorization headers, or pass credentials into the skill sandbox. It removes opaque continuation state such as `X-Codex-Turn-State` and transport-level `encrypted_content`, including nested and encoded transport bodies, before persisting responses. Ordinary answer text and tool arguments remain task data. Credentials must not be included in endpoint URLs.

If a credential has entered any Git commit, revoke or rotate it at its provider. Removing the current file does not revoke a key or erase earlier commits.

## Benchmark artifacts

Some scenarios intentionally contain malicious code, prompt injections, synthetic secrets, or private-key-shaped test fixtures. Treat these files as benchmark data. Use the isolated evaluator for new executions; do not import or execute scenario code directly on your workstation. Frozen replay reads recorded evidence and does not execute skills, contact model endpoints, or unpickle saved native states.

The live evaluator requires Linux namespace and seccomp support. It fails if containment cannot be established. It does not fall back to running untrusted skills on the host.

## Report a problem

Use the repository's private vulnerability reporting feature if it is enabled, or contact a repository maintainer privately. Public issues may describe the affected path and credential type, but must not include actual keys, account passwords, or private data.

## Published evidence

Public evidence uses workspace-neutral `/slb/` aliases for experiment-host paths. Explicit source-to-public ledgers record path aliasing and transport-field removal. Source hashes identify the original records; public hashes authenticate the redistributed bytes. Offline verification preserves the scoring criteria and reproduces the recorded decisions without requiring removed session state.

Removing sensitive content from the latest file does not remove older Git objects. Release preparation must scan reachable history and compressed archives as well as the current tree. Git author identity is an intentional project attribution choice, separate from model credentials and session state.

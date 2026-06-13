# Contributing

Thanks for contributing to FlowProxy.

## Prerequisites

- Go 1.22+
- Linux/macOS shell environment

## Development Setup

```bash
go test ./...
```

For local runtime testing:

```bash
./start.sh
```

## Pull Request Guidelines

- Keep changes focused and atomic.
- Add or update tests for behavior changes.
- Run `go test ./...` before opening a PR.
- Update `README.md` or example config/docs when user-facing behavior changes.
- Avoid committing local runtime data under `data/` or local env files.

## Commit Style

- Use clear, imperative commit messages.
- Mention security-relevant changes explicitly in the commit message and PR description.

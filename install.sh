#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-.}"
TARGET="$(cd "$TARGET" && pwd)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -d "$TARGET/.git" ]; then
  echo "error: target is not a Git repository: $TARGET" >&2
  exit 1
fi

mkdir -p "$TARGET/tools" "$TARGET/.github/workflows"
cp "$HERE/tools/privacy_guard.py" "$TARGET/tools/privacy_guard.py"
chmod +x "$TARGET/tools/privacy_guard.py"

if [ ! -f "$TARGET/.pre-commit-config.yaml" ]; then
  cp "$HERE/examples/.pre-commit-config.yaml" "$TARGET/.pre-commit-config.yaml"
else
  echo "notice: .pre-commit-config.yaml already exists; merge examples/.pre-commit-config.yaml manually if needed"
fi

if [ ! -f "$TARGET/gitleaks.toml" ]; then
  cp "$HERE/examples/gitleaks.toml" "$TARGET/gitleaks.toml"
fi

if [ ! -f "$TARGET/.privacy-guard-allowlist" ]; then
  cp "$HERE/examples/privacy-guard-allowlist" "$TARGET/.privacy-guard-allowlist"
fi

cp "$HERE/examples/pre-push" "$TARGET/.git/hooks/pre-push"
chmod +x "$TARGET/.git/hooks/pre-push"

if [ ! -f "$TARGET/.github/workflows/privacy-guard.yml" ]; then
  cp "$HERE/.github/workflows/privacy-guard.yml" "$TARGET/.github/workflows/privacy-guard.yml"
fi

if command -v pre-commit >/dev/null 2>&1; then
  (cd "$TARGET" && pre-commit install)
else
  echo "notice: pre-commit not found. Install it with: python3 -m pip install --user pre-commit"
fi

echo "installed GitHub Privacy Push Guard into $TARGET"
echo "run: cd '$TARGET' && python3 tools/privacy_guard.py --all-files --fail-on medium"

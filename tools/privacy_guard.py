#!/usr/bin/env python3
"""Privacy guard for GitHub publishing.

Scans staged files or tracked files for secrets, private data, and dangerous files.
Uses only Python standard library so it can run in Git hooks without extra packages.
"""
from __future__ import annotations

import argparse
import math
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

SENSITIVE_FILENAMES = [
    (re.compile(r"(^|/)\.env(\.(?!example$)[^/]+)?$"), "critical", "env_file"),
    (re.compile(r"(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519)$"), "critical", "ssh_private_key_file"),
    (re.compile(r"\.(pem|key|p12|pfx)$", re.I), "critical", "private_key_or_cert_file"),
    (re.compile(r"(^|/)(credentials|service-account|firebase-adminsdk).*\.json$", re.I), "critical", "credential_json"),
    (re.compile(r"(^|/)(\.npmrc|\.pypirc|\.netrc)$"), "high", "credential_config"),
    (re.compile(r"(^|/)(kubeconfig|config)$", re.I), "medium", "possible_cluster_config"),
    (re.compile(r"\.(sql|sqlite|sqlite3|db|dump|bak)$", re.I), "high", "database_or_dump_file"),
    (re.compile(r"\.(tar|tar\.gz|zip|7z|rar)$", re.I), "medium", "archive_file"),
    (re.compile(r"\.(log)$", re.I), "medium", "log_file"),
]

PATTERNS = [
    ("critical", "private_key_block", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("critical", "github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b")),
    ("critical", "github_fine_grained_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("critical", "openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("critical", "aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("critical", "slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("critical", "jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("critical", "password_assignment", re.compile(r"(?i)\b[A-Z0-9_-]*(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)\b\s*[:=]\s*['\"]?[^'\"\s]{8,}")),
    ("high", "database_url_with_password", re.compile(r"(?i)\b(?:postgres|postgresql|mysql|mongodb|redis)://[^\s:@]+:[^\s:@]+@[^\s]+")),
    ("medium", "email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)),
    ("medium", "japanese_phone", re.compile(r"\b0\d{1,4}[- ]?\d{1,4}[- ]?\d{3,4}\b")),
    ("medium", "postal_code_jp", re.compile(r"\b\d{3}-\d{4}\b")),
    ("medium", "home_path", re.compile(r"(?:/Users/|/home/)[A-Za-z0-9._-]+")),
    ("medium", "private_ipv4", re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")),
]

TOKEN_RE = re.compile(r"\b[A-Za-z0-9_+/=-]{32,}\b")

@dataclass
class Finding:
    severity: str
    kind: str
    path: str
    line_no: int | None
    preview: str


def run_git(args: Sequence[str], cwd: Path) -> bytes:
    return subprocess.check_output(["git", *args], cwd=str(cwd))


def repo_root() -> Path:
    try:
        root = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], stderr=subprocess.DEVNULL)
        return Path(root.decode().strip())
    except Exception:
        return Path.cwd()


def split_z(data: bytes) -> list[str]:
    return [x.decode("utf-8", errors="replace") for x in data.split(b"\0") if x]


def staged_files(root: Path) -> list[str]:
    data = run_git(["diff", "--cached", "--name-only", "--diff-filter=ACMRT", "-z"], root)
    return split_z(data)


def tracked_files(root: Path) -> list[str]:
    data = run_git(["ls-files", "-z"], root)
    return split_z(data)


def file_content_from_index(root: Path, rel: str) -> bytes | None:
    try:
        return run_git(["show", f":{rel}"], root)
    except Exception:
        return None


def file_content_from_worktree(root: Path, rel: str, max_bytes: int) -> tuple[bytes | None, Finding | None]:
    path = root / rel
    try:
        if path.is_symlink():
            return None, Finding("medium", "symlink_file_skipped", rel, None, "symlink target not scanned")
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
        if not resolved.is_file() or resolved.stat().st_size > max_bytes:
            return None, None
        return resolved.read_bytes(), None
    except Exception:
        return None, None


def is_binary(data: bytes) -> bool:
    return b"\0" in data[:4096]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {ch: s.count(ch) for ch in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


def redact(text: str) -> str:
    redacted = text
    replacements = [
        (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{8,}\b"), "<GITHUB_TOKEN_REDACTED>"),
        (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{8,}\b"), "<GITHUB_TOKEN_REDACTED>"),
        (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{8,}\b"), "<OPENAI_API_KEY_REDACTED>"),
        (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "<AWS_ACCESS_KEY_REDACTED>"),
        (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{8,}\b"), "<SLACK_TOKEN_REDACTED>"),
        (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "<JWT_REDACTED>"),
        (re.compile(r"(?i)\b([A-Z0-9_-]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token))(\s*[:=]\s*)['\"]?(?!<[^>]+_REDACTED>)[^'\"\s]+"), r"\1\2<REDACTED>"),
        (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), "<EMAIL_REDACTED>"),
        (re.compile(r"(?:/Users/|/home/)[A-Za-z0-9._-]+"), "/home/<USER>"),
        (re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"), "<PRIVATE_IP_REDACTED>"),
    ]
    for pattern, replacement in replacements:
        redacted = pattern.sub(replacement, redacted)
    return redacted[:240]


def load_allowlist(path: Path) -> list[re.Pattern[str]]:
    if not path.exists():
        return []
    patterns: list[re.Pattern[str]] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            patterns.append(re.compile(line))
        except re.error as exc:
            print(f"warning: invalid allowlist regex ignored: {line} ({exc})", file=sys.stderr)
    return patterns


def allowed(f: Finding, allowlist: Sequence[re.Pattern[str]]) -> bool:
    haystack = f"{f.severity}:{f.kind}:{f.path}:{f.line_no or ''}:{f.preview}"
    return any(p.search(haystack) for p in allowlist)


def filename_findings(rel: str) -> list[Finding]:
    out: list[Finding] = []
    normalized = rel.replace(os.sep, "/")
    for pattern, severity, kind in SENSITIVE_FILENAMES:
        if pattern.search(normalized):
            out.append(Finding(severity, kind, rel, None, "sensitive filename"))
    return out


def scan_text(rel: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        for severity, kind, pattern in PATTERNS:
            if pattern.search(line):
                out.append(Finding(severity, kind, rel, i, redact(line.strip())))
        for m in TOKEN_RE.finditer(line):
            token = m.group(0)
            # Avoid common harmless long zero/hex-ish hashes unless extremely random-looking.
            if re.fullmatch(r"[a-fA-F0-9]{32,128}", token):
                continue
            if token.count("/") > 0 or token.count("-") > 3:
                continue
            if entropy(token) >= 4.2:
                out.append(Finding("medium", "high_entropy_token", rel, i, redact(line.strip())))
                break
    return out


def scan_files(root: Path, files: Iterable[str], staged: bool, max_bytes: int) -> list[Finding]:
    findings: list[Finding] = []
    for rel in files:
        findings.extend(filename_findings(rel))
        if staged:
            data = file_content_from_index(root, rel)
        else:
            data, file_finding = file_content_from_worktree(root, rel, max_bytes)
            if file_finding is not None:
                findings.append(file_finding)
        if data is None:
            continue
        if len(data) > max_bytes:
            findings.append(Finding("medium", "large_file_skipped", rel, None, f"file larger than {max_bytes} bytes"))
            continue
        if is_binary(data):
            findings.append(Finding("medium", "binary_file_skipped", rel, None, "binary content; manual review recommended"))
            continue
        text = data.decode("utf-8", errors="replace")
        findings.extend(scan_text(rel, text))
    return findings


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan files before publishing to GitHub.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged", action="store_true", help="scan staged files from the Git index")
    mode.add_argument("--all-files", action="store_true", help="scan all tracked files")
    parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="high", help="minimum severity that causes non-zero exit")
    parser.add_argument("--allowlist", default=".privacy-guard-allowlist", help="regex allowlist file")
    parser.add_argument("--max-bytes", type=int, default=2_000_000, help="maximum bytes per file to scan")
    args = parser.parse_args(argv)

    root = repo_root()
    files = staged_files(root) if args.staged else tracked_files(root)
    allowlist = load_allowlist(root / args.allowlist)
    findings = [f for f in scan_files(root, files, args.staged, args.max_bytes) if not allowed(f, allowlist)]

    if not findings:
        print("privacy_guard: OK - no unallowed findings detected")
        return 0

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.path, f.line_no or 0, f.kind))
    print("privacy_guard: findings detected")
    for f in findings:
        loc = f"{f.path}:{f.line_no}" if f.line_no else f.path
        print(f"- [{f.severity.upper()}] {f.kind} at {loc} :: {f.preview}")

    threshold = SEVERITY_ORDER[args.fail_on]
    should_fail = any(SEVERITY_ORDER[f.severity] >= threshold for f in findings)
    if should_fail:
        print(f"privacy_guard: BLOCKED because findings >= {args.fail_on}", file=sys.stderr)
        return 2

    print(f"privacy_guard: warnings only; no findings >= {args.fail_on}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

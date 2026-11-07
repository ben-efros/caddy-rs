#!/usr/bin/env python3
"""Advisory LLM review of a pull request diff.

Security posture:
* The diff is sent to an operator-provided endpoint only when `LLM_API_KEY` is set; without it the
  script exits 0 after saying so, so the check is a no-op on forks and in private mirrors.
* The result is posted as a *comment*. It never approves, never requests changes and is never a
  required status check: a human maintainer remains the approving reviewer.
* Secrets are redacted from the diff before it leaves the runner, and the request is limited to the
  PR diff so unrelated repository content is not disclosed.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

MAX_DIFF_BYTES = 120_000
SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"]?[A-Za-z0-9/+_-]{16,}"),
]

PROMPT = """You are reviewing a Rust pull request for caddy-rs, a Caddy-compatible web server.
Report only concrete defects a maintainer must act on, ordered by severity. Focus on:
1. security: untrusted input handling, TLS/auth mistakes, path traversal, injection, secret leakage;
2. correctness: logic errors, panics on network input, unbounded memory or blocking in async code;
3. tests: behaviour changed without a test, or a test that cannot fail.
Ignore style and naming. If nothing is wrong, say so in one line. Keep it under 300 words.

Diff:
"""


def redact(diff: str) -> str:
    for pattern in SECRET_PATTERNS:
        diff = pattern.sub("[REDACTED]", diff)
    return diff


def pr_diff() -> str:
    base = os.environ.get("PR_BASE_SHA") or "origin/main"
    out = subprocess.run(
        ["git", "diff", f"{base}...HEAD"], capture_output=True, text=True, check=False
    )
    diff = out.stdout[:MAX_DIFF_BYTES]
    return redact(diff)


def call(endpoint: str, key: str, model: str, diff: str) -> str:
    payload = json.dumps(
        {
            "model": model,
            "messages": [
                {"role": "system", "content": "You are a careful security-focused code reviewer."},
                {"role": "user", "content": PROMPT + diff},
            ],
            "temperature": 0,
        }
    ).encode()
    request = urllib.request.Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        body = json.load(response)
    return body["choices"][0]["message"]["content"].strip()


def main() -> int:
    key = os.environ.get("LLM_API_KEY")
    if not key:
        print("ai-review: LLM_API_KEY is not configured; skipping (advisory check only)")
        return 0
    endpoint = os.environ.get("LLM_ENDPOINT", "https://api.openai.com/v1/chat/completions")
    model = os.environ.get("LLM_MODEL", "gpt-4o-mini")
    diff = pr_diff()
    if not diff.strip():
        print("ai-review: empty diff; nothing to review")
        return 0
    try:
        review = call(endpoint, key, model, diff)
    except (urllib.error.URLError, KeyError, TimeoutError) as error:
        # Never fail the build on an advisory check.
        print(f"ai-review: review unavailable ({error}); continuing without it")
        return 0
    print(review)
    if body_file := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(body_file, "a", encoding="utf-8") as summary:
            summary.write("## Advisory LLM review\n\n" + review + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

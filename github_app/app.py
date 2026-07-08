"""
github_app/app.py
GitHub App webhook server — listens for pull_request events,
runs code review analysis, and posts structured comments on PRs.

Setup:
    pip install flask PyGithub requests
    Set environment variables (see .env.example)
    Run: python github_app/app.py
"""

import os
import sys
import hmac
import hashlib
import json
import logging
import tempfile
from pathlib import Path
from typing import Any

from flask import Flask, request, jsonify, abort
from github import Github, GithubException

# Add model path
sys.path.insert(0, str(Path(__file__).parent.parent))
from model.train import CombinedAnalyzer

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

GITHUB_TOKEN         = os.environ.get("GITHUB_TOKEN", "")
WEBHOOK_SECRET       = os.environ.get("WEBHOOK_SECRET", "")
SUPPORTED_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go"}
MAX_FILE_LINES       = 1000   # skip very large files
MAX_FILES_PER_PR     = 20

# ─────────────────────────────────────────────
# SIGNATURE VERIFICATION
# ─────────────────────────────────────────────
def verify_signature(payload: bytes, sig_header: str) -> bool:
    """Verify GitHub webhook HMAC-SHA256 signature."""
    if not WEBHOOK_SECRET:
        logger.warning("WEBHOOK_SECRET not set — skipping signature check")
        return True
    if not sig_header or not sig_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, sig_header)


# ─────────────────────────────────────────────
# ANALYSIS ENGINE
# ─────────────────────────────────────────────
analyzer: CombinedAnalyzer | None = None

def get_analyzer() -> CombinedAnalyzer:
    global analyzer
    if analyzer is None:
        logger.info("Loading code review analyzer …")
        analyzer = CombinedAnalyzer()
    return analyzer


# ─────────────────────────────────────────────
# PR REVIEWER
# ─────────────────────────────────────────────
class PRReviewer:
    """Analyzes all changed files in a PR and posts review comments."""

    def __init__(self, gh_token: str):
        self.gh = Github(gh_token)
        self.engine = get_analyzer()

    def review_pr(self, repo_name: str, pr_number: int) -> dict[str, Any]:
        """Full PR review workflow."""
        logger.info("Reviewing %s#%d", repo_name, pr_number)
        try:
            repo = self.gh.get_repo(repo_name)
            pr   = repo.get_pull(pr_number)
        except GithubException as e:
            logger.error("GitHub API error: %s", e)
            return {"error": str(e)}

        files         = list(pr.get_files())[:MAX_FILES_PER_PR]
        all_findings  = []
        file_results  = []

        for gh_file in files:
            ext = Path(gh_file.filename).suffix.lower()
            if ext not in SUPPORTED_EXTENSIONS:
                continue
            if gh_file.status == "removed":
                continue

            # Fetch file content
            try:
                content_file = repo.get_contents(
                    gh_file.filename,
                    ref=pr.head.sha,
                )
                code = content_file.decoded_content.decode("utf-8", errors="replace")
            except Exception as e:
                logger.warning("Could not fetch %s: %s", gh_file.filename, e)
                continue

            if code.count("\n") > MAX_FILE_LINES:
                logger.info("Skipping large file: %s", gh_file.filename)
                continue

            result = self.engine.analyze(code, filename=gh_file.filename)
            file_results.append(result)
            all_findings.extend(result["rule_findings"])

            # Post inline comments for each finding
            for finding in result["rule_findings"]:
                self._post_inline_comment(pr, gh_file, finding)

        # Post summary review comment
        summary = self._build_summary(all_findings, file_results, pr)
        self._post_summary_comment(pr, summary)

        return {
            "pr":           pr_number,
            "files_checked": len(file_results),
            "total_findings": len(all_findings),
            "summary":      summary,
        }

    # ── Inline comment ────────────────────────
    def _post_inline_comment(self, pr, gh_file, finding: dict):
        """Post a review comment at a specific line."""
        icon = {
            "critical": "🔴",
            "high":     "🟠",
            "medium":   "🟡",
            "low":      "🔵",
            "none":     "✅",
        }.get(finding["severity"], "⚪")

        body = (
            f"{icon} **[{finding['severity'].upper()}] {finding['rule_id']}** "
            f"— `{finding['category']}`\n\n"
            f"{finding['message']}\n\n"
            f"> **Snippet:** `{finding['snippet'][:120]}`"
        )
        try:
            pr.create_review_comment(
                body=body,
                commit=pr.get_commits().reversed[0],
                path=gh_file.filename,
                line=finding["line"],
            )
        except GithubException as e:
            logger.warning("Could not post inline comment on line %d: %s", finding["line"], e)

    # ── Summary comment ───────────────────────
    def _build_summary(self, findings: list, file_results: list, pr) -> str:
        from collections import Counter
        sev_counts = Counter(f["severity"] for f in findings)
        cat_counts = Counter(f["category"] for f in findings)

        passed = all(r["passed"] for r in file_results)
        status_line = "✅ **All checks passed!**" if passed else "❌ **Issues detected — review required.**"

        lines = [
            "## 🤖 AI Code Review Report",
            "",
            status_line,
            "",
            f"**Files analyzed:** {len(file_results)} | "
            f"**Total findings:** {len(findings)}",
            "",
        ]

        if findings:
            lines += [
                "### 📊 Severity Breakdown",
                "| Severity | Count |",
                "|----------|-------|",
            ]
            for sev in ["critical", "high", "medium", "low"]:
                n = sev_counts.get(sev, 0)
                if n:
                    icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}[sev]
                    lines.append(f"| {icon} {sev.capitalize()} | {n} |")

            lines += [
                "",
                "### 🔍 Finding Categories",
                "| Category | Count |",
                "|----------|-------|",
            ]
            for cat, n in cat_counts.most_common():
                lines.append(f"| `{cat}` | {n} |")

        lines += [
            "",
            "---",
            "*Powered by AI Code Review — CodeBERT + Static Analysis*",
        ]
        return "\n".join(lines)

    def _post_summary_comment(self, pr, body: str):
        try:
            pr.create_issue_comment(body)
        except GithubException as e:
            logger.error("Could not post summary comment: %s", e)


# ─────────────────────────────────────────────
# WEBHOOK ROUTES
# ─────────────────────────────────────────────
@app.route("/webhook", methods=["POST"])
def webhook():
    """GitHub webhook endpoint for pull_request events."""
    payload_bytes = request.get_data()
    sig_header    = request.headers.get("X-Hub-Signature-256", "")

    if not verify_signature(payload_bytes, sig_header):
        logger.warning("Invalid webhook signature")
        abort(403)

    event = request.headers.get("X-GitHub-Event", "")
    if event not in ("pull_request",):
        return jsonify({"status": "ignored", "event": event}), 200

    try:
        data = json.loads(payload_bytes)
    except json.JSONDecodeError:
        abort(400)

    action = data.get("action", "")
    if action not in ("opened", "synchronize", "reopened"):
        return jsonify({"status": "ignored", "action": action}), 200

    repo_name = data["repository"]["full_name"]
    pr_number = data["pull_request"]["number"]

    logger.info("PR event: %s %s#%d", action, repo_name, pr_number)

    if not GITHUB_TOKEN:
        return jsonify({"error": "GITHUB_TOKEN not set"}), 500

    reviewer = PRReviewer(GITHUB_TOKEN)
    result   = reviewer.review_pr(repo_name, pr_number)

    return jsonify(result), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "ai-code-review"}), 200


@app.route("/analyze", methods=["POST"])
def analyze_snippet():
    """Direct API endpoint: POST {code, filename} → analysis result."""
    data     = request.get_json(force=True)
    code     = data.get("code", "")
    filename = data.get("filename", "<stdin>")

    if not code:
        return jsonify({"error": "No code provided"}), 400

    engine = get_analyzer()
    result = engine.analyze(code, filename=filename)
    return jsonify(result), 200


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info("Starting AI Code Review GitHub App on port %d …", port)
    app.run(host="0.0.0.0", port=port, debug=False)

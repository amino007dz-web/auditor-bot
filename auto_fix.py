"""
Auto-Fix PR — Fork + apply fixes + Pull Request automatically via GitHub.
"""
import json
import logging
import os
import re
from typing import List, Optional

from github import Github, GithubException

from agents import call_model_with_fallback
from config import OPENROUTER_API_KEY

logger = logging.getLogger(__name__)


def _extract_fixes(report: str) -> List[dict]:
    """Extract fix code from the audit report."""
    fixes: List[dict] = []
    blocks = re.findall(
        r'###\s*\d*:?\s*(.*?)\n.*?(?:Fix|Remediation)\s*:\s*(.*?)(?=\n###|\Z)',
        report, re.DOTALL
    )
    for title, fix_text in blocks:
        code_blocks = re.findall(r'```(?:solidity)?\n(.*?)```', fix_text, re.DOTALL)
        if code_blocks:
            fixes.append({
                "title": title.strip()[:100],
                "description": fix_text.strip()[:300],
                "code": code_blocks[0].strip(),
            })
    # Fallback: find any code inside ```
    if not fixes:
        for m in re.finditer(r'```(?:solidity)?\n(.*?)```', report, re.DOTALL):
            fixes.append({
                "title": f"Fix #{len(fixes)+1}",
                "description": "",
                "code": m.group(1).strip(),
            })
    return fixes


def _apply_fix_to_code(original: str, fix_code: str) -> str:
    """Apply fix code to original code via AI."""
    prompt = f"""I have a smart contract and a fix report. Apply the following changes to the original code and output only the modified version.

Original code:
```solidity
{original[:4000]}
```

Fix to apply:
```solidity
{fix_code[:2000]}
```

Output the entire code after applying the fix inside ```solidity."""
    try:
        result = call_model_with_fallback(prompt, timeout=180)
        code_block = re.search(r'```(?:solidity)?\n(.*?)```', result, re.DOTALL)
        if code_block:
            return code_block.group(1).strip()
        return original
    except Exception as e:
        logger.warning(f"Fix application failed: {e}")
        return original


def create_fix_pr(repo_url: str, code: str, report: str,
                   github_token: str, branch_name: str = "auto-fix") -> str:
    """Create Fork + apply fixes + PR to original repository."""
    from github_loader import extract_repo_info

    username, repo_name = extract_repo_info(repo_url)
    if not username or not repo_name:
        return "❌ Invalid GitHub URL"

    try:
        g = Github(github_token)
        user = g.get_user()
        original_repo = g.get_repo(f"{username}/{repo_name}")

        # Fork
        logger.info(f"Forking {username}/{repo_name}...")
        try:
            fork = user.create_fork(original_repo)
            logger.info(f"Fork created: {fork.html_url}")
        except GithubException as e:
            if e.status == 202:
                fork = user.get_repo(repo_name)
                logger.info("Fork already exists, reusing.")
            else:
                return f"❌ Fork failed: {e}"

        # Extract fixes
        fixes = _extract_fixes(report)
        if not fixes:
            return "❌ No fix code found in the report"

        # Apply fixes
        modified_code = code
        for fix in fixes:
            if fix["code"]:
                modified_code = _apply_fix_to_code(modified_code, fix["code"])

        if modified_code == code:
            return "❌ Version unchanged — no fix was applied"

        # Push the new branch
        try:
            sb = fork.get_branch(original_repo.default_branch)
            fork.create_git_ref(
                ref=f"refs/heads/{branch_name}",
                sha=sb.commit.sha
            )

            # Edit the file
            contents = fork.get_contents("", ref=branch_name)
            for content in contents:
                if content.path.endswith(".sol"):
                    fork.update_file(
                        path=content.path,
                        message=f"Auto-fix: {fixes[0]['title'][:50]}" if fixes else "Auto-fix by Smart Contract Auditor",
                        content=modified_code,
                        sha=content.sha,
                        branch=branch_name,
                    )
                    break

        except GithubException as e:
            return f"❌ Failed to apply changes: {e}"

        # Create PR
        fix_summary = "\n".join(f"- {f['title']}" for f in fixes[:5])
        pr_body = f"""## Auto-Fix by Smart Contract Auditor

The following fixes were applied automatically:

{fix_summary}

{"- ... and more" if len(fixes) > 5 else ""}

> This Pull Request was created automatically by the Security Audit Tool.
> Please review the changes before merging.
"""
        try:
            pr = original_repo.create_pull(
                title="Auto-Fix: Security Audit Recommendations",
                body=pr_body,
                head=f"{user.login}:{branch_name}",
                base=original_repo.default_branch,
            )
            return f"✅ PR created: {pr.html_url}"
        except GithubException as e:
            return f"❌ Failed to create PR: {e}"

    except Exception as e:
        return f"❌ Error: {e}"

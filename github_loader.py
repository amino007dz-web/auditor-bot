import logging
import re
import requests
from typing import List, Dict, Optional, Tuple

if not logging.getLogger().hasHandlers():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def extract_repo_info(repo_url: str) -> Tuple[Optional[str], Optional[str]]:
    pattern: str = r"github\.com/([^/]+)/([^/]+)"
    match = re.search(pattern, repo_url)
    if match:
        return match.group(1), match.group(2).replace('.git', '')
    return None, None


SUPPORTED_EXTS: tuple = (".sol", ".vy", ".move", ".clsp", ".clib", ".rs", ".py")
MAX_FILES_LIMIT = 20


def get_all_sol_files(username: str, repo_name: str, github_token: Optional[str] = None) -> List[Dict[str, str]]:
    api_base = f"https://api.github.com/repos/{username}/{repo_name}"
    headers = {"Accept": "application/vnd.github+json"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    try:
        r = requests.get(api_base, headers=headers, timeout=15)
        r.raise_for_status()
        default_branch = r.json().get("default_branch", "main")
        logger.info(f"✅ Repository accessed. Branch: {default_branch}")

        tree_url = f"{api_base}/git/trees/{default_branch}?recursive=1"
        r = requests.get(tree_url, headers=headers, timeout=30)
        r.raise_for_status()
        tree_data = r.json()

        sol_paths = []
        for item in tree_data.get("tree", []):
            if item["type"] == "blob" and any(item["path"].endswith(ext) for ext in SUPPORTED_EXTS):
                sol_paths.append(item["path"])
        sol_paths.sort(key=lambda p: (
            "test" in p.lower() or "mock" in p.lower() or "migration" in p.lower(),
        ))
        sol_paths = sol_paths[:MAX_FILES_LIMIT]

        contracts = []
        for path in sol_paths:
            raw_url = f"https://raw.githubusercontent.com/{username}/{repo_name}/{default_branch}/{path}"
            try:
                r = requests.get(raw_url, timeout=15)
                if r.status_code == 200:
                    contracts.append({"name": path, "code": r.text})
                    logger.info(f"✅ Found: {path}")
                else:
                    logger.warning(f"⚠️ Failed to download {path}: HTTP {r.status_code}")
            except Exception as e:
                logger.warning(f"⚠️ Error downloading {path}: {e}")

        logger.info(f"📊 Found {len(contracts)} contract(s).")
        return contracts

    except requests.exceptions.RequestException as e:
        logger.error(f"❌ GitHub API request failed: {e}")
        return []


def download_contracts(repo_url: str, github_token: Optional[str] = None) -> List[Dict[str, str]]:
    username, repo_name = extract_repo_info(repo_url)
    if not username or not repo_name:
        logger.error("❌ Invalid GitHub URL. Must be: https://github.com/username/repo")
        return []

    logger.info(f"🔍 Connecting to: {username}/{repo_name} ...")
    return get_all_sol_files(username, repo_name, github_token)

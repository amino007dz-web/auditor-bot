import logging
import re
from typing import List, Dict, Optional, Tuple
from github import Github, GithubException

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
MAX_DEPTH = 20

def get_all_sol_files(repo, path: str = "", depth: int = 0, collected: list = None) -> List[Dict[str, str]]:
    if collected is None:
        collected = []
    if depth > MAX_DEPTH or len(collected) >= MAX_FILES_LIMIT:
        return collected
    try:
        contents = repo.get_contents(path)
        for content in contents:
            if len(collected) >= MAX_FILES_LIMIT:
                break
            if content.type == "dir":
                get_all_sol_files(repo, content.path, depth + 1, collected)
            elif any(content.path.endswith(ext) for ext in SUPPORTED_EXTS):
                try:
                    file_content = content.decoded_content.decode('utf-8')
                    collected.append({
                        "name": content.path,
                        "code": file_content
                    })
                    logger.info(f"✅ Found: {content.path}")
                except Exception as e:
                    logger.warning(f"⚠️ Error reading {content.path}: {e}")
    except GithubException as e:
        if e.status == 403:
            logger.warning(f"⚠️ GitHub rate limit exceeded for {path}. Use a token to increase from 60 to 5000 req/hr.")
        else:
            logger.warning(f"⚠️ GitHub error accessing {path}: {e}")
    return collected


def download_contracts(repo_url: str, github_token: Optional[str] = None) -> List[Dict[str, str]]:
    username, repo_name = extract_repo_info(repo_url)
    if not username or not repo_name:
        logger.error("❌ Invalid GitHub URL. Must be: https://github.com/username/repo")
        return []

    logger.info(f"🔍 Connecting to: {username}/{repo_name} ...")
    g: Github = Github(github_token) if github_token else Github()

    try:
        repo = g.get_repo(f"{username}/{repo_name}")
        logger.info("✅ Repository accessed.")
        logger.info("📂 Searching for all .sol files...")
        contracts: List[Dict[str, str]] = get_all_sol_files(repo)

        if not contracts:
            logger.warning("❌ No Solidity (.sol) files found in this repository.")
        else:
            logger.info(f"📊 Found {len(contracts)} contract(s).")
        return contracts

    except GithubException as e:
        logger.error(f"❌ Failed to access repository: {e}")
        return []

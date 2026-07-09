"""
RAG Context Builder — injects relevant past vulnerabilities into AI prompts.
"""
import logging
import re
from typing import Dict, List, Optional

from knowledge_base.db import KnowledgeBase

logger = logging.getLogger(__name__)

CONTRACT_TYPE_KEYWORDS: Dict[str, List[str]] = {
    "ERC20":        ["ERC20", "IERC20", "transfer", "approve", "allowance", "totalSupply", "balanceOf"],
    "ERC721":       ["ERC721", "IERC721", "safeTransferFrom", "mint", "tokenURI", "ownerOf"],
    "ERC1155":      ["ERC1155", "IERC1155", "safeTransferFrom", "uri"],
    "Lending":      ["lend", "borrow", "collateral", "liquidate", "interestRate", "loan"],
    "DEX/AMM":      ["swap", "pool", "liquidity", "addLiquidity", "removeLiquidity", "reserve"],
    "Bridge":       ["bridge", "relay", "crossChain", "message", "validator", "consensus"],
    "Staking":      ["stake", "unstake", "reward", "withdrawStake", "delegate"],
    "Governance":   ["propose", "vote", "quorum", "governor", "timelock"],
    "Vault":        ["vault", "deposit", "withdraw", "share", "strategy", "harvest"],
    "Oracle":       ["oracle", "priceFeed", "getPrice", "aggregator", "roundData"],
    "Multisig":     ["multisig", "signature", "confirm", "execute", "threshold"],
    "Proxy":        ["proxy", "delegatecall", "implementation", "upgradeTo", "UUPS"],
}


def detect_contract_type(code: str) -> str:
    code_lower = code.lower()
    scores = {}
    for ctype, keywords in CONTRACT_TYPE_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw.lower() in code_lower)
        if score > 0:
            scores[ctype] = score
    if not scores:
        return "General"
    return max(scores, key=scores.get)


def extract_key_functions(code: str) -> List[str]:
    funcs = re.findall(r'function\s+(\w+)\s*\(', code)
    return funcs[:15]


class RAGContext:
    """Builds relevant context from the Knowledge Base for a given code snippet."""

    def __init__(self, kb: KnowledgeBase, max_context_chars: int = 2000):
        self.kb = kb
        self.max_context_chars = max_context_chars
        self._vectorizer = None
        self._tfidf_matrix = None
        self._cached_patterns = []
        self._pattern_count = 0

        self._use_tfidf = False
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            self._TfidfVectorizer = TfidfVectorizer
            self._use_tfidf = True
        except ImportError:
            logger.info("scikit-learn not available, falling back to keyword search")

    def update_embeddings(self):
        """Rebuild the TF-IDF matrix from KB vulnerability patterns."""
        if not self._use_tfidf:
            return
        patterns = self.kb.get_patterns_by_severity(limit=1000)
        if not patterns:
            return
        texts = []
        for p in patterns:
            text = " ".join([p.get('name', ''), p.get('description', ''),
                            p.get('code_snippet', ''), p.get('contract_type', '')])
            texts.append(text)
        self._vectorizer = self._TfidfVectorizer(max_features=1000, stop_words='english')
        self._tfidf_matrix = self._vectorizer.fit_transform(texts)
        self._cached_patterns = patterns
        self._pattern_count = len(patterns)

    def _tfidf_retrieve(self, code: str, top_k: int) -> List[Dict]:
        if self._vectorizer is None or self._tfidf_matrix is None:
            self.update_embeddings()
        if self._vectorizer is None or self._tfidf_matrix is None:
            return []
        query_vec = self._vectorizer.transform([code])
        from sklearn.metrics.pairwise import cosine_similarity
        scores = cosine_similarity(query_vec, self._tfidf_matrix).flatten()
        top_indices = scores.argsort()[-top_k:][::-1]
        return [self._cached_patterns[i] for i in top_indices if scores[i] > 0]

    def build_context(self, code: str, top_k: int = 3) -> str:
        contract_type = detect_contract_type(code)
        extract_key_functions(code)

        if self._use_tfidf:
            if self._pattern_count != len(self.kb.get_patterns_by_severity(limit=1000)):
                self.update_embeddings()
            patterns = self._tfidf_retrieve(code, top_k)
        else:
            patterns = self.kb.find_similar_patterns(code[:200], contract_type, limit=top_k)

        if not patterns:
            return ""
        parts: List[str] = []
        parts.append(f"## Similar Previous Vulnerability Patterns (Contract Type: {contract_type})")
        parts.append("")
        for p in patterns:
            if len("\n".join(parts)) > self.max_context_chars:
                break
            line = f"- **{p.get('name', '?')}** [{p.get('severity', '?')}] — {p.get('description', '')[:200]}"
            if p.get('fix_code'):
                line += f"\n  - Previous Fix: `{p['fix_code'][:150]}`"
            parts.append(line)
            self.kb.increment_hit(p['id'])
        parts.append("")
        return "\n".join(parts)

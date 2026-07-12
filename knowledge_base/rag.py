"""
RAG Context Builder — injects relevant past vulnerabilities into AI prompts.
Supports Sentence-Transformers (semantic), TF-IDF (keyword), and keyword fallback.
"""
import logging
import re
import os
from typing import Dict, List, Optional
from dataclasses import dataclass

from knowledge_base.db import KnowledgeBase

logger = logging.getLogger(__name__)

CONTRACT_TYPE_KEYWORDS: Dict[str, List[str]] = {
    "ERC20":        ["ERC20", "IERC20", "transfer", "transferFrom", "approve", "allowance", "totalSupply", "balanceOf"],
    "ERC721":       ["ERC721", "IERC721", "safeTransferFrom", "mint", "tokenURI", "ownerOf"],
    "ERC1155":      ["ERC1155", "IERC1155", "safeTransferFrom", "uri", "balanceOfBatch"],
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


@dataclass
class _EmbCache:
    patterns: List[Dict]
    texts: List[str]
    model: object


class RAGContext:
    """Builds relevant context from the Knowledge Base using semantic search + fallback."""

    def __init__(self, kb: KnowledgeBase, max_context_chars: int = 2000):
        self.kb = kb
        self.max_context_chars = max_context_chars
        self._cache: Optional[_EmbCache] = None
        self._pattern_count = 0

        self._use_st = False
        self._use_tfidf = False
        _st_available = False
        try:
            import sentence_transformers
            _st_available = True
        except ImportError:
            pass
        if _st_available and os.environ.get("KB_USE_ST", "1") == "1":
            try:
                from sentence_transformers import SentenceTransformer
                self._st_model = SentenceTransformer("all-MiniLM-L6-v2")
                self._use_st = True
                logger.info("RAG: Sentence-Transformer model loaded (all-MiniLM-L6-v2)")
            except Exception as e:
                logger.warning(f"sentence-transformers load failed: {e}")
        if not self._use_st:
            try:
                from sklearn.feature_extraction.text import TfidfVectorizer
                self._TfidfVectorizer = TfidfVectorizer
                self._use_tfidf = True
                logger.info("RAG: using TF-IDF fallback")
            except ImportError:
                logger.info("scikit-learn not available, falling back to keyword search")

    def _encode_texts(self, texts: List[str]) -> object:
        if self._use_st:
            return self._st_model.encode(texts, convert_to_tensor=False, show_progress_bar=False)
        if self._use_tfidf:
            return self._vectorizer.fit_transform(texts)
        return None

    def _encode_query(self, text: str):
        if self._use_st:
            return self._st_model.encode([text], convert_to_tensor=False, show_progress_bar=False)[0]
        if self._use_tfidf:
            return self._vectorizer.transform([text])
        return None

    def _cosine_similarity(self, query_vec, matrix) -> List[float]:
        if self._use_st:
            import numpy as np
            query_norm = query_vec / (np.linalg.norm(query_vec) + 1e-10)
            matrix_norm = matrix / (np.linalg.norm(matrix, axis=1, keepdims=True) + 1e-10)
            return (matrix_norm @ query_norm).tolist()
        if self._use_tfidf:
            from sklearn.metrics.pairwise import cosine_similarity
            return cosine_similarity(query_vec, matrix).flatten().tolist()
        return []

    def update_embeddings(self):
        patterns = self.kb.get_patterns_by_severity(limit=2000)
        if not patterns:
            return
        texts = []
        for p in patterns:
            texts.append(" ".join([p.get('name', ''), p.get('description', ''),
                                   str(p.get('code_snippet', '')), p.get('contract_type', '')]))
        if self._use_tfidf:
            self._vectorizer = self._TfidfVectorizer(max_features=1000, stop_words='english')
        encoded = self._encode_texts(texts)
        self._cache = _EmbCache(patterns=patterns, texts=texts, model=encoded)
        self._pattern_count = len(patterns)

    def _vector_retrieve(self, code: str, top_k: int) -> List[Dict]:
        if self._cache is None or self._pattern_count != len(self.kb.get_patterns_by_severity(limit=2000)):
            self.update_embeddings()
        if self._cache is None:
            return []
        query_vec = self._encode_query(code)
        if query_vec is None:
            return []
        scores = self._cosine_similarity(query_vec, self._cache.model)
        indexed = list(enumerate(scores))
        indexed.sort(key=lambda x: x[1], reverse=True)
        results = []
        for idx, score in indexed:
            if score > 0.05 and len(results) < top_k:
                results.append(self._cache.patterns[idx])
        return results

    def build_context(self, code: str, top_k: int = 3) -> str:
        contract_type = detect_contract_type(code)
        extract_key_functions(code)

        if self._use_st or self._use_tfidf:
            patterns = self._vector_retrieve(code, top_k)
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

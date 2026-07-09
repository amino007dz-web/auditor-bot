import os, json, logging, hashlib
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

try:
    import chromadb
    from chromadb.config import Settings
    HAS_CHROMA = True
except ImportError:
    HAS_CHROMA = False

try:
    from sentence_transformers import SentenceTransformer
    HAS_SENTENCE = True
except ImportError:
    HAS_SENTENCE = False

VECTOR_DB_DIR = os.path.join(os.path.dirname(__file__), "vector_db")
COLLECTION_NAME = "vulnerability_knowledge"
EMBED_MODEL = "all-MiniLM-L6-v2"


class VectorKB:
    def __init__(self):
        self._client = None
        self._collection = None
        self._encoder = None
        self._ready = False
        self._init()

    def _init(self):
        if not HAS_CHROMA:
            logger.warning("chromadb not installed. pip install chromadb")
            return
        try:
            self._client = chromadb.PersistentClient(
                path=VECTOR_DB_DIR,
                settings=Settings(anonymized_telemetry=False, allow_reset=False),
            )
            self._collection = self._client.get_or_create_collection(
                name=COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"},
            )
            if HAS_SENTENCE:
                self._encoder = SentenceTransformer(EMBED_MODEL)
            self._ready = True
            logger.info(f"VectorKB ready ({self._collection.count()} entries)")
        except Exception as e:
            logger.warning(f"VectorKB init failed: {e}")

    def ready(self) -> bool:
        return self._ready

    def _embed(self, texts: List[str]) -> List[List[float]]:
        if self._encoder:
            return self._encoder.encode(texts).tolist()
        return [[0.0] * 384 for _ in texts]

    def add_knowledge(self, entries: List[Dict]):
        if not self._ready:
            return
        ids, texts, metas = [], [], []
        for e in entries:
            text = f"{e.get('title', '')} {e.get('description', '')} {e.get('code', '')} {e.get('fix', '')}"
            hid = hashlib.sha256(text.encode()).hexdigest()[:32]
            ids.append(hid)
            texts.append(text)
            metas.append({
                "vulnerability": e.get("title", ""),
                "severity": e.get("severity", ""),
                "category": e.get("category", ""),
                "language": e.get("language", "solidity"),
            })
        try:
            self._collection.add(
                documents=texts,
                embeddings=self._embed(texts),
                metadatas=metas,
                ids=ids,
            )
            logger.info(f"Added {len(entries)} entries to vector KB")
        except Exception as e:
            logger.warning(f"VectorKB add failed: {e}")

    def search(self, query: str, top_k: int = 5) -> List[Dict]:
        if not self._ready:
            return []
        try:
            results = self._collection.query(
                query_embeddings=self._embed([query]),
                n_results=top_k,
            )
            docs = []
            for i in range(len(results["ids"][0])):
                docs.append({
                    "id": results["ids"][0][i],
                    "text": results["documents"][0][i][:500],
                    "metadata": results["metadatas"][0][i],
                    "score": 1 - results["distances"][0][i],
                })
            return docs
        except Exception as e:
            logger.warning(f"VectorKB search failed: {e}")
            return []

    def count(self) -> int:
        return self._collection.count() if self._ready else 0

    def reset(self):
        if self._ready:
            try:
                self._client.delete_collection(COLLECTION_NAME)
                self._collection = self._client.create_collection(COLLECTION_NAME)
                logger.info("VectorKB reset")
            except Exception as e:
                logger.warning(f"VectorKB reset failed: {e}")


_KB = VectorKB()


def get_vector_kb() -> VectorKB:
    return _KB


def add_findings_as_knowledge(findings: list, language: str = "solidity"):
    entries = []
    for f in findings:
        entries.append({
            "title": f.agent_name,
            "description": f.description,
            "severity": f.severity,
            "category": f.category,
            "language": language,
            "code": f.fix or "",
        })
    _KB.add_knowledge(entries)


def search_similar(query: str, top_k: int = 5) -> List[Dict]:
    return _KB.search(query, top_k)

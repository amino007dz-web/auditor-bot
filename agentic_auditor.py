import os, re, json, logging
from typing import Dict, List, Optional, Set
from collections import defaultdict

_has_networkx = False
try:
    import networkx as nx
    _has_networkx = True
except ImportError:
    pass

logger = logging.getLogger(__name__)

IMPORT_RE = re.compile(r'import\s+[\"\'"]+([^\"\'"]+)[\"\'"]+')
SOL_PRAGMA_RE = re.compile(r'pragma\s+solidity\s+[^;]+;')
CONTRACT_RE = re.compile(r'(contract|interface|library|abstract\s+contract)\s+(\w+)')
INHERITANCE_RE = re.compile(r'contract\s+\w+\s+is\s+([^{]+)')


class AgenticAuditor:
    def __init__(self, root_dir: str = ""):
        self.root = root_dir
        self.files: Dict[str, str] = {}
        self.graph: Dict[str, List[str]] = defaultdict(list)
        self.contracts: Dict[str, str] = {}
        self.import_map: Dict[str, str] = {}
        self.remappings: Dict[str, str] = {}

    def load_directory(self, directory: str):
        self.root = directory
        exts = (".sol", ".vy", ".move", ".clsp", ".clib")
        entries = []
        for root, _, files in os.walk(directory):
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in exts:
                    path = os.path.join(root, f)
                    try:
                        with open(path, "r", encoding="utf-8") as fh:
                            content = fh.read()
                        rel = os.path.relpath(path, directory)
                        self.files[rel] = content
                        entries.append((rel, content))
                    except Exception as e:
                        logger.warning("Could not read %s: %s", path, e)
        self._load_remappings()
        for rel, content in entries:
            try:
                self._index_file(rel, content)
            except Exception as e:
                logger.warning("Could not index %s: %s", rel, e)

    def _index_file(self, path: str, content: str):
        for m in IMPORT_RE.finditer(content):
            imp = m.group(1)
            resolved = self._resolve_import(path, imp)
            if resolved:
                self.graph[path].append(resolved)

        contract_match = CONTRACT_RE.search(content)
        if contract_match:
            name = contract_match.group(2)
            self.contracts[name] = path

        inh = INHERITANCE_RE.search(content)
        if inh:
            bases = [b.strip() for b in inh.group(1).split(",")]
            for base in bases:
                if base in self.contracts:
                    base_path = self.contracts[base]
                    if base_path != path:
                        self.graph[path].append(base_path)

    def _load_remappings(self):
        self.remappings = {}
        remap_file = os.path.join(self.root, "remappings.txt")
        if os.path.isfile(remap_file):
            with open(remap_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        prefix, _, path = line.partition("=")
                        self.remappings[prefix.strip()] = path.strip()

        toml_file = os.path.join(self.root, "foundry.toml")
        if os.path.isfile(toml_file):
            with open(toml_file, "r", encoding="utf-8") as f:
                content = f.read()
            m = re.search(r'remappings\s*=\s*\[([^\]]+)\]', content, re.DOTALL)
            if m:
                for entry in re.findall(r'"([^"]+)"', m.group(1)):
                    if "=" in entry:
                        prefix, _, path = entry.partition("=")
                        self.remappings[prefix.strip()] = path.strip()

        logger.info("Loaded %d remappings", len(self.remappings))

    def _resolve_import(self, current: str, imp_path: str) -> Optional[str]:
        for prefix, local_path in self.remappings.items():
            if imp_path.startswith(prefix):
                relocated = os.path.normpath(os.path.join(local_path, imp_path[len(prefix):]))
                abs_check = os.path.normpath(os.path.join(self.root, relocated))
                if abs_check in self.files:
                    return abs_check
                for ext in (".sol", ".vy", ".move"):
                    with_ext = abs_check + ext if not abs_check.endswith(ext) else abs_check
                    if with_ext in self.files:
                        return with_ext
                break
        candidates = [
            os.path.normpath(os.path.join(os.path.dirname(current), imp_path)),
            os.path.normpath(imp_path),
        ]
        for c in candidates:
            if c in self.files:
                return c
            for ext in (".sol", ".vy", ".move"):
                with_ext = c + ext if not c.endswith(ext) else c
                if with_ext in self.files:
                    return with_ext
        return None

    def build_context(self, target_file: str, depth: int = 2) -> str:
        visited: Set[str] = set()

        def _walk(file: str, d: int) -> str:
            if file not in self.files or d > depth or file in visited:
                return ""
            visited.add(file)
            content = self.files[file]
            max_per_file = 3000 if depth > 1 else 6000
            parts = [f"// === {file} ===\n{content[:max_per_file]}"]
            for neighbor in self.graph.get(file, []):
                parts.append(_walk(neighbor, d + 1))
            return "\n\n".join(p for p in parts if p)

        return _walk(target_file, 0)

    def get_entry_points(self) -> List[str]:
        """Files that are not imported by any other file."""
        imported = set()
        for deps in self.graph.values():
            imported.update(deps)
        return [f for f in self.files if f not in imported]

    def build_call_graph(self) -> Optional[object]:
        if not _has_networkx:
            return None
        G = nx.DiGraph()
        for f in self.files:
            G.add_node(f, size=len(self.files[f]))
        for src, deps in self.graph.items():
            for dst in deps:
                G.add_edge(src, dst)
        return G

    def get_subgraph(self, target_function: str, depth: int = 2) -> Dict[str, str]:
        G = self.build_call_graph()
        if G is None:
            return self.files
        nodes = {f for f in self.files if target_function in self.files[f]}
        for _ in range(depth):
            neighbors = set()
            for n in nodes:
                for pred in G.predecessors(n):
                    neighbors.add(pred)
                for succ in G.successors(n):
                    neighbors.add(succ)
            nodes |= neighbors
        return {f: self.files[f] for f in nodes if f in self.files}

    def prioritized_files(self, limit: int = 5) -> List[str]:
        entry = self.get_entry_points()
        scored = []
        for f in entry:
            content = self.files[f]
            score = 0
            if re.search(r"function\s+\w+\s*\([^)]*\)\s*(?:public|external)\s*(?:payable)?\s*(?:returns?[^\{]*)?\s*\{", content):
                score += 3
            if re.search(r"\.(?:delegatecall|call)\{value", content):
                score += 5
            if re.search(r"\bselfdestruct\b", content, re.IGNORECASE):
                score += 5
            if re.search(r"tx\.origin", content):
                score += 3
            if re.search(r"unchecked\s*\{", content):
                score += 2
            if re.search(r"for\s*\([^)]*msg\.value", content):
                score += 5
            if re.search(r"(?:_mint|_burn|safeTransfer|transferFrom)\s*\(", content):
                score += 2
            if re.search(r"require\s*\(\s*tx\.origin", content):
                score += 4
            if re.search(r"\.call\s*\([^)]*\)(?:\s*;(?!\s*require))", content):
                score += 3
            if len(self.graph.get(f, [])) > 3:
                score += 2
            scored.append((score, f))
        scored.sort(reverse=True, key=lambda x: x[0])
        return [f for _, f in scored[:limit]]

    def generate_code_map(self) -> str:
        lines = ["# Code Architecture Map\n"]
        for f, deps in self.graph.items():
            if deps:
                lines.append(f"- `{f}` imports: {', '.join(f'`{d}`' for d in deps)}")
        lines.append(f"\n## Contracts ({len(self.contracts)})")
        for name, path in sorted(self.contracts.items(), key=lambda x: x[0]):
            lines.append(f"- **{name}** → `{path}`")
        lines.append(f"\n## Entry Points ({len(self.get_entry_points())})")
        for f in self.get_entry_points():
            lines.append(f"- `{f}`")
        lines.append(f"\n## Priority Files")
        for f in self.prioritized_files():
            lines.append(f"- `{f}` (high risk indicators)")
        return "\n".join(lines)


def analyze_project_agentic(directory: str) -> str:
    auditor = AgenticAuditor()
    auditor.load_directory(directory)
    code_map = auditor.generate_code_map()

    from agents import call_model_with_fallback
    prompt = f"""You are a smart contract security expert. 

Below is the architecture map of a project:

{code_map}

Based on this map:
1. Identify which files are MOST CRITICAL (handle user funds, have external calls, etc.)
2. Explain the data flow between contracts
3. List potential attack vectors given the architecture
4. For each high-risk file, explain what specific vulnerabilities to look for

Be specific and reference actual file names and contract names."""
    try:
        return call_model_with_fallback(prompt)
    except Exception as e:
        return f"Agentic analysis failed: {e}"

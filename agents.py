import asyncio
import hashlib
import logging
import os
import re
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

_HAS_REDIS = False
try:
    import redis as _redis_module
    _REDIS_CLIENT = _redis_module.Redis.from_url(
        os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        socket_connect_timeout=2, socket_timeout=2, decode_responses=True,
    )
    _REDIS_CLIENT.ping()
    _HAS_REDIS = True
except Exception:
    _REDIS_CLIENT = None

import requests

from config import (
    OPENROUTER_API_KEY, OPENROUTER_BASE_URL, FREE_MODELS,
    MODEL_FALLBACK_CHAIN, GROQ_API_KEY, GROQ_MODEL, API_PROVIDER,
    TEMPERATURE, MAX_CODE_CHARS, CACHE_ENABLED, CACHE_DB_PATH,
    MAX_RETRIES, INITIAL_BACKOFF, TIMEOUT, PARALLEL_MAX_WORKERS,
    KB_ENABLED, KB_RAG_ENABLED, KB_DB_PATH, KB_AUTO_LEARN, KB_MAX_CONTEXT,
    OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT,
)
from cli_display import console

logger = logging.getLogger(__name__)

SYSTEM_PROMPT: str = """You are an expert smart contract security auditor specialized in Solidity.
Your tasks:
1. Detect security vulnerabilities in the code
2. Analyze gas consumption and suggest improvements
3. Give the contract a security rating

Examples of vulnerabilities to look for:
- **Reentrancy**: External call before state update (e.g. call.value{gas:2300}() before balance deduction)
- **Integer Overflow/Underflow**: Arithmetic without SafeMath in Solidity < 0.8
- **Access Control**: Public functions without onlyOwner or modifier
- **Uninitialized Storage**: Temporary storage variables polluting state
- **Timestamp Manipulation**: Relying on block.timestamp for critical logic
- **Front-running**: Transaction ordering affecting outcome
- **Gas Griefing**: Infinite loop or high-gas fallback calls

Required response format:

## Smart Contract Assessment

### Overall Security Rating: [A+ / A / B / C / D / F]

### Vulnerability List
- **Name**: [vulnerability name]
- **Severity**: [High / Medium / Low]
- **Description**: [simple explanation]
- **Fix**: [how to fix, with code if possible]

### Gas Optimizations
- [list of possible gas improvements]

### Fixed Code (optional)
```solidity
...
```"""

CHUNK_PROMPT: str = """You are an expert smart contract security auditor. Analyze this function step by step:

## Chain of Thought Instructions
1. **Understand the function**: What does it do? What are the parameters? What global variables does it interact with?
2. **Identify the flow**: Are there external calls? Does state change before or after the call?
3. **Search for dangerous patterns**: Review the vulnerability list below
4. **Assess exploitability**: Can this vulnerability actually be exploited in the real world? Ignore theoretical warnings requiring impossible conditions.
5. **Conclude**: Only list exploitable vulnerabilities with a clear exploit explanation.

## Focus on these vulnerabilities
- **Reentrancy**: External call (call, transfer, send) before state update
- **Access Control**: Public/External functions without appropriate modifiers
- **Integer Issues**: Arithmetic without overflow checks (Solidity < 0.8)
- **Timestamp**: Relying on block.timestamp for critical logic
- **Unchecked Return**: Not checking return value of call/delegatecall

## Strict Rules
- **Do not report theoretical vulnerabilities** that are not practically exploitable
- **Minimize False Positives**: Ensure a realistic exploit path exists
- **Provide specific fix code** for each vulnerability

## Response Format
### [Vulnerability Name] — [Severity]
- **Analysis**: (step by step)
- **Exploit**: (how)
- **Fix**: (code)
"""

_cache_lock = threading.Lock()

_KB = None
_RAG = None
_EXTRACTOR = None

def _init_kb():
    global _KB, _RAG, _EXTRACTOR
    if not KB_ENABLED:
        return
    try:
        from knowledge_base import KnowledgeBase, RAGContext, PatternExtractor
        _KB = KnowledgeBase(KB_DB_PATH)
        _RAG = RAGContext(_KB, KB_MAX_CONTEXT)
        _EXTRACTOR = PatternExtractor(_KB)
    except Exception as e:
        logger.debug(f"KB init deferred: {e}")

def _get_kb():
    global _KB
    if _KB is None and KB_ENABLED:
        _init_kb()
    return _KB

def _get_rag():
    global _RAG
    if _RAG is None and KB_ENABLED:
        _init_kb()
    return _RAG

def _get_extractor():
    global _EXTRACTOR
    if _EXTRACTOR is None and KB_ENABLED:
        _init_kb()
    return _EXTRACTOR

def _cache_cleanup(max_age_days: int = 30):
    """Delete cached responses older than 30 days."""
    if not CACHE_ENABLED:
        return
    try:
        cutoff = time.time() - max_age_days * 86400
        with _cache_lock:
            conn = sqlite3.connect(CACHE_DB_PATH, timeout=30)
            deleted = conn.execute("DELETE FROM responses WHERE created_at < ?", (cutoff,)).rowcount
            conn.commit()
            conn.close()
        if deleted:
            logger.info(f"🧹 Cache: deleted {deleted} entries older than {max_age_days} days")
    except Exception as e:
        logger.debug(f"Cache cleanup error: {e}")

def _init_cache():
    if not CACHE_ENABLED:
        return
    try:
        with _cache_lock:
            conn = sqlite3.connect(CACHE_DB_PATH, timeout=30)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""CREATE TABLE IF NOT EXISTS responses (
                model_id TEXT NOT NULL, prompt_hash TEXT NOT NULL,
                response TEXT NOT NULL, created_at REAL NOT NULL,
                hits INTEGER DEFAULT 1,
                PRIMARY KEY (model_id, prompt_hash))""")
            conn.execute("""CREATE TABLE IF NOT EXISTS stats (
                key TEXT PRIMARY KEY, value TEXT)""")
            conn.commit()
            conn.close()
        _cache_cleanup()
    except Exception as e:
        logger.warning(f"⚠️ Cache init failed: {e}")

def _cache_get(model_id: str, prompt: str) -> Optional[str]:
    if not CACHE_ENABLED:
        return None
    h = hashlib.sha256(prompt.encode()).hexdigest()
    try:
        if _HAS_REDIS:
            val = _REDIS_CLIENT.get(f"cache:{model_id}:{h}")
            if val is not None:
                console.log(f"[dim]💾 Redis Cache: {model_id} — hit[/]")
                return val
    except Exception:
        pass
    try:
        with _cache_lock:
            conn = sqlite3.connect(CACHE_DB_PATH, timeout=30)
            row = conn.execute(
                "SELECT response FROM responses WHERE model_id=? AND prompt_hash=?",
                (model_id, h)
            ).fetchone()
            if row:
                conn.execute("UPDATE responses SET hits=hits+1 WHERE model_id=? AND prompt_hash=?", (model_id, h))
                conn.commit()
                conn.close()
                console.log(f"[dim]💾 Cache: {model_id} — from cache[/]")
                return row[0]
            conn.close()
    except Exception as e:
        logger.debug(f"Cache get error: {e}")
    return None

def _cache_set(model_id: str, prompt: str, response: str):
    if not CACHE_ENABLED:
        return
    h = hashlib.sha256(prompt.encode()).hexdigest()
    try:
        if _HAS_REDIS:
            _REDIS_CLIENT.setex(f"cache:{model_id}:{h}", 86400, response)
    except Exception:
        pass
    try:
        with _cache_lock:
            conn = sqlite3.connect(CACHE_DB_PATH, timeout=30)
            conn.execute(
                "INSERT OR REPLACE INTO responses (model_id, prompt_hash, response, created_at) VALUES (?, ?, ?, ?)",
                (model_id, h, response, time.time())
            )
            conn.commit()
            conn.close()
    except Exception as e:
        logger.debug(f"Cache set error: {e}")

def cache_stats() -> Dict:
    if not CACHE_ENABLED:
        return {"enabled": False}
    try:
        conn = sqlite3.connect(CACHE_DB_PATH, timeout=5)
        total = conn.execute("SELECT COUNT(*) FROM responses").fetchone()[0]
        total_hits = conn.execute("SELECT COALESCE(SUM(hits), 0) FROM responses").fetchone()[0]
        conn.close()
        return {"enabled": True, "entries": total, "total_hits": total_hits}
    except:
        return {"enabled": True, "entries": 0, "total_hits": 0}

_init_cache()

def truncate_code(code: str, model_key: str = "") -> str:
    ctx = FREE_MODELS.get(model_key, {}).get("context", 0) if model_key else 0
    limit = min(ctx // 2 if ctx else MAX_CODE_CHARS, MAX_CODE_CHARS)
    if len(code) <= limit:
        return code
    logger.warning(f"⚠️ Code too long ({len(code)} chars) — smart truncation to {limit}")
    lines = code.split("\n")
    total = 0
    header_end = next((i for i, l in enumerate(lines) if l.strip().startswith(("contract ", "interface ", "library ", "abstract contract "))), len(lines))
    header = "\n".join(lines[:header_end])
    selected = [header]
    total = len(header)
    current = None
    contract_sizes = {}
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith(("contract ", "interface ", "library ", "abstract contract ")):
            current = s.split("{")[0].strip() if "{" in s else s
            contract_sizes[current] = 0
        if current and i >= header_end:
            contract_sizes[current] = contract_sizes.get(current, 0) + len(line) + 1
    for name, size in sorted(contract_sizes.items(), key=lambda x: -x[1]):
        if total + size > limit and total > 0:
            remaining = limit - total
            if remaining > 100:
                partial, sz, in_c = [], 0, False
                for line in lines:
                    if line.strip().startswith(("contract ", "interface ", "library ", "abstract contract ")) and name in line:
                        in_c = True
                    if in_c:
                        partial.append(line)
                        sz += len(line) + 1
                        if sz > remaining:
                            partial.append(f"// ... [truncated - continued {name}]")
                            break
                selected.append("\n".join(partial))
                total += sz
            break
        else:
            in_c, block, started = False, [], False
            for line in lines:
                s = line.strip()
                if s.startswith(("contract ", "interface ", "library ", "abstract contract ")) and name in s:
                    started = True
                if started:
                    in_c = True
                    block.append(line)
                    if s.startswith("}") and not s.endswith(";"):
                        started = False
            if in_c and block:
                b = "\n".join(block)
                selected.append(b)
                total += len(b)
    result = "\n\n".join(selected)
    result += f"\n\n// ⚡ Smart truncation: {len(code)} → {len(result)} chars"
    return result

def call_model_with_fallback(prompt: str, timeout: int = 0, model_chain: Optional[List[str]] = None) -> str:
    if model_chain is None:
        model_chain = MODEL_FALLBACK_CHAIN
    last_error = ""
    timeout = timeout or TIMEOUT
    for model_key in model_chain:
        if model_key not in FREE_MODELS:
            continue
        model_id = FREE_MODELS[model_key]["id"]
        try:
            return call_model(model_id, prompt, timeout)
        except requests.HTTPError as e:
            last_error = str(e)
            if e.response.status_code == 402:
                logger.warning(f"⚠️ {model_key}: 402 (payment required) — trying next...")
            elif e.response.status_code == 429:
                logger.info(f"⏳ {model_key}: Rate limit — trying next...")
            else:
                logger.warning(f"⚠️ {model_key} failed: {e} — trying next...")
        except Exception as e:
            last_error = str(e)
            logger.warning(f"⚠️ {model_key} failed: {e} — trying next...")
    raise Exception(f"All models failed. Last error: {last_error}")

def _call_ollama(model_name: str, prompt: str, timeout: int = 0) -> str:
    """Call Ollama local model API."""
    cached = _cache_get(f"ollama:{model_name}", prompt)
    if cached is not None:
        return cached
    timeout = timeout or OLLAMA_TIMEOUT
    url = f"{OLLAMA_BASE_URL.rstrip('/')}/api/generate"
    console.log(f"[bold magenta]🦙 Ollama: {model_name}[/]")
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.post(
                url,
                json={"model": model_name, "prompt": prompt, "stream": False, "temperature": TEMPERATURE},
                timeout=timeout,
            )
            resp.raise_for_status()
            result = resp.json().get("response", "")
            _cache_set(f"ollama:{model_name}", prompt, result)
            return result
        except (requests.ConnectionError, requests.Timeout) as e:
            backoff = INITIAL_BACKOFF * (2 ** (attempt - 1))
            logger.warning(f"⏳ Ollama connection error (attempt {attempt}/{MAX_RETRIES}) — waiting {backoff:.0f}s...")
            time.sleep(backoff)
        except Exception as e:
            if attempt == MAX_RETRIES:
                raise
            time.sleep(INITIAL_BACKOFF)
    raise Exception(f"Ollama failed after {MAX_RETRIES} attempts")


def call_model(model_id: str, prompt: str, timeout: int = 0) -> str:
    if API_PROVIDER == "ollama":
        return _call_ollama(OLLAMA_MODEL, prompt, timeout)
    cached = _cache_get(model_id, prompt)
    if cached is not None:
        return cached
    timeout = timeout or TIMEOUT
    info = FREE_MODELS.get(model_id, {})
    ctx = info.get("context", 0)
    console.log(f"[bold cyan]🤖 {model_id}[/]  [dim]context: {ctx:,}[/]")
    masked_key = OPENROUTER_API_KEY[:8] + "..." if OPENROUTER_API_KEY else "missing"
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.post(
                f"{OPENROUTER_BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model_id,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": TEMPERATURE,
                },
                timeout=timeout,
            )
            if resp.status_code == 429:
                backoff = INITIAL_BACKOFF * (2 ** (attempt - 1))
                console.log(f"[yellow]⏳ Rate limit (attempt {attempt}/{MAX_RETRIES}) — waiting {backoff:.0f}s...[/]")
                time.sleep(backoff)
                continue
            elif resp.status_code == 402:
                raise requests.HTTPError(f"402 Payment Required (key: {masked_key})", response=resp)
            resp.raise_for_status()
            result = resp.json()["choices"][0]["message"]["content"]
            _cache_set(model_id, prompt, result)
            return result
        except requests.HTTPError as e:
            if e.response.status_code in (502, 503, 504):
                backoff = INITIAL_BACKOFF * (2 ** (attempt - 1))
                console.log(f"[yellow]⏳ {e.response.status_code} (attempt {attempt}/{MAX_RETRIES}) — waiting {backoff:.0f}s...[/]")
                time.sleep(backoff)
                continue
            raise
        except (requests.ConnectionError, requests.Timeout) as e:
            backoff = INITIAL_BACKOFF * (2 ** (attempt - 1))
            logger.warning(f"⏳ Connection error (attempt {attempt}/{MAX_RETRIES}) — waiting {backoff:.0f}s...")
            time.sleep(backoff)
            continue
    raise Exception(f"Failed after {MAX_RETRIES} attempts. Key: {masked_key}")


def call_model_parallel(model_id: str, prompt: str, timeout: int = 0) -> str:
    return call_model(model_id, prompt, timeout)

def run_parallel(work_items: List[Dict]) -> List[tuple]:
    results: List[tuple] = []
    with ThreadPoolExecutor(max_workers=PARALLEL_MAX_WORKERS) as executor:
        futures = {}
        for i, item in enumerate(work_items):
            if i > 0:
                time.sleep(1)
            future = executor.submit(call_model, item["model_id"], item["prompt"], item.get("timeout", 0))
            futures[future] = item.get("label", item["model_id"])
        for future in as_completed(futures):
            label = futures[future]
            try:
                result = future.result()
                results.append((label, result, None))
            except Exception as e:
                results.append((label, None, str(e)))
    return results


async def async_call_model(model_id: str, prompt: str, timeout: int = 0) -> str:
    import aiohttp
    if API_PROVIDER == "ollama":
        raise NotImplementedError("Async not supported for Ollama")
    cached = _cache_get(model_id, prompt)
    if cached is not None:
        return cached
    timeout = timeout or TIMEOUT
    info = FREE_MODELS.get(model_id, {})
    masked_key = OPENROUTER_API_KEY[:8] + "..." if OPENROUTER_API_KEY else "missing"
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{OPENROUTER_BASE_URL}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": model_id,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": TEMPERATURE,
                    },
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    if resp.status == 429:
                        backoff = INITIAL_BACKOFF * (2 ** (attempt - 1))
                        console.log(f"[yellow]⏳ Async rate limit (attempt {attempt}/{MAX_RETRIES}) — waiting {backoff:.0f}s...[/]")
                        await asyncio.sleep(backoff)
                        continue
                    elif resp.status == 402:
                        raise aiohttp.ClientResponseError(resp.request_info, resp.history, status=402, message=f"402 Payment Required (key: {masked_key})")
                    resp.raise_for_status()
                    data = await resp.json()
                    result = data["choices"][0]["message"]["content"]
                    _cache_set(model_id, prompt, result)
                    return result
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            backoff = INITIAL_BACKOFF * (2 ** (attempt - 1))
            logger.warning(f"Async connection error (attempt {attempt}/{MAX_RETRIES}) — waiting {backoff:.0f}s...")
            await asyncio.sleep(backoff)
            last_err = str(e)
    raise Exception(f"Async call failed after {MAX_RETRIES} attempts. Key: {masked_key}. Last: {last_err}")

def analyze_code(code: str, lang: str = "english", model_key: str = "") -> str:
    code = truncate_code(code, model_key)

    rag_context = ""
    if KB_RAG_ENABLED:
        rag = _get_rag()
        if rag:
            rag_context = rag.build_context(code)
            if rag_context:
                logger.info(f"📚 RAG: added context from knowledge base ({len(rag_context)} chars)")

    prompt: str = (
        f"{SYSTEM_PROMPT}\n\n"
        f"{rag_context}\n"
        f"Code to analyze:\n"
        f"```solidity\n{code}\n```\n"
        f"Language: {lang}"
    )
    result: str = ""
    if model_key:
        result = call_model_with_fallback(prompt, model_chain=[model_key] + MODEL_FALLBACK_CHAIN)
    elif API_PROVIDER == "openrouter":
        result = call_model_with_fallback(prompt)
    else:
        result = _call_groq(prompt)

    if KB_AUTO_LEARN and result:
        extractor = _get_extractor()
        if extractor:
            try:
                extractor.learn_from_report(result, code, protocol_name="auto", contract_type="")
            except Exception as e:
                logger.debug(f"KB auto-learn skipped: {e}")

    return result

def _split_functions(code: str) -> List[Dict[str, str]]:
    """Split code into functions using AST (or Regex as fallback)."""
    chunks: List[Dict[str, str]] = []
    # If Solc AST is available, use it
    try:
        from analyzers.solidity_ast import compile_to_ast, analyze_contracts, HAS_SOLCAST
        if HAS_SOLCAST:
            units = compile_to_ast(code)
            if units:
                contracts = analyze_contracts(units)
                state_vars = []
                for c in contracts:
                    for sv in c.state_vars:
                        state_vars.append(f"{sv.get('type','?')} {sv.get('name','?')};")
                    for fn in c.functions:
                        chunks.append({
                            "name": f"{c.name}.{fn.name}",
                            "state_vars": state_vars,
                            "modifiers": c.modifiers,
                            "code": fn.body or f"// function {fn.name} (body not available)",
                        })
                if chunks:
                    return chunks
    except ImportError:
        pass

    # Regex fallback: extract functions from Solidity
    lines = code.split("\n")
    state_vars: List[str] = []
    fn_starts: List[int] = []
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("contract ") or s.startswith("interface ") or s.startswith("library ") or s.startswith("abstract contract "):
            state_vars = []
        if re.match(r'^\s*(?:public |internal |external |private )?(?:function|modifier)\s+\w+\s*\(', s):
            fn_starts.append(i)
        # State variables at contract level
        if s and not s.startswith(("function", "//", "/*", "*", "event", "modifier", "constructor")):
            if ";" in s and "(" not in s and ")" not in s and not s.startswith(("contract", "import", "pragma", "using", "type")):
                state_vars.append(s.rstrip(";{"))

    # Build chunks from functions with their context
    for idx, fn_line in enumerate(fn_starts):
        fn_end = fn_starts[idx + 1] if idx + 1 < len(fn_starts) else len(lines)
        fn_code = "\n".join(lines[fn_line:fn_end]).strip()
        fn_name_match = re.match(r'^\s*(?:public |internal |external |private )?(?:function|modifier)\s+(\w+)', lines[fn_line])
        fn_name = fn_name_match.group(1) if fn_name_match else f"fn_{idx}"
        context = "\n".join(state_vars[:20])
        chunks.append({
            "name": fn_name,
            "state_vars": state_vars[:20],
            "code": f"// State vars context:\n{context}\n\n{fn_code}",
        })

    if not chunks:
        # If no functions found, send full code
        chunks.append({"name": "full", "state_vars": [], "code": code[:5000]})

    return chunks


def _run_chunk(chunk: Dict, lang: str) -> str:
    """Analyze a single function chunk."""
    fn_code = chunk["code"][:4000]
    state_context = "\n".join(f"// {sv}" for sv in chunk["state_vars"][:10])
    prompt = f"""{CHUNK_PROMPT}

### Function Context
State variables:
{state_context or "// No state variables"}

### Function Name
{chunk['name']}

### Code
```solidity
{fn_code}
```

### Language
{lang}
"""
    try:
        return call_model_with_fallback(prompt, timeout=300)
    except Exception as e:
        logger.error(f"Failed to analyze {chunk['name']}: {e}")
        return f"(Analysis failed: {e})"


def chunked_audit(code: str, lang: str = "english") -> str:
    """Parallel chunked analysis by splitting code into functions."""
    chunks = _split_functions(code)
    if len(chunks) <= 1:
        logger.info("chunked_audit: only one function — using normal analysis")
        return analyze_code(code, lang)

    console.log(f"[bold]chunked_audit:[/] splitting code into [cyan]{len(chunks)}[/] functions — parallel analysis")

    results = []
    with ThreadPoolExecutor(max_workers=min(PARALLEL_MAX_WORKERS, len(chunks))) as executor:
        futures = {}
        for chunk in chunks:
            future = executor.submit(_run_chunk, chunk, lang)
            futures[future] = chunk["name"]
            time.sleep(0.5)

        for future in as_completed(futures):
            name = futures[future]
            result = future.result()
            results.append((name, result))
            console.log(f"[green]✓[/] {name}: done")

    results.sort(key=lambda x: [c["name"] for c in chunks].index(x[0]))
    header = f"# Chunked Analysis — {len(chunks)} functions (parallel)\n\n"
    body = "\n---\n".join(f"### {name}\n{text}" for name, text in results)
    return header + body


def _call_groq(prompt: str) -> str:
    from groq import Groq
    logger.info("Calling Groq (Llama 3)...")
    client = Groq(api_key=GROQ_API_KEY)
    response = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=TEMPERATURE,
    )
    return response.choices[0].message.content

def audit(code: str, lang: str = "english") -> str:
    return analyze_code(code, lang)

def self_critique(report: str, code: str, lang: str = "english") -> str:
    prompt = f"""You are a second reviewer. Carefully review the audit report and look for:
1. Missing vulnerabilities (not detected by the report)
2. Overstated severity (false positives)
3. Analysis errors

Original report:
{report}

Original code:
```solidity
{(code or "")[:3000]}
```

Output in {lang}:
## Critique
### Additional Vulnerabilities: [if any]
### Misclassified Severity: [if any]
### Improvements to Original Report: [if any]
### Rating Revised (if needed): [Yes/No]
"""
    try:
        critique = call_model_with_fallback(prompt)
        return critique
    except Exception as e:
        logger.warning(f"⚠️ Critique failed: {e}")
        return ""

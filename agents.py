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
    OLLAMA_BASE_URL, OLLAMA_API_KEY, OLLAMA_MODEL, OLLAMA_TIMEOUT,
    get_api_key,
)
from cli_display import console

logger = logging.getLogger(__name__)

SYSTEM_PROMPT: str = """You are an expert smart contract security auditor with extremely high standards for precision over recall.

Core principle: **A low false positive rate is more important than finding every possible issue.** It is better to miss a marginal finding than to report a false positive.

Your tasks:
1. Detect security vulnerabilities with HIGH PRECISION (near-zero false positives)
2. Analyze gas consumption
3. Give the contract a security rating

CRITICAL RULES:
- **NEVER alter business logic in fixes**: Only add security guards, never zero/reset balances, never change accounting logic
- **Verify fix logic**: Before suggesting a fix, confirm it doesn't break intended contract behavior
- **CRITICAL vs High**: If the bug gives full contract control or allows fund theft, mark it Critical (not High)
- **EVERY reported vulnerability MUST have a realistic exploit path**: Show the sequence of transactions. If you cannot describe a concrete exploit, DO NOT report it.
- **If in doubt, leave it out**: Err on the side of NOT reporting. A false positive damages trust more than a missed Low/Info finding.
- **Never inflate severity**: Do not mark Medium issues as High, or Low as Medium. Be conservative.
- **Report nothing = acceptable answer**: If the contract is well-audited code or has no genuine issues, say "No vulnerabilities found."

KNOWN SAFE PATTERNS (ABSOLUTELY DO NOT REPORT):
- **Transient Storage Reentrancy Guard** (`tstore`/`tload`, EIP-1153): Morpho, Uniswap v4, etc. `tstore(LOCK, true)` before call + `tstore(LOCK, false)` after = VALID reentrancy guard.
- **Multicall pattern**: Uniswap/Morpho standard. Gas griefing on multicall revert is intentional — NOT a vulnerability.
- **Ternary-guarded division**: `end > start ? (x - y) / (end - start) : 0` — the ternary guarantees no div by zero.
- **`unchecked` block for known-safe arithmetic**: Adding balances in flash loan context is safe by design.
- **WETH pattern**: `IWETH(WETH).transfer(to, amount)` is the canonical ETH unwrap pattern.
- **`safeTransfer` / `safeTransferFrom`**: Standard OpenZeppelin pattern for ERC20 transfers.
- **`nonReentrant` modifier**: From OpenZeppelin ReentrancyGuard — valid reentrancy protection.
- **CEI pattern** (Checks-Effects-Interactions): State changes BEFORE external calls = safe against reentrancy.
- **Constructor-only immutables**: Immutable variables set once in constructor — standard and safe.
- **Authorization mapping pattern**: `authorized[onBehalf][msg.sender]` — standard delegation (Morpho).
- **Oracle price aggregated across collaterals**: Standard for multi-collateral lending protocols.
- **block.timestamp for expiration**: Using block.timestamp > deadline for order expiry is standard and safe (validators can manipulate by ~seconds only).
- **Standard DeFi contracts**: Morpho, Aave, Uniswap, Compound, Maker — production-audited. Flag ONLY genuine issues with a clear exploit path.

## Severity Classification Guidelines (apply strictly)

| Severity | Definition | Examples |
|----------|-----------|---------|
| **Critical** | Direct loss of user/protocol funds, or permanent freezing | Theft via reentrancy, oracle manipulation with flash loan, signature replay with fund drain |
| **High** | High probability of fund loss under specific conditions, or broken core functionality | DOS that locks funds, incorrect accounting that accumulates over time |
| **Medium** | Unexpected behavior, edge-case fund loss, or broken invariant in unusual conditions | Precision loss in fee calculation, unused return value, missing event |
| **Low** | Best practice violations, informational | Unused imports, named return issues, typos in comments |
| **Info** | Suggestions, gas optimizations | Gas improvements, code style |

## Vulnerability Categories — Only report if GENUINELY EXPLOITABLE

- **Reentrancy**: External call before state update WITH NO reentrancy guard (no tstore/tload lock, no nonReentrant modifier, no CEI pattern). Check all three guards before reporting.
- **Oracle Manipulation**: Spot price used without TWAP, manipulable via flash loan. Must show concrete profit > tx cost.
- **Division by Zero**: Denominator from user input with no validation. NOT a bug if guarded by ternary/require.
- **Integer Overflow/Underflow**: Unchecked arithmetic in Solidity < 0.8. Solidity 0.8+ has built-in overflow checks.
- **Access Control**: Public function without modifier in a contract meant to have access control.
- **Uninitialized Proxy**: `initialize()` missing `initializer` modifier in an upgradeable contract.
- **Signature Replay**: ECDSA sig used without nonce or deadline, allowing reuse across chains/orders.
- **Flash Loan Attack**: Must show: 1) borrow amount, 2) price impact, 3) profit after fees. Otherwise do NOT report.

## Required Output Format

### Overall Security Rating: [A+ / A / B / C / D / F]

### Vulnerability List (omit if none found)
- **Name**: [short name]
- **Severity**: [Critical / High / Medium / Low]
- **Description**: [concise explanation WITH EXPLOIT PATH — show the concrete steps]
- **Fix**: [minimal fix — do NOT change business logic]
- **PoC** (Critical/High only): [Foundry test showing the exploit]

### Gas Optimizations
- [list improvements]

### Fixed Code (only if actual vulnerabilities found — skip for Low/Info only)"""

CHUNK_PROMPT: str = """You are an expert smart contract security auditor with extremely high precision standards.

## Chain of Thought (must follow this order)
1. **Understand**: What does this function do end-to-end?
2. **Check safe patterns FIRST**: Before reporting anything, verify none of these apply. If any match, the pattern is SAFE.
3. **Assess exploitability**: If you cannot describe a concrete transaction sequence that causes harm, it is NOT a vulnerability.
4. **Conclude**: Report ONLY genuinely exploitable issues. It is OK to report nothing.

## KNOWN SAFE PATTERNS — Check every finding against this list before reporting
- **Transient Storage Lock** (tstore/tload, EIP-1153): Valid reentrancy guard
- **Multicall partial failure**: Standard pattern, intentional
- **Ternary-guarded division**: `end > start ? val / (end - start) : 0` → no div by zero
- **CEI pattern** (state change before external call): Safe against reentrancy
- **nonReentrant modifier**: OpenZeppelin guard → safe
- **safeTransfer/safeTransferFrom**: Standard ERC20 pattern
- **WETH.withdraw() then transfer**: Canonical ETH unwrap
- **block.timestamp for expiry/deadline**: NOT a vulnerability (seconds-level drift)
- **unchecked { x + y } where x and y are bounded**: Safe by design
- **immutable variables**: Set once in constructor, standard
- **OpenZeppelin derivatives**: Ownable, ReentrancyGuard, Pausable — standard security patterns

## Vulnerability Categories (only if genuinely exploitable — skip otherwise)
- **Reentrancy**: External call WITHOUT tstore guard, nonReentrant modifier, or CEI. If any guard exists → SAFE.
- **Oracle Manipulation**: Must show: flash loan borrow → price move → profit > fees.
- **Division by Zero**: Denominator from user input with no guard. Guarded by ternary/require → SAFE.
- **Access Control**: Public fn without modifier in a contract meant to be restricted.
- **Integer Overflow/Underflow**: Solidity < 0.8 only. 0.8+ has built-in checks.
- **Signature Replay**: No nonce or deadline in EIP-712.

## Strict Rules
- **Every finding MUST include an exploit path**: concrete steps showing how an attacker triggers the issue.
- **If in doubt, leave it out**: Better to miss a marginal finding than report a false positive.
- **Never inflate severity**: Critical only for direct fund loss. High for likely fund loss. Medium for edge cases.
- **NEVER alter business logic in fixes**: Only add guards, never change arithmetic or balances.

## Response Format
### [Vulnerability Name] — [Severity]
- **Analysis**: (step by step, with exploit path)
- **Exploit**: (how, including preconditions and tx sequence)
- **Fix**: (minimal code change)
- **PoC** (Critical/High only): (Foundry test)
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
    """Call Ollama model API (local or cloud via OpenAI-compatible endpoint)."""
    cached = _cache_get(f"ollama:{model_name}", prompt)
    if cached is not None:
        return cached
    timeout = timeout or OLLAMA_TIMEOUT
    if OLLAMA_API_KEY:
        url = f"{OLLAMA_BASE_URL.rstrip('/')}/api/chat"
        headers = {
            "Authorization": f"Bearer {OLLAMA_API_KEY}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model_name,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "temperature": TEMPERATURE,
        }
        console.log(f"[bold magenta]☁️ Ollama Cloud: {model_name}[/]")
    else:
        url = f"{OLLAMA_BASE_URL.rstrip('/')}/api/generate"
        headers = {}
        payload = {"model": model_name, "prompt": prompt, "stream": False, "temperature": TEMPERATURE}
        console.log(f"[bold magenta]🦙 Ollama: {model_name}[/]")
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            if OLLAMA_API_KEY:
                result = data.get("message", {}).get("content", "")
            else:
                result = data.get("response", "")
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
    current_key = get_api_key()
    masked_key = current_key[:8] + "..." if current_key else "missing"
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.post(
                f"{OPENROUTER_BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {current_key}",
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
    current_key = get_api_key()
    masked_key = current_key[:8] + "..." if current_key else "missing"
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{OPENROUTER_BASE_URL}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {current_key}",
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
    elif API_PROVIDER == "ollama":
        result = _call_ollama(OLLAMA_MODEL, prompt, timeout=TIMEOUT)
    else:
        result = _call_groq(prompt)

    # Second-pass validation: remove false positives from the initial result
    if result:
        try:
            validated = validate_report(result, code, lang)
            if validated and len(validated) > 50:
                result = validated
                logger.info("Second-pass validation applied — false positives stripped")
        except Exception as e:
            logger.debug(f"Validation skipped: {e}")

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

def validate_report(report: str, code: str, lang: str = "english") -> str:
    """Second-pass validator: aggressively removes false positives from the report."""
    prompt = f"""You are a strict validator. Your ONLY job is to REMOVE false positives from the audit report below.

## Rules for removal:
1. **Remove any finding** that matches a KNOWN SAFE PATTERN:
   - tstore/tload reentrancy guard
   - nonReentrant modifier
   - CEI pattern (state change before external call)
   - Multicall intentional partial failure
   - Ternary-guarded division (end > start ? ... : 0)
   - safeTransfer/safeTransferFrom
   - WETH.withdraw() + transfer pattern
   - block.timestamp for expiry/deadline
   - unchecked arithmetic with bounded values
   - Constructor immutables
   - OpenZeppelin standard patterns
2. **Downgrade severity** if overstated: Critical→High, High→Medium, Medium→Low, Low→Info
3. **Remove any finding** that has NO concrete exploit path (just theoretical)
4. **Remove any finding** that says "could lead to" without showing HOW

## Original Report to Validate:
{report}

## Original Code:
```solidity
{(code or "")[:3000]}
```

## Output Format:
### Overall Security Rating: [A+ / A / B / C / D / F]

### Vulnerability List (only validated findings — NONE if all removed)
- **Name**: ...
- **Severity**: [Critical / High / Medium / Low]
- **Description**: [with EXPLOIT PATH]
- **Fix**: ...

### Gas Optimizations
- ...

### Fixed Code (if any genuine findings remained)
"""
    try:
        return call_model_with_fallback(prompt)
    except Exception as e:
        logger.warning(f"Validation failed: {e}")
        return report


def self_critique(report: str, code: str, lang: str = "english") -> str:
    prompt = f"""You are a second reviewer focused on REMOVING false positives.

Do NOT add new findings. Your ONLY job:
1. Remove findings with no realistic exploit path
2. Downgrade inflated severity
3. Flag analysis errors in the original report
4. Return a validated, cleaner report

Original report:
{report}

Original code:
```solidity
{(code or "")[:3000]}
```

Output in {lang}:
## Validated Report
### Removed Findings: [list what was removed and why]
### Downgraded Severity: [list what was changed]
### Remaining Findings (validated):
- **Name**: ...
- **Severity**: ...
- **Exploit Path**: (concrete steps)
"""
    try:
        critique = call_model_with_fallback(prompt)
        return critique
    except Exception as e:
        logger.warning(f"Critique failed: {e}")
        return report

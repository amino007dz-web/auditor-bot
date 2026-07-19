import asyncio
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

import requests

from config import (
    OPENROUTER_BASE_URL, FREE_MODELS, MODEL_FALLBACK_CHAIN,
    API_PROVIDER, TEMPERATURE, MAX_RETRIES, INITIAL_BACKOFF,
    TIMEOUT, OLLAMA_BASE_URL, OLLAMA_API_KEY, OLLAMA_MODEL, OLLAMA_TIMEOUT,
    PARALLEL_MAX_WORKERS, get_api_key,
)
from cli_display import console
from agents.cache import _cache_get, _cache_set

logger = logging.getLogger(__name__)


def _validate_text_input(prompt: str) -> str:
    """Check if prompt appears to be a binary/image read error rather than valid code."""
    if not prompt:
        return ""
    lines = prompt.strip().split('\n')
    header = '\n'.join(lines[:min(5, len(lines))])
    binary_indicators = ["cannot read", "this model does not support image", "image input"]
    for indicator in binary_indicators:
        if indicator in header.lower():
            logger.warning(f"Rejected prompt containing image/binary reference: {indicator}")
            return ""
    return prompt


def _truncate_key(key: str) -> str:
    return f"...{key[-4:]}" if len(key) > 8 else "***"

def _call_ollama(model_name: str, prompt: str, timeout: int = 0) -> str:
    """Call Ollama model API (local or cloud via OpenAI-compatible endpoint)."""
    prompt = _validate_text_input(prompt)
    if not prompt:
        return "ERROR: Image files are not supported. Please upload smart contract source code."
    cached = _cache_get(f"ollama:{model_name}", prompt)
    if cached is not None:
        return cached
    timeout = timeout or OLLAMA_TIMEOUT
    if OLLAMA_API_KEY:
        url = f"{OLLAMA_BASE_URL.rstrip('/')}/api/chat"
        key_suffix = _truncate_key(OLLAMA_API_KEY)
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
        console.log(f"[bold magenta]Ollama Cloud: {model_name} (key: {key_suffix})[/]")
    else:
        url = f"{OLLAMA_BASE_URL.rstrip('/')}/api/generate"
        headers = {}
        payload = {"model": model_name, "prompt": prompt, "stream": False, "temperature": TEMPERATURE}
        console.log(f"[bold magenta]Ollama: {model_name}[/]")
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            if 'error' in data:
                raise Exception(data['error'])
            if OLLAMA_API_KEY:
                result = data.get("message", {}).get("content", "")
            else:
                result = data.get("response", "")
            _cache_set(f"ollama:{model_name}", prompt, result)
            return result
        except (requests.ConnectionError, requests.Timeout) as e:
            backoff = INITIAL_BACKOFF * (2 ** (attempt - 1))
            logger.warning(f"Ollama connection error (attempt {attempt}/{MAX_RETRIES}) — waiting {backoff:.0f}s...")
            time.sleep(backoff)
        except Exception as e:
            if attempt == MAX_RETRIES:
                raise
            time.sleep(INITIAL_BACKOFF)
    raise Exception(f"Ollama failed after {MAX_RETRIES} attempts")


def _stream_ollama(model_name: str, prompt: str, timeout: int = 300):
    """Generator that yields tokens from Ollama as they arrive (SSE-style)."""
    prompt = _validate_text_input(prompt)
    if not prompt:
        yield "data: ERROR: Image files are not supported.\n\n"
        return
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
            "stream": True,
            "temperature": TEMPERATURE,
        }
    else:
        url = f"{OLLAMA_BASE_URL.rstrip('/')}/api/generate"
        headers = {}
        payload = {"model": model_name, "prompt": prompt, "stream": True, "temperature": TEMPERATURE}
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=timeout, stream=True)
        resp.raise_for_status()
        full = []
        for line in resp.iter_lines(decode_unicode=True):
            if not line:
                continue
            if line.startswith("data: "):
                line = line[6:]
            try:
                chunk = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Check if the model returned an API-level error
            if 'error' in chunk:
                yield f"data: {json.dumps({'error': chunk['error']})}\n\n"
                return
            if OLLAMA_API_KEY:
                delta = chunk.get("message", {}).get("content", "")
            else:
                delta = chunk.get("response", "")
            if delta:
                full.append(delta)
                yield f"data: {json.dumps({'token': delta})}\n\n"
            if chunk.get("done"):
                yield f"data: {json.dumps({'done': True, 'full': ''.join(full)})}\n\n"
                return
    except Exception as e:
        yield f"data: {json.dumps({'error': str(e)})}\n\n"


def _stream_openrouter(model_id: str, prompt: str, timeout: int = 300):
    """Generator that yields tokens from OpenRouter as they arrive (SSE-style)."""
    from config import OPENROUTER_BASE_URL, get_api_key, TEMPERATURE
    key = get_api_key()
    if not key:
        yield f"data: {json.dumps({'error': 'No OpenRouter API key configured'})}\n\n"
        return
    try:
        resp = requests.post(
            f"{OPENROUTER_BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={"model": model_id, "messages": [{"role": "user", "content": prompt}], "stream": True, "temperature": TEMPERATURE},
            timeout=timeout, stream=True
        )
        resp.raise_for_status()
        full = []
        for line in resp.iter_lines(decode_unicode=True):
            if not line or not line.startswith("data: "):
                continue
            data_str = line[6:].strip()
            if data_str == "[DONE]":
                break
            try:
                chunk = json.loads(data_str)
            except json.JSONDecodeError:
                continue
            choices = chunk.get("choices", [])
            if not choices:
                continue
            delta = choices[0].get("delta", {})
            content = delta.get("content", "")
            if content:
                full.append(content)
                yield f"data: {json.dumps({'token': content})}\n\n"
        if full:
            yield f"data: {json.dumps({'done': True, 'full': ''.join(full)})}\n\n"
    except Exception as e:
        yield f"data: {json.dumps({'error': str(e)})}\n\n"


def call_model(model_id: str, prompt: str, timeout: int = 0) -> str:
    try:
        asyncio.get_running_loop()
        logger.warning("call_model() is synchronous — use async_call_model() in async context")
    except RuntimeError:
        pass
    if API_PROVIDER == "ollama":
        return _call_ollama(OLLAMA_MODEL, prompt, timeout)
    prompt = _validate_text_input(prompt)
    if not prompt:
        return "ERROR: Image files are not supported. Please upload smart contract source code."
    cached = _cache_get(model_id, prompt)
    if cached is not None:
        return cached
    timeout = timeout or TIMEOUT
    info = FREE_MODELS.get(model_id, {})
    ctx = info.get("context", 0)
    console.log(f"[bold cyan]{model_id}[/]  [dim]context: {ctx:,}  key: {key_suffix}[/]")
    current_key = get_api_key()
    key_suffix = _truncate_key(current_key) if current_key else "none"
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
                console.log(f"[yellow]Rate limit (attempt {attempt}/{MAX_RETRIES}) — waiting {backoff:.0f}s...[/]")
                time.sleep(backoff)
                continue
            elif resp.status_code == 402:
                raise requests.HTTPError("402 Payment Required — API key is invalid or has insufficient credits", response=resp)
            resp.raise_for_status()
            result = resp.json()["choices"][0]["message"]["content"]
            _cache_set(model_id, prompt, result)
            return result
        except requests.HTTPError as e:
            if e.response.status_code in (502, 503, 504):
                backoff = INITIAL_BACKOFF * (2 ** (attempt - 1))
                console.log(f"[yellow]{e.response.status_code} (attempt {attempt}/{MAX_RETRIES}) — waiting {backoff:.0f}s...[/]")
                time.sleep(backoff)
                continue
            raise
        except (requests.ConnectionError, requests.Timeout) as e:
            backoff = INITIAL_BACKOFF * (2 ** (attempt - 1))
            logger.warning(f"Connection error (attempt {attempt}/{MAX_RETRIES}) — waiting {backoff:.0f}s...")
            time.sleep(backoff)
            continue
    raise Exception(f"Failed after {MAX_RETRIES} attempts. API key is invalid or rate-limited.")


def call_model_with_fallback(prompt: str, timeout: int = 0, model_chain: Optional[List[str]] = None) -> str:
    try:
        asyncio.get_running_loop()
        logger.warning("call_model_with_fallback() is synchronous — use async_call_model() in async context")
    except RuntimeError:
        pass
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
                logger.warning(f"{model_key}: 402 (payment required) — trying next...")
            elif e.response.status_code == 429:
                logger.info(f"{model_key}: Rate limit — trying next...")
            else:
                logger.warning(f"{model_key} failed: {e} — trying next...")
        except Exception as e:
            last_error = str(e)
            logger.warning(f"{model_key} failed: {e} — trying next...")
    raise Exception(f"All models failed. Last error: {last_error}")


_shared_pool = None
def _get_pool():
    global _shared_pool
    if _shared_pool is None:
        _shared_pool = ThreadPoolExecutor(max_workers=PARALLEL_MAX_WORKERS)
    return _shared_pool

def call_model_parallel(model_id: str, prompt: str, timeout: int = 0) -> str:
    pool = _get_pool()
    future = pool.submit(call_model, model_id, prompt, timeout)
    return future.result()


def run_parallel(work_items: List[Dict]) -> List[tuple]:
    results: List[tuple] = []
    with ThreadPoolExecutor(max_workers=PARALLEL_MAX_WORKERS) as executor:
        futures = {}
        for i, item in enumerate(work_items):
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
                        console.log(f"[yellow]Async rate limit (attempt {attempt}/{MAX_RETRIES}) — waiting {backoff:.0f}s...[/]")
                        await asyncio.sleep(backoff)
                        continue
                    elif resp.status == 402:
                        raise aiohttp.ClientResponseError(resp.request_info, resp.history, status=402, message="402 Payment Required — API key is invalid or has insufficient credits")
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
    raise Exception(f"Async call failed after {MAX_RETRIES} attempts. API key is invalid or rate-limited. Last: {last_err}")


def _call_groq(prompt: str) -> str:
    from groq import Groq
    from config import GROQ_API_KEY, GROQ_MODEL
    logger.info("Calling Groq (Llama 3)...")
    client = Groq(api_key=GROQ_API_KEY)
    response = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=TEMPERATURE,
    )
    return response.choices[0].message.content

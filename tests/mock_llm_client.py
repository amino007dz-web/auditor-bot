"""mock_llm_client — replaces agents.llm_client for offline tests."""

_original_call_model = None
_original_call_ollama = None
_original_call_groq = None
_original_call_model_with_fallback = None


MOCK_RESPONSE = """## Security Analysis Report

### Summary
1 critical, 1 high, 1 medium finding

### Critical: Reentrancy in withdraw()
- **Severity:** Critical (CVSS 9.8)
- **Line:** 12
- **Description:** The `withdraw()` function sends ETH before updating state
- **Exploit Path:** Attacker calls withdraw → receives ETH → fallback calls withdraw again
- **Fix:** Use Checks-Effects-Interactions pattern

### High: Unchecked external call
- **Severity:** High (CVSS 7.5)
- **Line:** 8
- **Description:** `call{value}` return value not checked
- **Fix:** Check the boolean return value

### Medium: Floating pragma
- **Severity:** Medium (CVSS 5.0)
- **Line:** 1
- **Description:** Use exact pragma version
- **Fix:** Use pragma solidity 0.8.26
"""


def mock_call_model(model_id: str, prompt: str, timeout: int = 0) -> str:
    return MOCK_RESPONSE


def mock_call_ollama(model: str, prompt: str, timeout: int = 300) -> str:
    return MOCK_RESPONSE


def mock_call_groq(prompt: str, **kwargs) -> str:
    return MOCK_RESPONSE


def mock_call_model_with_fallback(prompt: str, model_chain=None, timeout: int = 120) -> str:
    return MOCK_RESPONSE


def install():
    import agents.llm_client as llm
    global _original_call_model, _original_call_ollama
    global _original_call_groq, _original_call_model_with_fallback
    _original_call_model = llm.call_model
    _original_call_ollama = llm._call_ollama
    _original_call_groq = llm._call_groq
    _original_call_model_with_fallback = llm.call_model_with_fallback
    llm.call_model = mock_call_model
    llm._call_ollama = mock_call_ollama
    llm._call_groq = mock_call_groq
    llm.call_model_with_fallback = mock_call_model_with_fallback


def uninstall():
    import agents.llm_client as llm
    if _original_call_model:
        llm.call_model = _original_call_model
    if _original_call_ollama:
        llm._call_ollama = _original_call_ollama
    if _original_call_groq:
        llm._call_groq = _original_call_groq
    if _original_call_model_with_fallback:
        llm.call_model_with_fallback = _original_call_model_with_fallback

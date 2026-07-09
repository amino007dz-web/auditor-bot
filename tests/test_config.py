import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from config import (
    FREE_MODELS, MODEL_FALLBACK_CHAIN,
    TEMPERATURE, MAX_CODE_CHARS, CACHE_ENABLED,
    MAX_RETRIES, INITIAL_BACKOFF
)


class TestConfig:
    def test_free_models_exist(self):
        assert len(FREE_MODELS) >= 5
        assert "deepseek-chat" in FREE_MODELS
        assert "openrouter-free" in FREE_MODELS

    def test_fallback_chain_not_empty(self):
        assert len(MODEL_FALLBACK_CHAIN) >= 3
        assert MODEL_FALLBACK_CHAIN[0] in FREE_MODELS

    def test_temperature_range(self):
        assert 0.0 <= TEMPERATURE <= 1.0

    def test_max_code_chars_positive(self):
        assert MAX_CODE_CHARS > 0

    def test_retry_settings(self):
        assert MAX_RETRIES >= 0
        assert INITIAL_BACKOFF > 0

    def test_cache_by_default(self):
        assert CACHE_ENABLED in (True, False)

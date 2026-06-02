.PHONY: help venv install preflight smoke gemini ensemble clean

help:
	@echo "Targets:"
	@echo "  make venv        - create .venv (Python 3.11) for the shinka sub-project"
	@echo "  make install     - uv pip install -e '.[dev]' (pulls shinka-adapter + kryptos)"
	@echo "  make preflight   - run shinka_adapter preflight (validates OPENROUTER_API_KEY etc.)"
	@echo "  make smoke       - pytest tests/test_smoke.py (validates fitness wiring, ~5s, \$$0)"
	@echo "  make gemini      - run: variant=openrouter_only (Gemini 3.5 Flash, ~\$$15-25)"
	@echo "  make ensemble    - run: variant=flash_plus_opus (Flash + Opus 4.7, ~\$$30-50)"
	@echo "                     Both via OpenRouter; OPENROUTER_API_KEY only"
	@echo "  make clean       - remove results/ and caches"

venv:
	uv venv --python 3.11 .venv

install: venv
	@. .venv/bin/activate && uv pip install -e ".[dev]"

preflight:
	@. .venv/bin/activate && uv run preflight

smoke:
	@. .venv/bin/activate && pytest tests/test_smoke.py -v

gemini:
	@. .venv/bin/activate && uv run shinka variant=openrouter_only

ensemble:
	@. .venv/bin/activate && uv run shinka variant=flash_plus_opus

clean:
	rm -rf results/ __pycache__/ .pytest_cache/ .ruff_cache/
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

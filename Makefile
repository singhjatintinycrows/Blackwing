.PHONY: setup dev check-bedrock test lint clean

VENV=.venv
PY=$(VENV)/bin/python
PIP=$(VENV)/bin/pip

setup:
	python3 -m venv $(VENV)
	$(PIP) install -U pip
	$(PIP) install -r web/requirements.txt
	@echo "Setup complete. Copy .env.example to .env and fill in credentials."

check-bedrock:
	@set -a; . ./.env; set +a; \
	curl -sS -w "\nHTTP %{http_code}\n" \
	  "https://bedrock-runtime.$$AWS_REGION.amazonaws.com/openai/v1/chat/completions" \
	  -H "Authorization: Bearer $$AWS_BEARER_TOKEN_BEDROCK" \
	  -H "Content-Type: application/json" \
	  -d '{"model":"'"$$BLACKWING_MODEL"'","messages":[{"role":"user","content":"say BLACKWING_OK"}],"max_completion_tokens":16}'

dev:
	@set -a; . ./.env; set +a; \
	$(VENV)/bin/uvicorn web.app.main:app --host $$BLACKWING_HOST --port $$BLACKWING_PORT --reload

test:
	BLACKWING_MODEL_MOCK=1 $(VENV)/bin/pytest -q tests/

lint:
	$(VENV)/bin/python -m pyflakes lib/ orchestrator/ web/ bin/ || true

clean:
	rm -rf $(VENV) **/__pycache__ .pytest_cache

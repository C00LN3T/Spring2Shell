.PHONY: help install install-dev lint format typecheck test test-unit test-integration clean run

PYTHON  := python3
PIP     := $(PYTHON) -m pip
PYTEST  := $(PYTHON) -m pytest
RUFF    := $(PYTHON) -m ruff
MYPY    := $(PYTHON) -m mypy
SRC_DIR := src/spring2shell
TEST_DIR := tests

# ─── Default target ────────────────────────────────────────────────────────────
help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ─── Installation ──────────────────────────────────────────────────────────────
install: ## Install package (production deps only)
	$(PIP) install -e .

install-dev: ## Install package with dev dependencies
	$(PIP) install -e ".[dev]"
	@echo "✓ Dev environment ready"

# ─── Code Quality ──────────────────────────────────────────────────────────────
lint: ## Run ruff linter
	$(RUFF) check $(SRC_DIR) $(TEST_DIR)

format: ## Run ruff formatter
	$(RUFF) format $(SRC_DIR) $(TEST_DIR)

format-check: ## Check formatting without modifying files
	$(RUFF) format --check $(SRC_DIR) $(TEST_DIR)

typecheck: ## Run mypy static analysis
	$(MYPY) $(SRC_DIR)

check: lint format-check typecheck ## Run all quality checks (CI mode)

# ─── Testing ───────────────────────────────────────────────────────────────────
test: ## Run full test suite with coverage
	$(PYTEST)

test-unit: ## Run unit tests only
	$(PYTEST) $(TEST_DIR)/unit -v

test-integration: ## Run integration tests only
	$(PYTEST) $(TEST_DIR)/integration -v

# ─── Running ───────────────────────────────────────────────────────────────────
run: ## Run scanner — usage: make run ARGS="safe-audit https://target.example"
	$(PYTHON) -m spring2shell $(ARGS)

scan: ## Bulk scan — usage: make scan TARGETS=targets.txt OUT=reports/scan
	$(PYTHON) -m spring2shell scan $(TARGETS) $(OUT)

# ─── Cleanup ───────────────────────────────────────────────────────────────────
clean: ## Remove build artifacts and cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache  -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache  -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ reports/coverage/
	@echo "✓ Clean"

# ─── Venv helpers ──────────────────────────────────────────────────────────────
venv: ## Create virtual environment
	$(PYTHON) -m venv .venv
	@echo "✓ Run: source .venv/bin/activate && make install-dev"

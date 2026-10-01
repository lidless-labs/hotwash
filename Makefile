.PHONY: help install dev dev-api dev-web build build-web clean test

# Default target
help:
	@echo "Hotwash - Development Commands"
	@echo ""
	@echo "Available targets:"
	@echo "  make install    - Install all dependencies (backend venv + frontend)"
	@echo "  make dev        - How to run both backend and frontend in dev mode"
	@echo "  make dev-api    - Run backend API server only (port 8000)"
	@echo "  make dev-web    - Run frontend dev server only (port 5177)"
	@echo "  make build      - Build production artifacts"
	@echo "  make build-web  - Build frontend production bundle"
	@echo "  make clean      - Remove build artifacts and caches"
	@echo "  make test       - Run the full verification gate (scripts/verify)"
	@echo ""

# Install development and test dependencies
install:
	@echo "Installing backend dependencies into .venv..."
	python3 -m venv .venv
	.venv/bin/pip install -r requirements-test.txt
	@echo ""
	@echo "Installing frontend dependencies..."
	cd web && npm install
	@echo ""
	@echo "Installation complete!"

# Run both backend and frontend in development mode
dev:
	@echo "Backend: http://localhost:8000"
	@echo "Frontend: http://localhost:5177"
	@echo ""
	@echo "Note: Run 'make dev-api' and 'make dev-web' in separate terminals"
	@echo "      or use a process manager like tmux/screen"

# Run backend API server
dev-api:
	@echo "Starting FastAPI backend on http://localhost:8000"
	@echo "API docs available at http://localhost:8000/docs"
	.venv/bin/uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

# Run frontend dev server
dev-web:
	@echo "Starting React frontend on http://localhost:5177"
	cd web && npm run dev

# Build production artifacts
build: build-web
	@echo ""
	@echo "Build complete!"
	@echo "Backend: Ready for deployment with uvicorn"
	@echo "Frontend: Build artifacts in web/dist/"

# Build frontend production bundle
build-web:
	@echo "Building frontend production bundle..."
	cd web && npm run build
	@echo "Frontend build complete! Artifacts in web/dist/"

# Clean build artifacts and caches
clean:
	@echo "Cleaning build artifacts..."
	rm -rf web/dist
	rm -rf web/node_modules
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo "Clean complete!"

# Run the full verification gate
test:
	./scripts/verify

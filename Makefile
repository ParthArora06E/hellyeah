.PHONY: setup test run-backend run-frontend clean

setup:
	python -m venv .venv
	./.venv/Scripts/pip install -r requirements.txt
	cd frontend && npm install

test:
	./.venv/Scripts/python -m pytest tests/ -v

run-backend:
	./.venv/Scripts/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload

run-frontend:
	cd frontend && npm run dev

clean:
	rm -rf __pycache__ .pytest_cache dist
